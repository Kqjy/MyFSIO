use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::Client;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use myfsio_common::types::{ListParams, ObjectMeta};
use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;

use crate::services::peer_fetch::PeerFetcher;
use crate::services::replication::{ReplicationManager, ReplicationRule, MODE_BIDIRECTIONAL};
use crate::services::s3_client::{build_client, ClientOptions};
use crate::stores::connections::ConnectionStore;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncedObjectInfo {
    pub last_synced_at: f64,
    pub remote_etag: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncState {
    #[serde(default)]
    pub synced_objects: HashMap<String, SyncedObjectInfo>,
    #[serde(default)]
    pub last_full_sync: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiteSyncStats {
    pub last_sync_at: Option<f64>,
    pub objects_pulled: u64,
    pub objects_skipped: u64,
    pub conflicts_resolved: u64,
    pub deletions_applied: u64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
struct RemoteObjectMeta {
    last_modified: f64,
    etag: String,
}

pub struct SiteSyncWorker {
    storage: Arc<FsStorageBackend>,
    connections: Arc<ConnectionStore>,
    replication: Arc<ReplicationManager>,
    peer_fetcher: Arc<PeerFetcher>,
    storage_root: PathBuf,
    interval: Duration,
    batch_size: usize,
    clock_skew_tolerance: f64,
    client_options: ClientOptions,
    bucket_stats: Mutex<HashMap<String, SiteSyncStats>>,
    shutdown: Arc<Notify>,
}

impl SiteSyncWorker {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        connections: Arc<ConnectionStore>,
        replication: Arc<ReplicationManager>,
        storage_root: PathBuf,
        interval_seconds: u64,
        batch_size: usize,
        connect_timeout: Duration,
        read_timeout: Duration,
        max_retries: u32,
        clock_skew_tolerance: f64,
    ) -> Self {
        let client_options = ClientOptions {
            connect_timeout,
            read_timeout,
            max_attempts: max_retries,
        };
        let peer_fetcher = Arc::new(PeerFetcher::new(
            storage.clone(),
            connections.clone(),
            replication.clone(),
            ClientOptions {
                connect_timeout,
                read_timeout,
                max_attempts: max_retries,
            },
        ));
        let bucket_stats = Mutex::new(load_stats(&storage_root));
        Self {
            storage,
            connections,
            replication,
            peer_fetcher,
            storage_root,
            interval: Duration::from_secs(interval_seconds),
            batch_size,
            clock_skew_tolerance,
            client_options,
            bucket_stats,
            shutdown: Arc::new(Notify::new()),
        }
    }

    pub fn peer_fetcher(&self) -> Arc<PeerFetcher> {
        self.peer_fetcher.clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    pub fn get_stats(&self, bucket: &str) -> Option<SiteSyncStats> {
        self.bucket_stats.lock().get(bucket).cloned()
    }

    pub fn snapshot_stats(&self) -> HashMap<String, SiteSyncStats> {
        self.bucket_stats.lock().clone()
    }

    fn save_stats(&self) {
        let snapshot = self.bucket_stats.lock().clone();
        save_stats(&self.storage_root, &snapshot);
    }

    pub async fn run(self: Arc<Self>) {
        tracing::info!(
            "Site sync worker started (interval={}s)",
            self.interval.as_secs()
        );
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {}
                _ = self.shutdown.notified() => {
                    tracing::info!("Site sync worker shutting down");
                    return;
                }
            }
            self.run_cycle().await;
        }
    }

    async fn run_cycle(&self) {
        let rules = self.replication.rules_snapshot();
        let mut mutated = false;
        for (bucket, rule) in rules {
            if rule.mode != MODE_BIDIRECTIONAL || !rule.enabled {
                continue;
            }
            match self.sync_bucket(&rule).await {
                Ok(stats) => {
                    self.bucket_stats.lock().insert(bucket, stats);
                    mutated = true;
                }
                Err(e) => {
                    tracing::error!("Site sync failed for bucket {}: {}", bucket, e);
                }
            }
        }
        if mutated {
            self.save_stats();
        }
    }

    pub async fn trigger_sync(&self, bucket: &str) -> Option<SiteSyncStats> {
        let rule = self.replication.get_rule(bucket)?;
        if rule.mode != MODE_BIDIRECTIONAL || !rule.enabled {
            return None;
        }
        match self.sync_bucket(&rule).await {
            Ok(stats) => {
                self.bucket_stats
                    .lock()
                    .insert(bucket.to_string(), stats.clone());
                self.save_stats();
                Some(stats)
            }
            Err(e) => {
                tracing::error!("Site sync trigger failed for {}: {}", bucket, e);
                None
            }
        }
    }

    async fn sync_bucket(&self, rule: &ReplicationRule) -> Result<SiteSyncStats, String> {
        let mut stats = SiteSyncStats::default();
        let connection = self
            .connections
            .get(&rule.target_connection_id)
            .ok_or_else(|| format!("connection {} not found", rule.target_connection_id))?;

        let local_objects = self
            .list_local_objects(&rule.bucket_name)
            .await
            .map_err(|e| format!("list local failed: {}", e))?;

        let client = build_client(&connection, &self.client_options);
        let remote_objects = self
            .list_remote_objects(&client, &rule.target_bucket)
            .await
            .map_err(|e| format!("list remote failed: {}", e))?;

        let mut sync_state = self.load_sync_state(&rule.bucket_name);

        let mut to_pull: Vec<String> = Vec::new();
        for (key, remote_meta) in &remote_objects {
            if let Some(local_meta) = local_objects.get(key) {
                match self.resolve_conflict(local_meta, remote_meta) {
                    "pull" => {
                        to_pull.push(key.clone());
                        stats.conflicts_resolved += 1;
                    }
                    _ => {
                        stats.objects_skipped += 1;
                    }
                }
            } else {
                to_pull.push(key.clone());
            }
        }

        let mut pulled = 0usize;
        for key in &to_pull {
            if pulled >= self.batch_size {
                break;
            }
            let remote_meta = match remote_objects.get(key) {
                Some(m) => m,
                None => continue,
            };
            if self
                .pull_object(&client, &rule.target_bucket, &rule.bucket_name, key)
                .await
            {
                stats.objects_pulled += 1;
                pulled += 1;
                sync_state.synced_objects.insert(
                    key.clone(),
                    SyncedObjectInfo {
                        last_synced_at: now_secs(),
                        remote_etag: remote_meta.etag.clone(),
                        source: "remote".to_string(),
                    },
                );
            } else {
                stats.errors += 1;
            }
        }

        if rule.sync_deletions {
            let tracked_keys: Vec<String> = sync_state.synced_objects.keys().cloned().collect();
            for key in tracked_keys {
                if remote_objects.contains_key(&key) {
                    continue;
                }
                let local_meta = match local_objects.get(&key) {
                    Some(m) => m,
                    None => continue,
                };
                let tracked = match sync_state.synced_objects.get(&key) {
                    Some(t) => t.clone(),
                    None => continue,
                };
                if tracked.source != "remote" {
                    continue;
                }
                let local_ts = local_meta.last_modified.timestamp() as f64;
                if local_ts <= tracked.last_synced_at
                    && self.apply_remote_deletion(&rule.bucket_name, &key).await
                {
                    stats.deletions_applied += 1;
                    sync_state.synced_objects.remove(&key);
                }
            }
        }

        sync_state.last_full_sync = Some(now_secs());
        self.save_sync_state(&rule.bucket_name, &sync_state);

        self.replication
            .update_last_pull(&rule.bucket_name, now_secs());

        stats.last_sync_at = Some(now_secs());
        tracing::info!(
            "Site sync completed for {}: pulled={}, skipped={}, conflicts={}, deletions={}, errors={}",
            rule.bucket_name,
            stats.objects_pulled,
            stats.objects_skipped,
            stats.conflicts_resolved,
            stats.deletions_applied,
            stats.errors,
        );
        Ok(stats)
    }

    async fn list_local_objects(
        &self,
        bucket: &str,
    ) -> Result<HashMap<String, ObjectMeta>, String> {
        let mut result = HashMap::new();
        let mut token: Option<String> = None;
        loop {
            let params = ListParams {
                max_keys: 1000,
                continuation_token: token.clone(),
                prefix: None,
                start_after: None,
            };
            let page = self
                .storage
                .list_objects(bucket, &params)
                .await
                .map_err(|e| e.to_string())?;
            for obj in page.objects {
                result.insert(obj.key.clone(), obj);
            }
            if !page.is_truncated {
                break;
            }
            token = page.next_continuation_token;
            if token.is_none() {
                break;
            }
        }
        Ok(result)
    }

    async fn list_remote_objects(
        &self,
        client: &Client,
        bucket: &str,
    ) -> Result<HashMap<String, RemoteObjectMeta>, String> {
        let mut result = HashMap::new();
        let mut continuation: Option<String> = None;
        loop {
            let mut req = client.list_objects_v2().bucket(bucket);
            if let Some(ref t) = continuation {
                req = req.continuation_token(t);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(err) => {
                    if is_not_found_error(&err) {
                        return Ok(result);
                    }
                    return Err(format!("{:?}", err));
                }
            };
            for obj in resp.contents() {
                let key = match obj.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };
                let last_modified = obj
                    .last_modified()
                    .and_then(|t| {
                        let secs = t.secs();
                        let nanos = t.subsec_nanos();
                        Some(secs as f64 + nanos as f64 / 1_000_000_000.0)
                    })
                    .unwrap_or(0.0);
                let etag = obj.e_tag().unwrap_or("").trim_matches('"').to_string();
                result.insert(
                    key,
                    RemoteObjectMeta {
                        last_modified,
                        etag,
                    },
                );
            }
            if resp.is_truncated().unwrap_or(false) {
                continuation = resp.next_continuation_token().map(|s| s.to_string());
                if continuation.is_none() {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(result)
    }

    fn resolve_conflict(&self, local: &ObjectMeta, remote: &RemoteObjectMeta) -> &'static str {
        let local_ts = local.last_modified.timestamp() as f64
            + local.last_modified.timestamp_subsec_nanos() as f64 / 1_000_000_000.0;
        let remote_ts = remote.last_modified;

        if (remote_ts - local_ts).abs() < self.clock_skew_tolerance {
            let local_etag = local.etag.clone().unwrap_or_default();
            let local_etag_trim = local_etag.trim_matches('"');
            if remote.etag == local_etag_trim {
                return "skip";
            }
            if remote.etag.as_str() > local_etag_trim {
                return "pull";
            }
            return "keep";
        }

        if remote_ts > local_ts {
            "pull"
        } else {
            "keep"
        }
    }

    async fn pull_object(
        &self,
        client: &Client,
        remote_bucket: &str,
        local_bucket: &str,
        key: &str,
    ) -> bool {
        self.peer_fetcher
            .fetch_into_storage(client, remote_bucket, local_bucket, key)
            .await
    }

    async fn apply_remote_deletion(&self, bucket: &str, key: &str) -> bool {
        match self.storage.delete_object(bucket, key).await {
            Ok(_) => {
                tracing::debug!("Applied remote deletion for {}/{}", bucket, key);
                true
            }
            Err(err) => {
                tracing::error!("Remote deletion failed {}/{}: {}", bucket, key, err);
                false
            }
        }
    }

    fn sync_state_path(&self, bucket: &str) -> PathBuf {
        self.storage_root
            .join(".myfsio.sys")
            .join("buckets")
            .join(bucket)
            .join("site_sync_state.json")
    }

    fn load_sync_state(&self, bucket: &str) -> SyncState {
        let path = self.sync_state_path(bucket);
        if !path.exists() {
            return SyncState::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => SyncState::default(),
        }
    }

    fn save_sync_state(&self, bucket: &str, state: &SyncState) {
        let path = self.sync_state_path(bucket);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(state) {
            let _ = std::fs::write(&path, text);
        }
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn stats_path(storage_root: &std::path::Path) -> PathBuf {
    storage_root
        .join(".myfsio.sys")
        .join("config")
        .join("site_sync_stats.json")
}

fn load_stats(storage_root: &std::path::Path) -> HashMap<String, SiteSyncStats> {
    let path = stats_path(storage_root);
    if !path.exists() {
        return HashMap::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_stats(storage_root: &std::path::Path, stats: &HashMap<String, SiteSyncStats>) {
    let path = stats_path(storage_root);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(stats) {
        let _ = std::fs::write(&path, text);
    }
}

fn is_not_found_error<E: std::fmt::Debug>(err: &aws_sdk_s3::error::SdkError<E>) -> bool {
    let msg = format!("{:?}", err);
    msg.contains("NoSuchBucket")
        || msg.contains("code: Some(\"NotFound\")")
        || msg.contains("code: Some(\"NoSuchBucket\")")
        || msg.contains("status: 404")
}
