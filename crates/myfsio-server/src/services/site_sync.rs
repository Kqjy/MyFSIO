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
    #[serde(default)]
    pub local_etag: String,
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
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_error_at: Option<f64>,
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
    pub(crate) async fn endpoint_allowed(&self, endpoint: &str) -> Result<(), String> {
        self.replication.endpoint_allowed(endpoint).await
    }
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
        encryption: Option<Arc<myfsio_crypto::encryption::EncryptionService>>,
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
            encryption,
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

    fn save_stats(&self) -> std::io::Result<()> {
        let snapshot = self.bucket_stats.lock().clone();
        save_stats(&self.storage_root, &snapshot)
    }

    fn record_failure(&self, bucket: &str, error: &str) {
        let mut stats = self.bucket_stats.lock();
        record_cycle_failure(&mut stats, bucket, error, now_secs());
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
                    self.record_failure(&bucket, &e);
                    mutated = true;
                }
            }
        }
        if mutated {
            if let Err(err) = self.save_stats() {
                tracing::error!(
                    path = %stats_path(&self.storage_root).display(),
                    error = %err,
                    "Failed to persist site sync stats; the dashboard counters will fall back to the last durable snapshot after a restart"
                );
            }
        }
    }

    async fn sync_bucket(&self, rule: &ReplicationRule) -> Result<SiteSyncStats, String> {
        let mut stats = SiteSyncStats::default();
        let connection = self
            .connections
            .get(&rule.target_connection_id)
            .ok_or_else(|| format!("connection {} not found", rule.target_connection_id))?;

        if let Err(reason) = self.endpoint_allowed(&connection.endpoint_url).await {
            return Err(format!(
                "endpoint rejected for connection '{}': {}. Set ALLOW_INTERNAL_ENDPOINTS=true to allow.",
                connection.name, reason
            ));
        }

        let local_objects = self
            .list_local_objects(&rule.bucket_name)
            .await
            .map_err(|e| format!("list local failed: {}", e))?;

        let client = build_client(
            &connection,
            &self.client_options,
            self.replication.http_client(),
        );
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
                let local_etag = self
                    .storage
                    .get_object_metadata(&rule.bucket_name, key)
                    .await
                    .ok()
                    .and_then(|m| m.get("__etag__").cloned())
                    .unwrap_or_default();
                sync_state.synced_objects.insert(
                    key.clone(),
                    SyncedObjectInfo {
                        last_synced_at: now_secs(),
                        remote_etag: remote_meta.etag.clone(),
                        local_etag,
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
                if !local_objects.contains_key(&key) {
                    continue;
                }
                let tracked = match sync_state.synced_objects.get(&key) {
                    Some(t) => t.clone(),
                    None => continue,
                };
                if tracked.source != "remote" {
                    continue;
                }
                let current_meta = match self
                    .storage
                    .get_object_metadata(&rule.bucket_name, &key)
                    .await
                {
                    Ok(meta) => meta,
                    Err(_) => {
                        continue;
                    }
                };
                let current_etag = current_meta.get("__etag__").cloned().unwrap_or_default();
                let current_last_modified = current_meta
                    .get("__last_modified__")
                    .and_then(|s| s.parse::<f64>().ok())
                    .or_else(|| {
                        local_objects.get(&key).map(|m| {
                            m.last_modified.timestamp() as f64
                                + m.last_modified.timestamp_subsec_nanos() as f64 / 1_000_000_000.0
                        })
                    });
                if !tracked.local_etag.is_empty()
                    && !current_etag.is_empty()
                    && current_etag != tracked.local_etag
                {
                    tracing::info!(
                        "Skipping remote-deletion for {}/{}: local etag changed since last sync",
                        rule.bucket_name,
                        key
                    );
                    continue;
                }
                let Some(current_last_modified) = current_last_modified else {
                    tracing::info!(
                        "Skipping remote-deletion for {}/{}: local timestamp could not be determined",
                        rule.bucket_name,
                        key
                    );
                    continue;
                };
                if current_last_modified > tracked.last_synced_at {
                    tracing::info!(
                        "Skipping remote-deletion for {}/{}: local timestamp newer than tracked sync",
                        rule.bucket_name,
                        key
                    );
                    continue;
                }
                if self.apply_remote_deletion(&rule.bucket_name, &key).await {
                    stats.deletions_applied += 1;
                    sync_state.synced_objects.remove(&key);
                }
            }
        }

        sync_state.last_full_sync = Some(now_secs());
        self.save_sync_state(&rule.bucket_name, &sync_state)
            .map_err(|e| format!("save sync cursor failed: {}", e))?;

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
                    return Err(remote_list_error(bucket, &format!("{:?}", err)));
                }
            };
            for obj in resp.contents() {
                let key = match obj.key() {
                    Some(k) => k.to_string(),
                    None => continue,
                };
                let last_modified = obj
                    .last_modified()
                    .map(|t| {
                        let secs = t.secs();
                        let nanos = t.subsec_nanos();
                        secs as f64 + nanos as f64 / 1_000_000_000.0
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
        let local_etag = local.etag.clone().unwrap_or_default();
        resolve_conflict_decision(
            local_ts,
            local_etag.trim_matches('"'),
            remote.last_modified,
            &remote.etag,
            self.clock_skew_tolerance,
        )
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
        match read_sync_state(&path) {
            Ok(state) => state,
            Err(err) => {
                preserve_unreadable_state(
                    &path,
                    &err.to_string(),
                    "Site sync cursor is unreadable; preserved it and continued from an empty cursor, so this bucket will be fully re-scanned and conflicts re-resolved",
                );
                SyncState::default()
            }
        }
    }

    fn save_sync_state(&self, bucket: &str, state: &SyncState) -> std::io::Result<()> {
        write_json_file(&self.sync_state_path(bucket), state)
    }
}

fn resolve_conflict_decision(
    local_ts: f64,
    local_etag: &str,
    remote_ts: f64,
    remote_etag: &str,
    clock_skew_tolerance: f64,
) -> &'static str {
    if (remote_ts - local_ts).abs() < clock_skew_tolerance {
        if remote_etag == local_etag {
            return "skip";
        }
        if remote_etag > local_etag {
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

fn read_sync_state(path: &std::path::Path) -> std::io::Result<SyncState> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(std::io::Error::other),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(SyncState::default()),
        Err(err) => Err(err),
    }
}

fn read_stats(path: &std::path::Path) -> std::io::Result<HashMap<String, SiteSyncStats>> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(std::io::Error::other),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err),
    }
}

fn write_json_file<T: Serialize>(path: &std::path::Path, value: &T) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    myfsio_common::fs_util::atomic_write_file(path, &bytes)
}

fn preserve_unreadable_state(path: &std::path::Path, reason: &str, outcome: &str) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("site_sync_state.json");
    let preserved = path.with_file_name(format!("{}.corrupt-{}", name, now_secs() as i64));
    match std::fs::rename(path, &preserved) {
        Ok(()) => tracing::error!(
            path = %path.display(),
            preserved_path = %preserved.display(),
            reason,
            "{}",
            outcome
        ),
        Err(rename_error) => tracing::error!(
            path = %path.display(),
            reason,
            rename_error = %rename_error,
            "{} (the damaged file could not be preserved)",
            outcome
        ),
    }
}

fn load_stats(storage_root: &std::path::Path) -> HashMap<String, SiteSyncStats> {
    let path = stats_path(storage_root);
    match read_stats(&path) {
        Ok(stats) => stats,
        Err(err) => {
            preserve_unreadable_state(
                &path,
                &err.to_string(),
                "Site sync stats are unreadable; preserved them and continued with empty counters",
            );
            HashMap::new()
        }
    }
}

fn save_stats(
    storage_root: &std::path::Path,
    stats: &HashMap<String, SiteSyncStats>,
) -> std::io::Result<()> {
    write_json_file(&stats_path(storage_root), stats)
}

fn record_cycle_failure(
    stats: &mut HashMap<String, SiteSyncStats>,
    bucket: &str,
    error: &str,
    at: f64,
) {
    let entry = stats.entry(bucket.to_string()).or_default();
    entry.errors = entry.errors.saturating_add(1);
    entry.last_error = Some(error.to_string());
    entry.last_error_at = Some(at);
}

fn is_not_found_error(debug: &str) -> bool {
    debug.contains("NoSuchBucket")
        || debug.contains("code: Some(\"NotFound\")")
        || debug.contains("code: Some(\"NoSuchBucket\")")
        || debug.contains("status: 404")
}

fn remote_list_error(bucket: &str, debug: &str) -> String {
    if is_not_found_error(debug) {
        format!(
            "remote bucket '{}' not found (skipping sync cycle to protect local data)",
            bucket
        )
    } else {
        debug.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_resolution_is_last_writer_wins_outside_the_skew_window() {
        assert_eq!(
            resolve_conflict_decision(100.0, "aaa", 200.0, "bbb", 1.0),
            "pull"
        );
        assert_eq!(
            resolve_conflict_decision(200.0, "aaa", 100.0, "bbb", 1.0),
            "keep"
        );
    }

    #[test]
    fn identical_etags_inside_the_skew_window_are_skipped() {
        assert_eq!(
            resolve_conflict_decision(100.0, "same", 100.5, "same", 1.0),
            "skip"
        );
    }

    #[test]
    fn differing_etags_inside_the_skew_window_use_the_lexical_tiebreaker() {
        assert_eq!(
            resolve_conflict_decision(100.0, "aaa", 100.5, "bbb", 1.0),
            "pull"
        );
        assert_eq!(
            resolve_conflict_decision(100.0, "bbb", 100.5, "aaa", 1.0),
            "keep"
        );
    }

    #[test]
    fn conflict_resolution_converges_from_both_sides() {
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state >> 16
        };
        for _ in 0..2000 {
            let ts_a = 1000.0 + (next() % 100) as f64 / 10.0;
            let ts_b = 1000.0 + (next() % 100) as f64 / 10.0;
            let etag_a = format!("{:08x}", next() as u32);
            let etag_b = format!("{:08x}", next() as u32);
            let tolerance = 1.0;

            let a_decision = resolve_conflict_decision(ts_a, &etag_a, ts_b, &etag_b, tolerance);
            let b_decision = resolve_conflict_decision(ts_b, &etag_b, ts_a, &etag_a, tolerance);

            if etag_a == etag_b && (ts_a - ts_b).abs() < tolerance {
                assert_eq!(a_decision, "skip");
                assert_eq!(b_decision, "skip");
                continue;
            }
            assert!(
                (a_decision == "pull") ^ (b_decision == "pull"),
                "exactly one site must pull for convergence: \
                 a=({ts_a},{etag_a})->{a_decision} b=({ts_b},{etag_b})->{b_decision}"
            );
        }
    }

    #[test]
    fn missing_remote_bucket_is_classified_as_not_found() {
        assert!(is_not_found_error(
            "ServiceError(ServiceError { source: NoSuchBucket(NoSuchBucket) })"
        ));
        assert!(is_not_found_error("code: Some(\"NotFound\")"));
        assert!(is_not_found_error("status: 404"));
        assert!(!is_not_found_error("status: 503, code: Some(\"SlowDown\")"));
    }

    #[test]
    fn remote_list_error_names_the_missing_bucket() {
        let msg = remote_list_error("photos", "code: Some(\"NoSuchBucket\")");
        assert_eq!(
            msg,
            "remote bucket 'photos' not found (skipping sync cycle to protect local data)"
        );
    }

    #[test]
    fn remote_list_error_preserves_other_failures() {
        let msg = remote_list_error("photos", "DispatchFailure(ConnectorError)");
        assert_eq!(msg, "DispatchFailure(ConnectorError)");
    }

    #[test]
    fn a_failed_cycle_increments_errors_and_records_the_reason() {
        let mut stats: HashMap<String, SiteSyncStats> = HashMap::new();
        record_cycle_failure(&mut stats, "photos", "list remote failed: boom", 100.0);
        record_cycle_failure(&mut stats, "photos", "list remote failed: boom", 160.0);

        let entry = stats.get("photos").unwrap();
        assert_eq!(entry.errors, 2);
        assert_eq!(
            entry.last_error.as_deref(),
            Some("list remote failed: boom")
        );
        assert_eq!(entry.last_error_at, Some(160.0));
    }

    #[test]
    fn a_successful_cycle_clears_the_recorded_failure() {
        let mut stats: HashMap<String, SiteSyncStats> = HashMap::new();
        record_cycle_failure(&mut stats, "photos", "list remote failed: boom", 100.0);
        stats.insert(
            "photos".to_string(),
            SiteSyncStats {
                last_sync_at: Some(200.0),
                objects_pulled: 3,
                ..SiteSyncStats::default()
            },
        );

        let entry = stats.get("photos").unwrap();
        assert_eq!(entry.errors, 0);
        assert!(entry.last_error.is_none());
        assert!(entry.last_error_at.is_none());
    }

    #[test]
    fn stats_persisted_before_the_error_fields_existed_still_load() {
        let legacy = r#"{"last_sync_at":1.5,"objects_pulled":4,"objects_skipped":1,
            "conflicts_resolved":0,"deletions_applied":2,"errors":0}"#;
        let stats: SiteSyncStats = serde_json::from_str(legacy).unwrap();

        assert_eq!(stats.objects_pulled, 4);
        assert_eq!(stats.deletions_applied, 2);
        assert!(stats.last_error.is_none());
        assert!(stats.last_error_at.is_none());
    }

    fn file_names(dir: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn absent_sync_files_load_empty_without_failing() {
        let tmp = tempfile::tempdir().expect("tempdir");

        assert!(load_stats(tmp.path()).is_empty());
        let state =
            read_sync_state(&tmp.path().join("site_sync_state.json")).expect("absent state");
        assert!(state.synced_objects.is_empty());
        assert!(state.last_full_sync.is_none());
        assert!(!tmp.path().join(".myfsio.sys").exists());
    }

    #[test]
    fn damaged_sync_stats_are_preserved_instead_of_silently_emptied() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = stats_path(tmp.path());
        std::fs::create_dir_all(path.parent().unwrap()).expect("create config dir");
        std::fs::write(&path, "{not json").expect("write stats");

        assert!(read_stats(&path).is_err());
        assert!(load_stats(tmp.path()).is_empty());
        assert!(!path.exists());
        assert!(file_names(path.parent().unwrap())
            .iter()
            .any(|name| name.starts_with("site_sync_stats.json.corrupt-")));
    }

    #[test]
    fn damaged_sync_cursor_is_preserved_instead_of_silently_emptied() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp
            .path()
            .join(".myfsio.sys")
            .join("buckets")
            .join("photos")
            .join("site_sync_state.json");
        std::fs::create_dir_all(path.parent().unwrap()).expect("create bucket dir");
        std::fs::write(&path, "{not json").expect("write state");

        let err = read_sync_state(&path).expect_err("damaged cursor must not load empty");
        preserve_unreadable_state(&path, &err.to_string(), "test outcome");

        assert!(!path.exists());
        assert!(file_names(path.parent().unwrap())
            .iter()
            .any(|name| name.starts_with("site_sync_state.json.corrupt-")));
    }

    #[test]
    fn sync_cursor_and_stats_round_trip_and_leave_no_temp_residue() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state_path = tmp
            .path()
            .join(".myfsio.sys")
            .join("buckets")
            .join("photos")
            .join("site_sync_state.json");
        let state = SyncState {
            synced_objects: HashMap::from([(
                "a/b.txt".to_string(),
                SyncedObjectInfo {
                    last_synced_at: 10.0,
                    remote_etag: "remote".to_string(),
                    local_etag: "local".to_string(),
                    source: "peer".to_string(),
                },
            )]),
            last_full_sync: Some(1234.5),
        };
        write_json_file(&state_path, &state).expect("write state");

        let mut stats: HashMap<String, SiteSyncStats> = HashMap::new();
        stats.insert(
            "photos".to_string(),
            SiteSyncStats {
                objects_pulled: 7,
                ..SiteSyncStats::default()
            },
        );
        save_stats(tmp.path(), &stats).expect("write stats");

        let reloaded_state = read_sync_state(&state_path).expect("reload state");
        assert_eq!(reloaded_state.last_full_sync, Some(1234.5));
        assert_eq!(
            reloaded_state
                .synced_objects
                .get("a/b.txt")
                .expect("object")
                .remote_etag,
            "remote"
        );
        assert_eq!(load_stats(tmp.path())["photos"].objects_pulled, 7);

        for dir in [
            state_path.parent().unwrap(),
            stats_path(tmp.path()).parent().unwrap(),
        ] {
            assert!(!file_names(dir).iter().any(|name| name.contains(".tmp-")));
        }
    }
}
