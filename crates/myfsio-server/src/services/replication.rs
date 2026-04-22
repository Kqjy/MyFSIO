use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::primitives::ByteStream;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use myfsio_common::types::ListParams;
use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;

use crate::services::s3_client::{build_client, check_endpoint_health, ClientOptions};
use crate::stores::connections::{ConnectionStore, RemoteConnection};

pub const MODE_NEW_ONLY: &str = "new_only";
pub const MODE_ALL: &str = "all";
pub const MODE_BIDIRECTIONAL: &str = "bidirectional";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplicationStats {
    #[serde(default)]
    pub objects_synced: u64,
    #[serde(default)]
    pub objects_pending: u64,
    #[serde(default)]
    pub objects_orphaned: u64,
    #[serde(default)]
    pub bytes_synced: u64,
    #[serde(default)]
    pub last_sync_at: Option<f64>,
    #[serde(default)]
    pub last_sync_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationRule {
    pub bucket_name: String,
    pub target_connection_id: String,
    pub target_bucket: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub created_at: Option<f64>,
    #[serde(default)]
    pub stats: ReplicationStats,
    #[serde(default = "default_true")]
    pub sync_deletions: bool,
    #[serde(default)]
    pub last_pull_at: Option<f64>,
    #[serde(default)]
    pub filter_prefix: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_mode() -> String {
    MODE_NEW_ONLY.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationFailure {
    pub object_key: String,
    pub error_message: String,
    pub timestamp: f64,
    pub failure_count: u32,
    pub bucket_name: String,
    pub action: String,
    #[serde(default)]
    pub last_error_code: Option<String>,
}

pub struct ReplicationFailureStore {
    storage_root: PathBuf,
    max_failures_per_bucket: usize,
    cache: Mutex<HashMap<String, Vec<ReplicationFailure>>>,
}

impl ReplicationFailureStore {
    pub fn new(storage_root: PathBuf, max_failures_per_bucket: usize) -> Self {
        Self {
            storage_root,
            max_failures_per_bucket,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn path(&self, bucket: &str) -> PathBuf {
        self.storage_root
            .join(".myfsio.sys")
            .join("buckets")
            .join(bucket)
            .join("replication_failures.json")
    }

    fn load_from_disk(&self, bucket: &str) -> Vec<ReplicationFailure> {
        let path = self.path(bucket);
        if !path.exists() {
            return Vec::new();
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                let parsed: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => return Vec::new(),
                };
                parsed
                    .get("failures")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .unwrap_or_default()
            }
            Err(_) => Vec::new(),
        }
    }

    fn save_to_disk(&self, bucket: &str, failures: &[ReplicationFailure]) {
        let path = self.path(bucket);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let trimmed = &failures[..failures.len().min(self.max_failures_per_bucket)];
        let data = serde_json::json!({ "failures": trimmed });
        let _ = std::fs::write(
            &path,
            serde_json::to_string_pretty(&data).unwrap_or_default(),
        );
    }

    pub fn load(&self, bucket: &str) -> Vec<ReplicationFailure> {
        let mut cache = self.cache.lock();
        if let Some(existing) = cache.get(bucket) {
            return existing.clone();
        }
        let loaded = self.load_from_disk(bucket);
        cache.insert(bucket.to_string(), loaded.clone());
        loaded
    }

    pub fn save(&self, bucket: &str, failures: Vec<ReplicationFailure>) {
        let trimmed: Vec<ReplicationFailure> = failures
            .into_iter()
            .take(self.max_failures_per_bucket)
            .collect();
        self.save_to_disk(bucket, &trimmed);
        self.cache.lock().insert(bucket.to_string(), trimmed);
    }

    pub fn add(&self, bucket: &str, failure: ReplicationFailure) {
        let mut failures = self.load(bucket);
        if let Some(existing) = failures
            .iter_mut()
            .find(|f| f.object_key == failure.object_key)
        {
            existing.failure_count += 1;
            existing.timestamp = failure.timestamp;
            existing.error_message = failure.error_message.clone();
            existing.last_error_code = failure.last_error_code.clone();
        } else {
            failures.insert(0, failure);
        }
        self.save(bucket, failures);
    }

    pub fn remove(&self, bucket: &str, object_key: &str) -> bool {
        let failures = self.load(bucket);
        let before = failures.len();
        let after: Vec<_> = failures
            .into_iter()
            .filter(|f| f.object_key != object_key)
            .collect();
        if after.len() != before {
            self.save(bucket, after);
            true
        } else {
            false
        }
    }

    pub fn clear(&self, bucket: &str) {
        self.cache.lock().remove(bucket);
        let path = self.path(bucket);
        let _ = std::fs::remove_file(path);
    }

    pub fn get(&self, bucket: &str, object_key: &str) -> Option<ReplicationFailure> {
        self.load(bucket)
            .into_iter()
            .find(|f| f.object_key == object_key)
    }

    pub fn count(&self, bucket: &str) -> usize {
        self.load(bucket).len()
    }
}

pub struct ReplicationManager {
    storage: Arc<FsStorageBackend>,
    connections: Arc<ConnectionStore>,
    rules_path: PathBuf,
    rules: Mutex<HashMap<String, ReplicationRule>>,
    client_options: ClientOptions,
    streaming_threshold_bytes: u64,
    pub failures: Arc<ReplicationFailureStore>,
    semaphore: Arc<Semaphore>,
}

impl ReplicationManager {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        connections: Arc<ConnectionStore>,
        storage_root: &Path,
        connect_timeout: Duration,
        read_timeout: Duration,
        max_retries: u32,
        streaming_threshold_bytes: u64,
        max_failures_per_bucket: usize,
    ) -> Self {
        let rules_path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("replication_rules.json");
        let rules = load_rules(&rules_path);
        let failures = Arc::new(ReplicationFailureStore::new(
            storage_root.to_path_buf(),
            max_failures_per_bucket,
        ));
        let client_options = ClientOptions {
            connect_timeout,
            read_timeout,
            max_attempts: max_retries,
        };
        Self {
            storage,
            connections,
            rules_path,
            rules: Mutex::new(rules),
            client_options,
            streaming_threshold_bytes,
            failures,
            semaphore: Arc::new(Semaphore::new(4)),
        }
    }

    pub fn reload_rules(&self) {
        *self.rules.lock() = load_rules(&self.rules_path);
    }

    pub fn list_rules(&self) -> Vec<ReplicationRule> {
        self.rules.lock().values().cloned().collect()
    }

    pub fn get_rule(&self, bucket: &str) -> Option<ReplicationRule> {
        self.rules.lock().get(bucket).cloned()
    }

    pub fn set_rule(&self, rule: ReplicationRule) {
        {
            let mut guard = self.rules.lock();
            guard.insert(rule.bucket_name.clone(), rule);
        }
        self.save_rules();
    }

    pub fn delete_rule(&self, bucket: &str) {
        {
            let mut guard = self.rules.lock();
            guard.remove(bucket);
        }
        self.save_rules();
    }

    pub fn save_rules(&self) {
        let snapshot: HashMap<String, ReplicationRule> = self.rules.lock().clone();
        if let Some(parent) = self.rules_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&snapshot) {
            let _ = std::fs::write(&self.rules_path, text);
        }
    }

    fn update_last_sync(&self, bucket: &str, key: &str) {
        {
            let mut guard = self.rules.lock();
            if let Some(rule) = guard.get_mut(bucket) {
                rule.stats.last_sync_at = Some(now_secs());
                rule.stats.last_sync_key = Some(key.to_string());
            }
        }
        self.save_rules();
    }

    pub async fn trigger(self: Arc<Self>, bucket: String, key: String, action: String) {
        let rule = match self.get_rule(&bucket) {
            Some(r) if r.enabled => r,
            _ => return,
        };
        let connection = match self.connections.get(&rule.target_connection_id) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "Replication skipped for {}/{}: connection {} not found",
                    bucket,
                    key,
                    rule.target_connection_id
                );
                return;
            }
        };
        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let sem = self.semaphore.clone();
                match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return,
                }
            }
        };
        let manager = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            manager
                .replicate_task(&bucket, &key, &rule, &connection, &action)
                .await;
        });
    }

    pub async fn replicate_existing_objects(self: Arc<Self>, bucket: String) -> usize {
        let rule = match self.get_rule(&bucket) {
            Some(r) if r.enabled => r,
            _ => return 0,
        };
        let connection = match self.connections.get(&rule.target_connection_id) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "Cannot replicate existing objects for {}: connection {} not found",
                    bucket,
                    rule.target_connection_id
                );
                return 0;
            }
        };
        if !self.check_endpoint(&connection).await {
            tracing::warn!(
                "Cannot replicate existing objects for {}: endpoint {} is unreachable",
                bucket,
                connection.endpoint_url
            );
            return 0;
        }

        let mut continuation_token: Option<String> = None;
        let mut submitted = 0usize;

        loop {
            let page = match self
                .storage
                .list_objects(
                    &bucket,
                    &ListParams {
                        max_keys: 1000,
                        continuation_token: continuation_token.clone(),
                        prefix: rule.filter_prefix.clone(),
                        start_after: None,
                    },
                )
                .await
            {
                Ok(page) => page,
                Err(err) => {
                    tracing::error!(
                        "Failed to list existing objects for replication in {}: {}",
                        bucket,
                        err
                    );
                    break;
                }
            };

            let next_token = page.next_continuation_token.clone();
            let is_truncated = page.is_truncated;

            for object in page.objects {
                submitted += 1;
                self.clone()
                    .trigger(bucket.clone(), object.key, "write".to_string())
                    .await;
            }

            if !is_truncated {
                break;
            }

            continuation_token = next_token;
            if continuation_token.is_none() {
                break;
            }
        }

        submitted
    }

    pub fn schedule_existing_objects_sync(self: Arc<Self>, bucket: String) {
        tokio::spawn(async move {
            let submitted = self
                .clone()
                .replicate_existing_objects(bucket.clone())
                .await;
            if submitted > 0 {
                tracing::info!(
                    "Scheduled {} existing object(s) for replication in {}",
                    submitted,
                    bucket
                );
            }
        });
    }

    async fn replicate_task(
        &self,
        bucket: &str,
        object_key: &str,
        rule: &ReplicationRule,
        conn: &RemoteConnection,
        action: &str,
    ) {
        if object_key.contains("..") || object_key.starts_with('/') || object_key.starts_with('\\')
        {
            tracing::error!("Invalid object key (path traversal): {}", object_key);
            return;
        }

        let client = build_client(conn, &self.client_options);

        if action == "delete" {
            match client
                .delete_object()
                .bucket(&rule.target_bucket)
                .key(object_key)
                .send()
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        "Replicated DELETE {}/{} to {} ({})",
                        bucket,
                        object_key,
                        conn.name,
                        rule.target_bucket
                    );
                    self.update_last_sync(bucket, object_key);
                    self.failures.remove(bucket, object_key);
                }
                Err(err) => {
                    let msg = format!("{:?}", err);
                    tracing::error!(
                        "Replication DELETE failed {}/{}: {}",
                        bucket,
                        object_key,
                        msg
                    );
                    self.failures.add(
                        bucket,
                        ReplicationFailure {
                            object_key: object_key.to_string(),
                            error_message: msg,
                            timestamp: now_secs(),
                            failure_count: 1,
                            bucket_name: bucket.to_string(),
                            action: "delete".to_string(),
                            last_error_code: None,
                        },
                    );
                }
            }
            return;
        }

        let src_path = match self.storage.get_object_path(bucket, object_key).await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("Source object not found: {}/{}", bucket, object_key);
                return;
            }
        };
        let file_size = match tokio::fs::metadata(&src_path).await {
            Ok(m) => m.len(),
            Err(_) => 0,
        };
        let content_type = mime_guess::from_path(&src_path)
            .first_raw()
            .map(|s| s.to_string());

        let upload_result = upload_object(
            &client,
            &rule.target_bucket,
            object_key,
            &src_path,
            file_size,
            self.streaming_threshold_bytes,
            content_type.as_deref(),
        )
        .await;

        let final_result = match upload_result {
            Err(err) if is_no_such_bucket(&err) => {
                tracing::info!(
                    "Target bucket {} not found, creating it",
                    rule.target_bucket
                );
                match client
                    .create_bucket()
                    .bucket(&rule.target_bucket)
                    .send()
                    .await
                {
                    Ok(_) | Err(_) => {
                        upload_object(
                            &client,
                            &rule.target_bucket,
                            object_key,
                            &src_path,
                            file_size,
                            self.streaming_threshold_bytes,
                            content_type.as_deref(),
                        )
                        .await
                    }
                }
            }
            other => other,
        };

        match final_result {
            Ok(()) => {
                tracing::info!(
                    "Replicated {}/{} to {} ({})",
                    bucket,
                    object_key,
                    conn.name,
                    rule.target_bucket
                );
                self.update_last_sync(bucket, object_key);
                self.failures.remove(bucket, object_key);
            }
            Err(err) => {
                let msg = err.to_string();
                tracing::error!("Replication failed {}/{}: {}", bucket, object_key, msg);
                self.failures.add(
                    bucket,
                    ReplicationFailure {
                        object_key: object_key.to_string(),
                        error_message: msg,
                        timestamp: now_secs(),
                        failure_count: 1,
                        bucket_name: bucket.to_string(),
                        action: action.to_string(),
                        last_error_code: None,
                    },
                );
            }
        }
    }

    pub async fn check_endpoint(&self, conn: &RemoteConnection) -> bool {
        let client = build_client(conn, &self.client_options);
        check_endpoint_health(&client).await
    }

    pub async fn retry_failed(&self, bucket: &str, object_key: &str) -> bool {
        let failure = match self.failures.get(bucket, object_key) {
            Some(f) => f,
            None => return false,
        };
        let rule = match self.get_rule(bucket) {
            Some(r) if r.enabled => r,
            _ => return false,
        };
        let conn = match self.connections.get(&rule.target_connection_id) {
            Some(c) => c,
            None => return false,
        };
        self.replicate_task(bucket, object_key, &rule, &conn, &failure.action)
            .await;
        true
    }

    pub async fn retry_all(&self, bucket: &str) -> (usize, usize) {
        let failures = self.failures.load(bucket);
        if failures.is_empty() {
            return (0, 0);
        }
        let rule = match self.get_rule(bucket) {
            Some(r) if r.enabled => r,
            _ => return (0, failures.len()),
        };
        let conn = match self.connections.get(&rule.target_connection_id) {
            Some(c) => c,
            None => return (0, failures.len()),
        };
        let mut submitted = 0;
        for failure in failures {
            self.replicate_task(bucket, &failure.object_key, &rule, &conn, &failure.action)
                .await;
            submitted += 1;
        }
        (submitted, 0)
    }

    pub fn get_failure_count(&self, bucket: &str) -> usize {
        self.failures.count(bucket)
    }

    pub fn get_failed_items(
        &self,
        bucket: &str,
        limit: usize,
        offset: usize,
    ) -> Vec<ReplicationFailure> {
        self.failures
            .load(bucket)
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect()
    }

    pub fn dismiss_failure(&self, bucket: &str, key: &str) -> bool {
        self.failures.remove(bucket, key)
    }

    pub fn clear_failures(&self, bucket: &str) {
        self.failures.clear(bucket);
    }

    pub fn rules_snapshot(&self) -> HashMap<String, ReplicationRule> {
        self.rules.lock().clone()
    }

    pub fn update_last_pull(&self, bucket: &str, at: f64) {
        {
            let mut guard = self.rules.lock();
            if let Some(rule) = guard.get_mut(bucket) {
                rule.last_pull_at = Some(at);
            }
        }
        self.save_rules();
    }

    pub fn client_options(&self) -> &ClientOptions {
        &self.client_options
    }
}

fn is_no_such_bucket<E: std::fmt::Debug>(err: &E) -> bool {
    let text = format!("{:?}", err);
    text.contains("NoSuchBucket")
}

async fn upload_object(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    path: &Path,
    file_size: u64,
    streaming_threshold: u64,
    content_type: Option<&str>,
) -> Result<(), aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>> {
    let mut req = client.put_object().bucket(bucket).key(key);
    if let Some(ct) = content_type {
        req = req.content_type(ct);
    }

    let body = if file_size >= streaming_threshold {
        ByteStream::from_path(path).await.map_err(|e| {
            aws_sdk_s3::error::SdkError::construction_failure(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                e,
            )))
        })?
    } else {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| aws_sdk_s3::error::SdkError::construction_failure(Box::new(e)))?;
        ByteStream::from(bytes)
    };

    req.body(body).send().await.map(|_| ())
}

fn load_rules(path: &Path) -> HashMap<String, ReplicationRule> {
    if !path.exists() {
        return HashMap::new();
    }
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
