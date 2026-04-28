use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use aws_smithy_types::byte_stream::Length;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use myfsio_common::types::ListParams;
use myfsio_storage::fs_backend::{metadata_is_corrupted, FsStorageBackend};
use myfsio_storage::traits::StorageEngine;

use crate::services::s3_client::{
    build_client, build_health_client, check_endpoint_health, check_target_bucket_reachable,
    ClientOptions,
};
use crate::stores::connections::{ConnectionStore, RemoteConnection};

pub const MODE_NEW_ONLY: &str = "new_only";
pub const MODE_ALL: &str = "all";
pub const MODE_BIDIRECTIONAL: &str = "bidirectional";

pub const REPLICATION_STATUS_KEY: &str = "__replication_status__";
pub const REPLICATION_STATUS_AT_KEY: &str = "__replication_status_at__";
pub const REPLICATION_STATUS_PENDING: &str = "PENDING";
pub const REPLICATION_STATUS_COMPLETED: &str = "COMPLETED";
pub const REPLICATION_STATUS_FAILED: &str = "FAILED";

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

    async fn set_replication_status(&self, bucket: &str, key: &str, status: &str) {
        let mut meta = match self.storage.get_object_metadata(bucket, key).await {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.get(REPLICATION_STATUS_KEY).map(|s| s.as_str()) == Some(status) {
            return;
        }
        meta.insert(REPLICATION_STATUS_KEY.to_string(), status.to_string());
        meta.insert(
            REPLICATION_STATUS_AT_KEY.to_string(),
            format!("{:.3}", now_secs()),
        );
        if let Err(e) = self.storage.put_object_metadata(bucket, key, &meta).await {
            tracing::debug!(
                "Failed to record replication status for {}/{}: {}",
                bucket,
                key,
                e
            );
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
        if !self
            .check_target_bucket(&connection, &rule.target_bucket)
            .await
        {
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
                    let code = sdk_error_code(&err);
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
                            last_error_code: code,
                        },
                    );
                }
            }
            return;
        }

        if let Ok(src_meta) = self.storage.get_object_metadata(bucket, object_key).await {
            if metadata_is_corrupted(&src_meta) {
                tracing::warn!(
                    "Replication skipped for {}/{}: source object is poisoned (corrupted)",
                    bucket,
                    object_key
                );
                return;
            }
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
        let stored_meta = self
            .storage
            .get_object_metadata(bucket, object_key)
            .await
            .unwrap_or_default();
        let mut obj_meta = ReplicationObjectMeta::from_internal_metadata(&stored_meta);
        if obj_meta.content_type.is_none() {
            obj_meta.content_type = mime_guess::from_path(&src_path)
                .first_raw()
                .map(|s| s.to_string());
        }
        if let Ok(tags) = self.storage.get_object_tags(bucket, object_key).await {
            if !tags.is_empty() {
                obj_meta.tagging_header = Some(
                    tags.iter()
                        .map(|t| {
                            format!(
                                "{}={}",
                                percent_encoding::utf8_percent_encode(
                                    &t.key,
                                    percent_encoding::NON_ALPHANUMERIC,
                                ),
                                percent_encoding::utf8_percent_encode(
                                    &t.value,
                                    percent_encoding::NON_ALPHANUMERIC,
                                ),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("&"),
                );
            }
        }

        self.set_replication_status(bucket, object_key, REPLICATION_STATUS_PENDING)
            .await;

        let upload_result = upload_object(
            &client,
            &rule.target_bucket,
            object_key,
            &src_path,
            file_size,
            self.streaming_threshold_bytes,
            Some(&obj_meta),
        )
        .await;

        let final_result = match upload_result {
            Err(err) if err.is_no_such_bucket => {
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
                            Some(&obj_meta),
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
                self.set_replication_status(bucket, object_key, REPLICATION_STATUS_COMPLETED)
                    .await;
            }
            Err(err) => {
                let code = err.code.clone();
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
                        last_error_code: code,
                    },
                );
                self.set_replication_status(bucket, object_key, REPLICATION_STATUS_FAILED)
                    .await;
            }
        }
    }

    pub async fn check_endpoint(&self, conn: &RemoteConnection) -> bool {
        let client = build_health_client(conn, &self.client_options);
        check_endpoint_health(&client).await
    }

    pub async fn check_target_bucket(&self, conn: &RemoteConnection, target_bucket: &str) -> bool {
        let client = build_client(conn, &self.client_options);
        check_target_bucket_reachable(&client, target_bucket).await
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
        if !self.check_target_bucket(&conn, &rule.target_bucket).await {
            tracing::warn!(
                "Cannot retry {}/{}: endpoint {} is not reachable",
                bucket,
                object_key,
                conn.endpoint_url
            );
            return false;
        }
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
        if !self.check_target_bucket(&conn, &rule.target_bucket).await {
            tracing::warn!(
                "Cannot retry {} failure(s) in {}: endpoint {} is not reachable",
                failures.len(),
                bucket,
                conn.endpoint_url
            );
            return (0, failures.len());
        }
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

    pub fn start_healer(self: Arc<Self>, interval: Duration, max_attempts: u32) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.heal_once(max_attempts).await;
            }
        });
    }

    async fn heal_once(&self, max_attempts: u32) {
        let buckets: Vec<String> = self
            .rules
            .lock()
            .iter()
            .filter(|(_, r)| r.enabled)
            .map(|(b, _)| b.clone())
            .collect();
        let now = now_secs();
        let mut healed = 0usize;
        let mut skipped = 0usize;
        for bucket in buckets {
            let rule = match self.get_rule(&bucket) {
                Some(r) if r.enabled => r,
                _ => continue,
            };
            let conn = match self.connections.get(&rule.target_connection_id) {
                Some(c) => c,
                None => continue,
            };
            let failures = self.failures.load(&bucket);
            if failures.is_empty() {
                continue;
            }
            for f in failures {
                if f.failure_count as u32 >= max_attempts {
                    skipped += 1;
                    continue;
                }
                let backoff_secs = healer_backoff_seconds(f.failure_count);
                if now - f.timestamp < backoff_secs as f64 {
                    skipped += 1;
                    continue;
                }
                self.replicate_task(&bucket, &f.object_key, &rule, &conn, &f.action)
                    .await;
                healed += 1;
            }
        }
        if healed > 0 || skipped > 0 {
            tracing::debug!(
                "Replication healer pass complete: attempted={} skipped={}",
                healed,
                skipped
            );
        }
    }
}

fn healer_backoff_seconds(failure_count: u32) -> u64 {
    let exp = failure_count.min(6);
    let secs: u64 = 60u64.saturating_mul(1u64 << exp);
    secs.min(3600)
}

#[derive(Debug, Clone)]
pub struct ReplicationUploadError {
    pub code: Option<String>,
    pub message: String,
    pub is_no_such_bucket: bool,
}

impl std::fmt::Display for ReplicationUploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn map_sdk_err<E, R>(err: aws_sdk_s3::error::SdkError<E, R>) -> ReplicationUploadError
where
    E: aws_sdk_s3::error::ProvideErrorMetadata + std::fmt::Debug,
    R: std::fmt::Debug,
{
    let dbg = format!("{:?}", err);
    let is_no_such_bucket = dbg.contains("NoSuchBucket");
    let code = if let aws_sdk_s3::error::SdkError::ServiceError(svc) = &err {
        svc.err().code().map(|c| c.to_string())
    } else {
        None
    };
    ReplicationUploadError {
        code,
        message: dbg,
        is_no_such_bucket,
    }
}

fn sdk_error_code<E, R>(err: &aws_sdk_s3::error::SdkError<E, R>) -> Option<String>
where
    E: aws_sdk_s3::error::ProvideErrorMetadata,
{
    if let aws_sdk_s3::error::SdkError::ServiceError(svc) = err {
        if let Some(code) = svc.err().code() {
            return Some(code.to_string());
        }
    }
    None
}

#[derive(Default, Clone)]
pub struct ReplicationObjectMeta {
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub content_disposition: Option<String>,
    pub content_language: Option<String>,
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub storage_class: Option<String>,
    pub website_redirect_location: Option<String>,
    pub user_metadata: HashMap<String, String>,
    pub tagging_header: Option<String>,
}

impl ReplicationObjectMeta {
    pub fn from_internal_metadata(meta: &HashMap<String, String>) -> Self {
        let mut user_metadata = HashMap::new();
        for (k, v) in meta {
            if k.starts_with("__") {
                continue;
            }
            if k.starts_with("x-amz-") {
                continue;
            }
            user_metadata.insert(k.clone(), v.clone());
        }
        Self {
            content_type: meta.get("__content_type__").cloned(),
            content_encoding: meta.get("__content_encoding__").cloned(),
            content_disposition: meta.get("__content_disposition__").cloned(),
            content_language: meta.get("__content_language__").cloned(),
            cache_control: meta.get("__cache_control__").cloned(),
            expires: meta.get("__expires__").cloned(),
            storage_class: meta.get("__storage_class__").cloned(),
            website_redirect_location: meta.get("__website_redirect_location__").cloned(),
            user_metadata,
            tagging_header: None,
        }
    }
}

const MULTIPART_MIN_PART_BYTES: u64 = 8 * 1024 * 1024;
const MULTIPART_MAX_PARTS: u64 = 10_000;
const MULTIPART_CONCURRENCY: usize = 4;

fn compute_part_size(file_size: u64) -> u64 {
    let target = file_size.div_ceil(MULTIPART_MAX_PARTS);
    target.max(MULTIPART_MIN_PART_BYTES)
}

async fn upload_object(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    path: &Path,
    file_size: u64,
    streaming_threshold: u64,
    obj_meta: Option<&ReplicationObjectMeta>,
) -> Result<(), ReplicationUploadError> {
    if file_size >= streaming_threshold && file_size > MULTIPART_MIN_PART_BYTES {
        upload_object_multipart(client, bucket, key, path, file_size, obj_meta).await
    } else {
        upload_object_single(client, bucket, key, path, file_size, streaming_threshold, obj_meta)
            .await
    }
}

async fn upload_object_single(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    path: &Path,
    file_size: u64,
    streaming_threshold: u64,
    obj_meta: Option<&ReplicationObjectMeta>,
) -> Result<(), ReplicationUploadError> {
    let mut req = client.put_object().bucket(bucket).key(key);
    if let Some(meta) = obj_meta {
        req = apply_meta_to_put_object(req, meta);
    }

    let body = if file_size >= streaming_threshold {
        ByteStream::from_path(path)
            .await
            .map_err(|e| ReplicationUploadError {
                code: None,
                message: format!("failed to open {} for upload: {}", path.display(), e),
                is_no_such_bucket: false,
            })?
    } else {
        let bytes = tokio::fs::read(path).await.map_err(|e| ReplicationUploadError {
            code: None,
            message: format!("failed to read {}: {}", path.display(), e),
            is_no_such_bucket: false,
        })?;
        ByteStream::from(bytes)
    };

    req.body(body).send().await.map(|_| ()).map_err(map_sdk_err)
}

async fn upload_object_multipart(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    path: &Path,
    file_size: u64,
    obj_meta: Option<&ReplicationObjectMeta>,
) -> Result<(), ReplicationUploadError> {
    let part_size = compute_part_size(file_size);
    let total_parts = file_size.div_ceil(part_size);
    if total_parts == 0 || total_parts > MULTIPART_MAX_PARTS {
        return Err(ReplicationUploadError {
            code: None,
            message: format!(
                "computed invalid part plan for {}: size={} parts={} part_size={}",
                key, file_size, total_parts, part_size
            ),
            is_no_such_bucket: false,
        });
    }

    let mut create_req = client.create_multipart_upload().bucket(bucket).key(key);
    if let Some(meta) = obj_meta {
        create_req = apply_meta_to_create_mpu(create_req, meta);
    }
    let create_resp = create_req.send().await.map_err(map_sdk_err)?;
    let upload_id = match create_resp.upload_id() {
        Some(s) => s.to_string(),
        None => {
            return Err(ReplicationUploadError {
                code: None,
                message: "CreateMultipartUpload returned no UploadId".to_string(),
                is_no_such_bucket: false,
            })
        }
    };

    let parts_result = run_part_uploads(
        client,
        bucket,
        key,
        &upload_id,
        path,
        file_size,
        part_size,
        total_parts as i32,
    )
    .await;

    let parts = match parts_result {
        Ok(p) => p,
        Err(e) => {
            let _ = client
                .abort_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(&upload_id)
                .send()
                .await;
            return Err(e);
        }
    };

    let completed = CompletedMultipartUpload::builder()
        .set_parts(Some(parts))
        .build();

    if let Err(e) = client
        .complete_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(&upload_id)
        .multipart_upload(completed)
        .send()
        .await
    {
        let mapped = map_sdk_err(e);
        let _ = client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(&upload_id)
            .send()
            .await;
        return Err(mapped);
    }

    Ok(())
}

const MULTIPART_PART_BUFFER_BYTES: usize = 64 * 1024;

async fn run_part_uploads(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    path: &Path,
    file_size: u64,
    part_size: u64,
    total_parts: i32,
) -> Result<Vec<CompletedPart>, ReplicationUploadError> {
    let mut tasks: JoinSet<Result<CompletedPart, ReplicationUploadError>> = JoinSet::new();
    let mut next_part: i32 = 1;
    let mut parts: Vec<CompletedPart> = Vec::with_capacity(total_parts as usize);

    loop {
        while tasks.len() < MULTIPART_CONCURRENCY && next_part <= total_parts {
            let part_number = next_part;
            let offset = (part_number as u64 - 1) * part_size;
            let length = std::cmp::min(part_size, file_size - offset);
            let client = client.clone();
            let bucket = bucket.to_string();
            let key = key.to_string();
            let upload_id = upload_id.to_string();
            let path = path.to_path_buf();
            tasks.spawn(async move {
                upload_one_part(
                    &client,
                    &bucket,
                    &key,
                    &upload_id,
                    &path,
                    offset,
                    length,
                    part_number,
                )
                .await
            });
            next_part += 1;
        }

        match tasks.join_next().await {
            Some(Ok(Ok(part))) => parts.push(part),
            Some(Ok(Err(e))) => {
                drain_join_set(&mut tasks).await;
                return Err(e);
            }
            Some(Err(join_err)) => {
                drain_join_set(&mut tasks).await;
                return Err(ReplicationUploadError {
                    code: None,
                    message: format!("part upload task panicked: {}", join_err),
                    is_no_such_bucket: false,
                });
            }
            None => break,
        }
    }

    parts.sort_by_key(|p| p.part_number().unwrap_or(0));
    Ok(parts)
}

async fn drain_join_set(tasks: &mut JoinSet<Result<CompletedPart, ReplicationUploadError>>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn upload_one_part(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    path: &Path,
    offset: u64,
    length: u64,
    part_number: i32,
) -> Result<CompletedPart, ReplicationUploadError> {
    let body = ByteStream::read_from()
        .path(path)
        .offset(offset)
        .length(Length::Exact(length))
        .buffer_size(MULTIPART_PART_BUFFER_BYTES)
        .build()
        .await
        .map_err(|e| ReplicationUploadError {
            code: None,
            message: format!(
                "failed to open part {} ({} bytes from offset {} of {}): {}",
                part_number,
                length,
                offset,
                path.display(),
                e
            ),
            is_no_such_bucket: false,
        })?;

    let resp = client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .part_number(part_number)
        .content_length(length as i64)
        .body(body)
        .send()
        .await
        .map_err(map_sdk_err)?;

    Ok(CompletedPart::builder()
        .part_number(part_number)
        .set_e_tag(resp.e_tag().map(|s| s.to_string()))
        .build())
}

fn apply_meta_to_put_object(
    mut req: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
    meta: &ReplicationObjectMeta,
) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
    if let Some(ref ct) = meta.content_type {
        req = req.content_type(ct);
    }
    if let Some(ref v) = meta.content_encoding {
        req = req.content_encoding(v);
    }
    if let Some(ref v) = meta.content_disposition {
        req = req.content_disposition(v);
    }
    if let Some(ref v) = meta.content_language {
        req = req.content_language(v);
    }
    if let Some(ref v) = meta.cache_control {
        req = req.cache_control(v);
    }
    if let Some(ref v) = meta.expires {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(v) {
            req = req.expires(aws_smithy_types::DateTime::from_secs(dt.timestamp()));
        } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
            req = req.expires(aws_smithy_types::DateTime::from_secs(dt.timestamp()));
        }
    }
    if let Some(ref v) = meta.storage_class {
        req = req.storage_class(aws_sdk_s3::types::StorageClass::from(v.as_str()));
    }
    if let Some(ref v) = meta.website_redirect_location {
        req = req.website_redirect_location(v);
    }
    if let Some(ref v) = meta.tagging_header {
        req = req.tagging(v);
    }
    for (k, v) in &meta.user_metadata {
        req = req.metadata(k, v);
    }
    req
}

fn apply_meta_to_create_mpu(
    mut req: aws_sdk_s3::operation::create_multipart_upload::builders::CreateMultipartUploadFluentBuilder,
    meta: &ReplicationObjectMeta,
) -> aws_sdk_s3::operation::create_multipart_upload::builders::CreateMultipartUploadFluentBuilder {
    if let Some(ref ct) = meta.content_type {
        req = req.content_type(ct);
    }
    if let Some(ref v) = meta.content_encoding {
        req = req.content_encoding(v);
    }
    if let Some(ref v) = meta.content_disposition {
        req = req.content_disposition(v);
    }
    if let Some(ref v) = meta.content_language {
        req = req.content_language(v);
    }
    if let Some(ref v) = meta.cache_control {
        req = req.cache_control(v);
    }
    if let Some(ref v) = meta.expires {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(v) {
            req = req.expires(aws_smithy_types::DateTime::from_secs(dt.timestamp()));
        } else if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(v) {
            req = req.expires(aws_smithy_types::DateTime::from_secs(dt.timestamp()));
        }
    }
    if let Some(ref v) = meta.storage_class {
        req = req.storage_class(aws_sdk_s3::types::StorageClass::from(v.as_str()));
    }
    if let Some(ref v) = meta.website_redirect_location {
        req = req.website_redirect_location(v);
    }
    if let Some(ref v) = meta.tagging_header {
        req = req.tagging(v);
    }
    for (k, v) in &meta.user_metadata {
        req = req.metadata(k, v);
    }
    req
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
