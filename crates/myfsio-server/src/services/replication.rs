use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use crate::services::site_registry::SiteRegistry;
use crate::stores::connections::{ConnectionStore, RemoteConnection};

pub const MODE_NEW_ONLY: &str = "new_only";
pub const MODE_ALL: &str = "all";
pub const MODE_BIDIRECTIONAL: &str = "bidirectional";

pub fn rule_requires_inbound_ak(mode: &str) -> bool {
    mode == MODE_BIDIRECTIONAL
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchRunKind {
    ResumeAll,
    RetryAll,
}

impl BatchRunKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BatchRunKind::ResumeAll => "resume_all",
            BatchRunKind::RetryAll => "retry_all",
        }
    }
}

pub struct BatchRun {
    pub run_id: String,
    pub bucket: String,
    pub kind: BatchRunKind,
    pub started_at: f64,
    pub enumeration_done: AtomicBool,
    pub total_queued: AtomicUsize,
    pub completed: AtomicUsize,
    pub failed: AtomicUsize,
    pub in_flight: AtomicUsize,
    pub last_object: Mutex<Option<String>>,
    pub finished_at: Mutex<Option<f64>>,
}

impl BatchRun {
    fn new(bucket: String, kind: BatchRunKind) -> Self {
        Self {
            run_id: uuid::Uuid::new_v4().to_string(),
            bucket,
            kind,
            started_at: now_secs(),
            enumeration_done: AtomicBool::new(false),
            total_queued: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            failed: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            last_object: Mutex::new(None),
            finished_at: Mutex::new(None),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.enumeration_done.load(Ordering::Acquire)
            && self.in_flight.load(Ordering::Acquire) == 0
            && self.completed.load(Ordering::Acquire) + self.failed.load(Ordering::Acquire)
                >= self.total_queued.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone)]
pub struct RetryAllResult {
    pub run_id: Option<String>,
    pub submitted: usize,
    pub skipped: usize,
    pub conflict: Option<BatchRunKind>,
}

#[derive(Debug, Clone)]
pub enum ScheduleRunOutcome {
    Started {
        run_id: String,
    },
    AlreadyRunning {
        run_id: String,
    },
    Conflict {
        existing_run_id: String,
        existing_kind: BatchRunKind,
    },
}

enum InternalStartRun {
    Started(Arc<BatchRun>),
    AlreadyRunning(String),
    Conflict {
        existing_run_id: String,
        existing_kind: BatchRunKind,
    },
}

#[derive(Debug, Clone)]
pub struct HealerStatus {
    pub running: bool,
    pub last_pass_at: Option<f64>,
    pub last_pass_healed: usize,
    pub last_pass_skipped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplicateOutcome {
    Succeeded,
    Skipped,
    Failed,
}

type StatusLocksMap = Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;

struct StatusLockHandle {
    map: StatusLocksMap,
    key: String,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl Drop for StatusLockHandle {
    fn drop(&mut self) {
        let mut guard = self.map.lock();
        if let Some(existing) = guard.get(&self.key) {
            if Arc::ptr_eq(existing, &self.lock) && Arc::strong_count(&self.lock) <= 2 {
                guard.remove(&self.key);
            }
        }
    }
}

pub struct ReplicationManager {
    storage: Arc<FsStorageBackend>,
    connections: Arc<ConnectionStore>,
    site_registry: Option<Arc<SiteRegistry>>,
    rules_path: PathBuf,
    rules: Mutex<HashMap<String, ReplicationRule>>,
    client_options: ClientOptions,
    streaming_threshold_bytes: u64,
    pub failures: Arc<ReplicationFailureStore>,
    semaphore: Arc<Semaphore>,
    allow_internal_endpoints: bool,
    http_client: aws_smithy_runtime_api::client::http::SharedHttpClient,
    status_locks_handle: StatusLocksMap,
    active_runs: Arc<Mutex<HashMap<String, Arc<BatchRun>>>>,
    last_runs: Arc<Mutex<HashMap<String, Arc<BatchRun>>>>,
    live_in_flight: Arc<AtomicUsize>,
    live_replicated_total: Arc<AtomicU64>,
    live_failed_total: Arc<AtomicU64>,
    healer_running: Arc<AtomicBool>,
    healer_last_pass_at: Arc<Mutex<Option<f64>>>,
    healer_last_pass_healed: Arc<AtomicUsize>,
    healer_last_pass_skipped: Arc<AtomicUsize>,
}

impl ReplicationManager {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        connections: Arc<ConnectionStore>,
        site_registry: Option<Arc<SiteRegistry>>,
        storage_root: &Path,
        connect_timeout: Duration,
        read_timeout: Duration,
        max_retries: u32,
        streaming_threshold_bytes: u64,
        max_failures_per_bucket: usize,
        allow_internal_endpoints: bool,
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
        let http_client = crate::services::safe_http_client::build(allow_internal_endpoints);
        Self {
            storage,
            connections,
            site_registry,
            rules_path,
            rules: Mutex::new(rules),
            client_options,
            streaming_threshold_bytes,
            failures,
            semaphore: Arc::new(Semaphore::new(4)),
            allow_internal_endpoints,
            http_client,
            status_locks_handle: Arc::new(Mutex::new(HashMap::new())),
            active_runs: Arc::new(Mutex::new(HashMap::new())),
            last_runs: Arc::new(Mutex::new(HashMap::new())),
            live_in_flight: Arc::new(AtomicUsize::new(0)),
            live_replicated_total: Arc::new(AtomicU64::new(0)),
            live_failed_total: Arc::new(AtomicU64::new(0)),
            healer_running: Arc::new(AtomicBool::new(false)),
            healer_last_pass_at: Arc::new(Mutex::new(None)),
            healer_last_pass_healed: Arc::new(AtomicUsize::new(0)),
            healer_last_pass_skipped: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn site_registry(&self) -> Option<Arc<SiteRegistry>> {
        self.site_registry.clone()
    }

    pub(crate) async fn endpoint_allowed(&self, endpoint: &str) -> Result<(), String> {
        if self.allow_internal_endpoints {
            return Ok(());
        }
        crate::handlers::ui_api::guard_external_endpoint_async(endpoint).await
    }

    pub(crate) fn http_client(&self) -> aws_smithy_runtime_api::client::http::SharedHttpClient {
        self.http_client.clone()
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

    fn status_lock_for(&self, lock_key: &str) -> StatusLockHandle {
        let lock = {
            let mut guard = self.status_locks_handle.lock();
            guard
                .entry(lock_key.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        StatusLockHandle {
            map: self.status_locks_handle.clone(),
            key: lock_key.to_string(),
            lock,
        }
    }

    async fn set_replication_status(&self, bucket: &str, key: &str, status: &str) {
        let lock_key = format!("{}/{}", bucket, key);
        let handle = self.status_lock_for(&lock_key);
        let _guard = handle.lock.lock().await;
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
        let live_in_flight = self.live_in_flight.clone();
        let live_replicated_total = self.live_replicated_total.clone();
        let live_failed_total = self.live_failed_total.clone();
        live_in_flight.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = manager
                .replicate_task(&bucket, &key, &rule, &connection, &action)
                .await;
            live_in_flight.fetch_sub(1, Ordering::Relaxed);
            match outcome {
                ReplicateOutcome::Succeeded | ReplicateOutcome::Skipped => {
                    live_replicated_total.fetch_add(1, Ordering::Relaxed);
                }
                ReplicateOutcome::Failed => {
                    live_failed_total.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    async fn enqueue_for_run(
        self: Arc<Self>,
        run: Arc<BatchRun>,
        key: String,
        action: String,
        rule: ReplicationRule,
        connection: RemoteConnection,
    ) {
        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                let sem = self.semaphore.clone();
                match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        run.failed.fetch_add(1, Ordering::Relaxed);
                        self.maybe_finalize_run(&run);
                        return;
                    }
                }
            }
        };
        let manager = self.clone();
        let live_in_flight = self.live_in_flight.clone();
        let live_replicated_total = self.live_replicated_total.clone();
        let live_failed_total = self.live_failed_total.clone();
        let manager_for_finalize = self.clone();
        let run_for_task = run.clone();
        live_in_flight.fetch_add(1, Ordering::Relaxed);
        run_for_task.in_flight.fetch_add(1, Ordering::Relaxed);
        let bucket = run_for_task.bucket.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = manager
                .replicate_task(&bucket, &key, &rule, &connection, &action)
                .await;
            {
                let mut last = run_for_task.last_object.lock();
                *last = Some(key.clone());
            }
            run_for_task.in_flight.fetch_sub(1, Ordering::Relaxed);
            live_in_flight.fetch_sub(1, Ordering::Relaxed);
            match outcome {
                ReplicateOutcome::Succeeded | ReplicateOutcome::Skipped => {
                    run_for_task.completed.fetch_add(1, Ordering::Relaxed);
                    live_replicated_total.fetch_add(1, Ordering::Relaxed);
                }
                ReplicateOutcome::Failed => {
                    run_for_task.failed.fetch_add(1, Ordering::Relaxed);
                    live_failed_total.fetch_add(1, Ordering::Relaxed);
                }
            }
            manager_for_finalize.maybe_finalize_run(&run_for_task);
        });
    }

    fn maybe_finalize_run(&self, run: &Arc<BatchRun>) {
        if !run.is_finished() {
            return;
        }
        {
            let mut finished_at = run.finished_at.lock();
            if finished_at.is_some() {
                return;
            }
            *finished_at = Some(now_secs());
        }
        let bucket = run.bucket.clone();
        let removed = {
            let mut active = self.active_runs.lock();
            active.remove(&bucket)
        };
        if let Some(removed_run) = removed {
            self.last_runs.lock().insert(bucket, removed_run);
        }
    }

    async fn replicate_existing_objects_with_run(
        self: Arc<Self>,
        bucket: String,
        run: Arc<BatchRun>,
    ) -> usize {
        let rule = match self.get_rule(&bucket) {
            Some(r) if r.enabled => r,
            _ => {
                run.enumeration_done.store(true, Ordering::Release);
                self.maybe_finalize_run(&run);
                return 0;
            }
        };
        let connection = match self.connections.get(&rule.target_connection_id) {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "Cannot replicate existing objects for {}: connection {} not found",
                    bucket,
                    rule.target_connection_id
                );
                run.enumeration_done.store(true, Ordering::Release);
                self.maybe_finalize_run(&run);
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
            run.enumeration_done.store(true, Ordering::Release);
            self.maybe_finalize_run(&run);
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

            run.total_queued
                .fetch_add(page.objects.len(), Ordering::Relaxed);
            for object in page.objects {
                submitted += 1;
                self.clone()
                    .enqueue_for_run(
                        run.clone(),
                        object.key,
                        "write".to_string(),
                        rule.clone(),
                        connection.clone(),
                    )
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

        run.enumeration_done.store(true, Ordering::Release);
        self.maybe_finalize_run(&run);
        submitted
    }

    fn try_start_run(&self, bucket: &str, kind: BatchRunKind) -> InternalStartRun {
        let mut active = self.active_runs.lock();
        if let Some(existing) = active.get(bucket) {
            if existing.kind == kind {
                return InternalStartRun::AlreadyRunning(existing.run_id.clone());
            }
            return InternalStartRun::Conflict {
                existing_run_id: existing.run_id.clone(),
                existing_kind: existing.kind,
            };
        }
        let run = Arc::new(BatchRun::new(bucket.to_string(), kind));
        active.insert(bucket.to_string(), run.clone());
        InternalStartRun::Started(run)
    }

    pub fn schedule_existing_objects_sync(self: Arc<Self>, bucket: String) -> ScheduleRunOutcome {
        let run = match self.try_start_run(&bucket, BatchRunKind::ResumeAll) {
            InternalStartRun::Started(run) => run,
            InternalStartRun::AlreadyRunning(run_id) => {
                return ScheduleRunOutcome::AlreadyRunning { run_id };
            }
            InternalStartRun::Conflict {
                existing_run_id,
                existing_kind,
            } => {
                return ScheduleRunOutcome::Conflict {
                    existing_run_id,
                    existing_kind,
                };
            }
        };
        let run_id = run.run_id.clone();
        let manager = self.clone();
        tokio::spawn(async move {
            let submitted = manager
                .replicate_existing_objects_with_run(bucket.clone(), run)
                .await;
            if submitted > 0 {
                tracing::info!(
                    "Scheduled {} existing object(s) for replication in {}",
                    submitted,
                    bucket
                );
            }
        });
        ScheduleRunOutcome::Started { run_id }
    }

    async fn replicate_task(
        &self,
        bucket: &str,
        object_key: &str,
        rule: &ReplicationRule,
        conn: &RemoteConnection,
        action: &str,
    ) -> ReplicateOutcome {
        if object_key.starts_with('/') || object_key.starts_with('\\') {
            tracing::error!("Invalid object key (path traversal): {}", object_key);
            return ReplicateOutcome::Failed;
        }

        if rule_requires_inbound_ak(&rule.mode) {
            if let Some(registry) = self.site_registry.as_ref() {
                if let Some(peer) =
                    registry.find_peer_by_connection_id(&rule.target_connection_id)
                {
                    let ak_set = peer
                        .peer_inbound_access_key
                        .as_deref()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false);
                    if !ak_set {
                        tracing::error!(
                            "Replication BLOCKED for {}/{}: bidirectional rule targets peer site '{}' but its peer_inbound_access_key is not configured. Refusing to push to avoid replication loop. Set the peer's inbound access key on /ui/sites before this rule can sync.",
                            bucket,
                            object_key,
                            peer.site_id
                        );
                        self.failures.add(
                            bucket,
                            ReplicationFailure {
                                object_key: object_key.to_string(),
                                error_message: format!(
                                    "bidirectional rule blocked: peer '{}' has no peer_inbound_access_key configured (would cause replication loop)",
                                    peer.site_id
                                ),
                                timestamp: now_secs(),
                                failure_count: 1,
                                bucket_name: bucket.to_string(),
                                action: action.to_string(),
                                last_error_code: Some("BidirectionalLoopGuard".to_string()),
                            },
                        );
                        self.set_replication_status(bucket, object_key, REPLICATION_STATUS_FAILED)
                            .await;
                        return ReplicateOutcome::Failed;
                    }
                }
            }
        }

        if let Err(reason) = self.endpoint_allowed(&conn.endpoint_url).await {
            tracing::warn!(
                "Replication blocked for {}/{}: connection '{}' endpoint rejected ({}). Set ALLOW_INTERNAL_ENDPOINTS=true to allow.",
                bucket,
                object_key,
                conn.name,
                reason
            );
            self.failures.add(
                bucket,
                ReplicationFailure {
                    object_key: object_key.to_string(),
                    error_message: format!("endpoint rejected: {}", reason),
                    timestamp: now_secs(),
                    failure_count: 1,
                    bucket_name: bucket.to_string(),
                    action: action.to_string(),
                    last_error_code: Some("InternalEndpointBlocked".to_string()),
                },
            );
            self.set_replication_status(bucket, object_key, REPLICATION_STATUS_FAILED)
                .await;
            return ReplicateOutcome::Failed;
        }

        let client = build_client(conn, &self.client_options, self.http_client.clone());

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
                    return ReplicateOutcome::Succeeded;
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
                    return ReplicateOutcome::Failed;
                }
            }
        }

        if let Ok(src_meta) = self.storage.get_object_metadata(bucket, object_key).await {
            if metadata_is_corrupted(&src_meta) {
                tracing::warn!(
                    "Replication skipped for {}/{}: source object is poisoned (corrupted)",
                    bucket,
                    object_key
                );
                return ReplicateOutcome::Skipped;
            }
        }

        let src_path = match self.storage.get_object_path(bucket, object_key).await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("Source object not found: {}/{}", bucket, object_key);
                return ReplicateOutcome::Failed;
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

        if action != "delete" {
            if let Some(local_etag) = stored_meta
                .get("__etag__")
                .map(|s| s.trim_matches('"').to_string())
                .filter(|s| !s.is_empty() && !s.contains('-'))
            {
                if let Ok(head) = client
                    .head_object()
                    .bucket(&rule.target_bucket)
                    .key(object_key)
                    .send()
                    .await
                {
                    let target_size = head.content_length().unwrap_or(-1);
                    let target_etag = head
                        .e_tag()
                        .map(|s| s.trim_matches('"').to_string())
                        .unwrap_or_default();
                    if target_size as u64 == file_size
                        && !target_etag.is_empty()
                        && !target_etag.contains('-')
                        && target_etag.eq_ignore_ascii_case(&local_etag)
                    {
                        tracing::debug!(
                            "Replication skipped {}/{} to {} ({}): target already up-to-date (etag match)",
                            bucket,
                            object_key,
                            conn.name,
                            rule.target_bucket
                        );
                        self.update_last_sync(bucket, object_key);
                        self.failures.remove(bucket, object_key);
                        self.set_replication_status(
                            bucket,
                            object_key,
                            REPLICATION_STATUS_COMPLETED,
                        )
                        .await;
                        return ReplicateOutcome::Skipped;
                    }
                }
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
                ReplicateOutcome::Succeeded
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
                ReplicateOutcome::Failed
            }
        }
    }

    pub async fn check_endpoint(&self, conn: &RemoteConnection) -> bool {
        if let Err(reason) = self.endpoint_allowed(&conn.endpoint_url).await {
            tracing::warn!(
                "Endpoint health check blocked for connection '{}': {}",
                conn.name,
                reason
            );
            return false;
        }
        let client = build_health_client(conn, &self.client_options, self.http_client.clone());
        check_endpoint_health(&client).await
    }

    pub async fn check_target_bucket(&self, conn: &RemoteConnection, target_bucket: &str) -> bool {
        if let Err(reason) = self.endpoint_allowed(&conn.endpoint_url).await {
            tracing::warn!(
                "Target-bucket reachability check blocked for connection '{}': {}",
                conn.name,
                reason
            );
            return false;
        }
        let client = build_client(conn, &self.client_options, self.http_client.clone());
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

    pub async fn retry_all(self: Arc<Self>, bucket: &str) -> RetryAllResult {
        let failures = self.failures.load(bucket);
        if failures.is_empty() {
            return RetryAllResult {
                run_id: None,
                submitted: 0,
                skipped: 0,
                conflict: None,
            };
        }
        let rule = match self.get_rule(bucket) {
            Some(r) if r.enabled => r,
            _ => {
                return RetryAllResult {
                    run_id: None,
                    submitted: 0,
                    skipped: failures.len(),
                    conflict: None,
                }
            }
        };
        let conn = match self.connections.get(&rule.target_connection_id) {
            Some(c) => c,
            None => {
                return RetryAllResult {
                    run_id: None,
                    submitted: 0,
                    skipped: failures.len(),
                    conflict: None,
                }
            }
        };
        if !self.check_target_bucket(&conn, &rule.target_bucket).await {
            tracing::warn!(
                "Cannot retry {} failure(s) in {}: endpoint {} is not reachable",
                failures.len(),
                bucket,
                conn.endpoint_url
            );
            return RetryAllResult {
                run_id: None,
                submitted: 0,
                skipped: failures.len(),
                conflict: None,
            };
        }

        let run = match self.try_start_run(bucket, BatchRunKind::RetryAll) {
            InternalStartRun::Started(run) => run,
            InternalStartRun::AlreadyRunning(run_id) => {
                return RetryAllResult {
                    run_id: Some(run_id),
                    submitted: 0,
                    skipped: failures.len(),
                    conflict: None,
                };
            }
            InternalStartRun::Conflict {
                existing_run_id,
                existing_kind,
            } => {
                return RetryAllResult {
                    run_id: Some(existing_run_id),
                    submitted: 0,
                    skipped: failures.len(),
                    conflict: Some(existing_kind),
                };
            }
        };
        let run_id = run.run_id.clone();
        let total = failures.len();
        run.total_queued.store(total, Ordering::Relaxed);

        let mut submitted = 0usize;
        for failure in failures {
            self.clone()
                .enqueue_for_run(
                    run.clone(),
                    failure.object_key,
                    failure.action,
                    rule.clone(),
                    conn.clone(),
                )
                .await;
            submitted += 1;
        }
        run.enumeration_done.store(true, Ordering::Release);
        self.maybe_finalize_run(&run);

        RetryAllResult {
            run_id: Some(run_id),
            submitted,
            skipped: 0,
            conflict: None,
        }
    }

    pub fn get_failure_count(&self, bucket: &str) -> usize {
        self.failures.count(bucket)
    }

    pub fn current_run(&self, bucket: &str) -> Option<Arc<BatchRun>> {
        self.active_runs.lock().get(bucket).cloned()
    }

    pub fn last_run(&self, bucket: &str) -> Option<Arc<BatchRun>> {
        self.last_runs.lock().get(bucket).cloned()
    }

    pub fn live_in_flight(&self) -> usize {
        self.live_in_flight.load(Ordering::Relaxed)
    }

    pub fn live_replicated_total(&self) -> u64 {
        self.live_replicated_total.load(Ordering::Relaxed)
    }

    pub fn live_failed_total(&self) -> u64 {
        self.live_failed_total.load(Ordering::Relaxed)
    }

    pub fn healer_status(&self) -> HealerStatus {
        HealerStatus {
            running: self.healer_running.load(Ordering::Relaxed),
            last_pass_at: *self.healer_last_pass_at.lock(),
            last_pass_healed: self.healer_last_pass_healed.load(Ordering::Relaxed),
            last_pass_skipped: self.healer_last_pass_skipped.load(Ordering::Relaxed),
        }
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
        self.healer_running.store(true, Ordering::Release);
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
                if f.failure_count >= max_attempts {
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
        self.healer_last_pass_healed.store(healed, Ordering::Relaxed);
        self.healer_last_pass_skipped
            .store(skipped, Ordering::Relaxed);
        *self.healer_last_pass_at.lock() = Some(now_secs());
        self.healer_running.store(false, Ordering::Release);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_run_atomics_are_consistent_under_parallel_increments() {
        let run = Arc::new(BatchRun::new(
            "test-bucket".to_string(),
            BatchRunKind::ResumeAll,
        ));
        run.total_queued.store(100, Ordering::Relaxed);

        let mut handles = Vec::new();
        for i in 0..100 {
            let run = run.clone();
            handles.push(std::thread::spawn(move || {
                run.in_flight.fetch_add(1, Ordering::Relaxed);
                if i % 7 == 0 {
                    run.failed.fetch_add(1, Ordering::Relaxed);
                } else {
                    run.completed.fetch_add(1, Ordering::Relaxed);
                }
                run.in_flight.fetch_sub(1, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        run.enumeration_done.store(true, Ordering::Release);

        let completed = run.completed.load(Ordering::Acquire);
        let failed = run.failed.load(Ordering::Acquire);
        let in_flight = run.in_flight.load(Ordering::Acquire);
        let total = run.total_queued.load(Ordering::Acquire);

        assert_eq!(completed + failed, 100);
        assert_eq!(total, 100);
        assert_eq!(in_flight, 0);
        assert!(run.is_finished());
    }

    #[test]
    fn batch_run_not_finished_while_in_flight() {
        let run = BatchRun::new("b".to_string(), BatchRunKind::RetryAll);
        run.total_queued.store(5, Ordering::Relaxed);
        run.completed.store(2, Ordering::Relaxed);
        run.in_flight.store(1, Ordering::Relaxed);
        run.enumeration_done.store(true, Ordering::Release);
        assert!(!run.is_finished());

        run.in_flight.store(0, Ordering::Relaxed);
        run.failed.store(3, Ordering::Relaxed);
        assert!(run.is_finished());
    }

    #[test]
    fn batch_run_not_finished_until_enumeration_done() {
        let run = BatchRun::new("b".to_string(), BatchRunKind::ResumeAll);
        run.total_queued.store(0, Ordering::Relaxed);
        run.completed.store(0, Ordering::Relaxed);
        run.in_flight.store(0, Ordering::Relaxed);
        assert!(!run.is_finished());
        run.enumeration_done.store(true, Ordering::Release);
        assert!(run.is_finished());
    }

    #[test]
    fn batch_run_kind_string_repr() {
        assert_eq!(BatchRunKind::ResumeAll.as_str(), "resume_all");
        assert_eq!(BatchRunKind::RetryAll.as_str(), "retry_all");
    }

    #[test]
    fn try_start_run_same_kind_returns_already_running() {
        let manager = build_test_manager();
        let first = match manager.try_start_run("b", BatchRunKind::ResumeAll) {
            InternalStartRun::Started(run) => run.run_id.clone(),
            other => panic!("expected Started, got {:?}", debug_internal(&other)),
        };
        match manager.try_start_run("b", BatchRunKind::ResumeAll) {
            InternalStartRun::AlreadyRunning(rid) => assert_eq!(rid, first),
            other => panic!(
                "expected AlreadyRunning for same-kind, got {:?}",
                debug_internal(&other)
            ),
        }
    }

    #[test]
    fn try_start_run_different_kind_returns_conflict() {
        let manager = build_test_manager();
        let first_id = match manager.try_start_run("b", BatchRunKind::RetryAll) {
            InternalStartRun::Started(run) => run.run_id.clone(),
            other => panic!("expected Started, got {:?}", debug_internal(&other)),
        };
        match manager.try_start_run("b", BatchRunKind::ResumeAll) {
            InternalStartRun::Conflict {
                existing_run_id,
                existing_kind,
            } => {
                assert_eq!(existing_run_id, first_id);
                assert_eq!(existing_kind, BatchRunKind::RetryAll);
            }
            other => panic!(
                "expected Conflict for different-kind, got {:?}",
                debug_internal(&other)
            ),
        }
    }

    fn build_test_manager() -> ReplicationManager {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        let connections = Arc::new(ConnectionStore::new(tmp.path()));
        let manager = ReplicationManager::new(
            storage,
            connections,
            None,
            tmp.path(),
            Duration::from_secs(5),
            Duration::from_secs(60),
            2,
            10 * 1024 * 1024,
            5000,
            true,
        );
        std::mem::forget(tmp);
        manager
    }

    fn debug_internal(s: &InternalStartRun) -> &'static str {
        match s {
            InternalStartRun::Started(_) => "Started",
            InternalStartRun::AlreadyRunning(_) => "AlreadyRunning",
            InternalStartRun::Conflict { .. } => "Conflict",
        }
    }
}
