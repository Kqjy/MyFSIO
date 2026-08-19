use md5::{Digest, Md5};
use myfsio_common::constants::{
    BUCKET_META_DIR, BUCKET_VERSIONS_DIR, DIR_MARKER_FILE, INDEX_FILE, KEY_DATA_MARKER_FILE,
    SYSTEM_BUCKETS_DIR, SYSTEM_ROOT,
};
use myfsio_crypto::encryption::EncryptionMetadata;
use myfsio_storage::fs_backend::{
    is_multipart_etag, metadata_is_corrupted, FsStorageBackend, IntegrityQuarantineOutcome,
    META_KEY_CORRUPTED, META_KEY_CORRUPTION_DETAIL, META_KEY_CORRUPTION_LAST_RETRY_AT,
    META_KEY_CORRUPTION_RETRY_COUNT, META_KEY_PART_SIZES, SIDECAR_ENTRY_NAME_FIELD,
    SIDECAR_FILE_EXT, SIDECAR_FILE_PREFIX,
};
use myfsio_storage::traits::StorageEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Instant, UNIX_EPOCH};
use tokio::sync::{RwLock, Semaphore};

use crate::services::peer_fetch::{HealOutcome, PeerFetcher};

const MAX_ISSUES_PER_TYPE: usize = 100;
const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];
const QUARANTINE_DIR: &str = "quarantine";
const CURSOR_FILE: &str = "integrity_cursor.json";
const VERIFIED_INDEX_FILE: &str = "integrity_verified.json";
const STALE_VERSION_GRACE: std::time::Duration = std::time::Duration::from_secs(120);

struct Pacer {
    every: usize,
    pause: std::time::Duration,
    count: usize,
}

impl Pacer {
    fn new(pacing_ms: u64) -> Self {
        Self {
            every: 100,
            pause: std::time::Duration::from_millis(pacing_ms),
            count: 0,
        }
    }

    fn tick(&mut self) {
        if self.pause.is_zero() {
            return;
        }
        self.count += 1;
        if self.count.is_multiple_of(self.every) {
            std::thread::sleep(self.pause);
        }
    }
}

#[derive(Default, Clone)]
struct CorruptionCursor {
    bucket: String,
    after_key: String,
}

fn cursor_path_for(storage_root: &Path) -> PathBuf {
    storage_root
        .join(SYSTEM_ROOT)
        .join("config")
        .join(CURSOR_FILE)
}

fn load_cursor(path: &Path) -> Result<CorruptionCursor, String> {
    let s = match std::fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CorruptionCursor::default());
        }
        Err(error) => return Err(format!("read checksum cursor: {error}")),
    };
    let Value::Object(map) = serde_json::from_str::<Value>(&s)
        .map_err(|error| format!("parse checksum cursor: {error}"))?
    else {
        return Err("parse checksum cursor: expected a JSON object".to_string());
    };
    Ok(CorruptionCursor {
        bucket: map
            .get("bucket")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        after_key: map
            .get("after_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

fn save_cursor(path: &Path, cursor: &CorruptionCursor) -> Result<(), String> {
    let v = json!({
        "bucket": cursor.bucket,
        "after_key": cursor.after_key,
    });
    myfsio_common::fs_util::atomic_write_json(path, &v)
        .map_err(|error| format!("persist checksum cursor: {error}"))
}

fn recently_modified(path: &Path, grace: std::time::Duration) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(mtime) = meta.modified() else {
        return false;
    };
    match mtime.elapsed() {
        Ok(elapsed) => elapsed < grace,
        Err(_) => true,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ObjectStat {
    size: u64,
    mtime_unix_secs: u64,
    mtime_nanos: u32,
}

#[derive(Deserialize, Serialize)]
struct VerifiedEntry {
    size: u64,
    mtime_unix_secs: u64,
    mtime_nanos: u32,
    etag: String,
    verified_at_unix_ms: i64,
}

type VerifiedIndex = BTreeMap<String, VerifiedEntry>;

fn verified_index_path(storage_root: &Path, bucket: &str) -> PathBuf {
    storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join(VERIFIED_INDEX_FILE)
}

fn load_verified_index(path: &Path) -> VerifiedIndex {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str(&contents).ok())
        .unwrap_or_default()
}

fn save_verified_index(path: &Path, index: &VerifiedIndex) -> Result<(), String> {
    myfsio_common::fs_util::atomic_write_json(path, &json!(index))
        .map_err(|error| format!("persist verified checksum index: {error}"))
}

fn object_stat(metadata: &std::fs::Metadata) -> Option<ObjectStat> {
    let modified = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(ObjectStat {
        size: metadata.len(),
        mtime_unix_secs: modified.as_secs(),
        mtime_nanos: modified.subsec_nanos(),
    })
}

fn verified_entry_matches(
    entry: &VerifiedEntry,
    stat: ObjectStat,
    etag: &str,
    now_unix_ms: i64,
    reverify_days: u64,
) -> bool {
    if reverify_days == 0
        || entry.size != stat.size
        || entry.mtime_unix_secs != stat.mtime_unix_secs
        || entry.mtime_nanos != stat.mtime_nanos
        || entry.etag != etag
    {
        return false;
    }
    let Some(age_ms) = now_unix_ms.checked_sub(entry.verified_at_unix_ms) else {
        return false;
    };
    age_ms >= 0 && (age_ms as u64) < reverify_days.saturating_mul(86_400_000)
}

pub struct IntegrityConfig {
    pub interval_hours: f64,
    pub batch_size: usize,
    pub auto_heal: bool,
    pub dry_run: bool,
    pub heal_concurrency: usize,
    pub scan_pacing_ms: u64,
    pub quarantine_retention_days: u64,
    pub reverify_days: u64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            interval_hours: 24.0,
            batch_size: 10_000,
            auto_heal: false,
            dry_run: false,
            heal_concurrency: 1,
            scan_pacing_ms: 0,
            quarantine_retention_days: 7,
            reverify_days: 30,
        }
    }
}

pub struct IntegrityService {
    storage: Arc<FsStorageBackend>,
    storage_root: PathBuf,
    config: IntegrityConfig,
    peer_fetcher: Option<Arc<PeerFetcher>>,
    running: Arc<AtomicBool>,
    started_at: Arc<StdMutex<Option<Instant>>>,
    history: Arc<RwLock<Vec<Value>>>,
    history_path: PathBuf,
    persistence_error: Arc<StdMutex<Option<String>>>,
}

struct RunGuard {
    running: Arc<AtomicBool>,
    started_at: Arc<StdMutex<Option<Instant>>>,
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.started_at.lock() {
            *guard = None;
        }
    }
}

#[derive(Default, Clone)]
struct HealStats {
    found: u64,
    healed: u64,
    poisoned: u64,
    peer_mismatch: u64,
    peer_unavailable: u64,
    verify_failed: u64,
    failed: u64,
    skipped: u64,
    would_heal: u64,
}

impl HealStats {
    fn to_value(&self) -> Value {
        json!({
            "found": self.found,
            "healed": self.healed,
            "poisoned": self.poisoned,
            "peer_mismatch": self.peer_mismatch,
            "peer_unavailable": self.peer_unavailable,
            "verify_failed": self.verify_failed,
            "failed": self.failed,
            "skipped": self.skipped,
            "would_heal": self.would_heal,
        })
    }
}

#[derive(Default)]
struct ScanState {
    objects_scanned: u64,
    buckets_scanned: u64,
    corrupted_objects: u64,
    orphaned_objects: u64,
    phantom_metadata: u64,
    stale_versions: u64,
    poisoned_objects: u64,
    checksummed_objects: u64,
    checksum_skipped_unchanged: u64,
    multipart_objects_checked: u64,
    multipart_objects_unverifiable: u64,
    encrypted_objects_unverifiable: u64,
    version_contents_unverifiable: u64,
    invalid_metadata_keys: u64,
    issues: Vec<Value>,
    issue_counts: HashMap<String, usize>,
    errors: Vec<String>,
}

impl ScanState {
    fn push_issue(&mut self, issue_type: &str, bucket: &str, key: &str, detail: String) {
        let count = self.issue_counts.entry(issue_type.to_string()).or_insert(0);
        if *count < MAX_ISSUES_PER_TYPE {
            *count += 1;
            self.issues.push(json!({
                "issue_type": issue_type,
                "bucket": bucket,
                "key": key,
                "detail": detail,
            }));
        }
    }
}

impl IntegrityService {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        storage_root: &Path,
        mut config: IntegrityConfig,
        peer_fetcher: Option<Arc<PeerFetcher>>,
    ) -> Self {
        if !config.interval_hours.is_finite() || config.interval_hours <= 0.0 {
            config.interval_hours = IntegrityConfig::default().interval_hours;
        }
        config.batch_size = config.batch_size.max(1);
        config.heal_concurrency = config.heal_concurrency.clamp(1, 64);
        config.quarantine_retention_days = config.quarantine_retention_days.max(1);
        let history_path = storage_root
            .join(SYSTEM_ROOT)
            .join("config")
            .join("integrity_history.json");

        let (history, persistence_error) = if history_path.exists() {
            match std::fs::read_to_string(&history_path)
                .map_err(|error| format!("read integrity history: {error}"))
                .and_then(|contents| {
                    serde_json::from_str::<Value>(&contents)
                        .map_err(|error| format!("parse integrity history: {error}"))
                })
                .and_then(|value| {
                    value
                        .get("executions")
                        .and_then(Value::as_array)
                        .cloned()
                        .ok_or_else(|| {
                            "parse integrity history: missing executions array".to_string()
                        })
                }) {
                Ok(history) => (history, None),
                Err(error) => (Vec::new(), Some(error)),
            }
        } else {
            (Vec::new(), None)
        };

        Self {
            storage,
            storage_root: storage_root.to_path_buf(),
            config,
            peer_fetcher,
            running: Arc::new(AtomicBool::new(false)),
            started_at: Arc::new(StdMutex::new(None)),
            history: Arc::new(RwLock::new(history)),
            history_path,
            persistence_error: Arc::new(StdMutex::new(persistence_error)),
        }
    }

    pub async fn status(&self) -> Value {
        let running = self.running.load(Ordering::SeqCst);
        let scan_elapsed_seconds = self.started_at.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .map(|started| started.elapsed().as_secs_f64())
        });
        let last_run = self.history.read().await.last().cloned();
        let persistence_error = self
            .persistence_error
            .lock()
            .ok()
            .and_then(|error| error.clone());
        let last_run_total_issues = last_run
            .as_ref()
            .and_then(|run| run.get("result"))
            .map(unresolved_issue_count)
            .unwrap_or(0);
        json!({
            "enabled": true,
            "running": running,
            "scanning": running,
            "scan_elapsed_seconds": scan_elapsed_seconds,
            "interval_hours": self.config.interval_hours,
            "batch_size": self.config.batch_size,
            "auto_heal": self.config.auto_heal,
            "dry_run": self.config.dry_run,
            "heal_concurrency": self.config.heal_concurrency,
            "reverify_days": self.config.reverify_days,
            "peer_heal_available": self.peer_fetcher.is_some(),
            "quarantine_retention_days": self.config.quarantine_retention_days,
            "last_run": last_run,
            "last_run_total_issues": last_run_total_issues,
            "persistence_error": persistence_error,
        })
    }

    pub async fn history(&self) -> Value {
        let history = self.history.read().await;
        let mut executions: Vec<Value> = history.iter().cloned().collect();
        executions.reverse();
        json!({ "executions": executions })
    }

    fn try_claim(&self) -> Result<(), String> {
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("Integrity check already running".to_string());
        }
        if let Ok(mut guard) = self.started_at.lock() {
            *guard = Some(Instant::now());
        }
        Ok(())
    }

    pub async fn run_now(self: Arc<Self>, dry_run: bool, auto_heal: bool) -> Result<Value, String> {
        self.try_claim()?;
        let svc = self.clone();
        let guard = RunGuard {
            running: self.running.clone(),
            started_at: self.started_at.clone(),
        };
        let handle = tokio::spawn(async move {
            let _guard = guard;
            svc.execute(dry_run, auto_heal).await
        });
        handle
            .await
            .unwrap_or_else(|e| Err(format!("integrity task aborted: {}", e)))
    }

    pub fn start_run(self: Arc<Self>, dry_run: bool, auto_heal: bool) -> Result<(), String> {
        self.try_claim()?;
        let svc = self.clone();
        let guard = RunGuard {
            running: self.running.clone(),
            started_at: self.started_at.clone(),
        };
        tokio::spawn(async move {
            let _guard = guard;
            if let Err(e) = svc.execute(dry_run, auto_heal).await {
                tracing::warn!("Integrity check failed: {}", e);
            }
        });
        Ok(())
    }

    async fn execute(&self, dry_run: bool, auto_heal: bool) -> Result<Value, String> {
        let start = Instant::now();
        let storage_root = self.storage_root.clone();
        let batch_size = self.config.batch_size;
        let pacing_ms = self.config.scan_pacing_ms;
        let reverify_days = self.config.reverify_days;
        let scan_state = tokio::task::spawn_blocking(move || {
            scan_all_buckets_with_reverify(&storage_root, batch_size, pacing_ms, reverify_days)
        })
        .await
        .unwrap_or_else(|e| {
            let mut st = ScanState::default();
            st.errors.push(format!("scan task failed: {}", e));
            st
        });

        let heal_stats = if auto_heal && dry_run {
            preview_heal_phase(&scan_state)
        } else if auto_heal {
            self.run_heal_phase(&scan_state).await
        } else {
            BTreeMap::new()
        };

        let elapsed = start.elapsed().as_secs_f64();

        let result_json = build_result_json(scan_state, heal_stats, elapsed);

        let record = json!({
            "timestamp": chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            "dry_run": dry_run,
            "auto_heal": auto_heal,
            "result": result_json.clone(),
        });

        {
            let mut history = self.history.write().await;
            history.push(record);
            if history.len() > 50 {
                let excess = history.len() - 50;
                history.drain(..excess);
            }
        }
        if let Err(error) = self.save_history().await {
            tracing::error!("Failed to persist integrity history: {}", error);
            if let Ok(mut last_error) = self.persistence_error.lock() {
                *last_error = Some(error);
            }
        } else if let Ok(mut last_error) = self.persistence_error.lock() {
            *last_error = None;
        }

        let total_issues = total_issue_count(&result_json);
        let error_count = result_json
            .get("errors")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        if total_issues > 0 || error_count > 0 {
            tracing::warn!(
                total_issues,
                error_count,
                "Integrity scan completed with findings"
            );
        }

        Ok(result_json)
    }

    async fn run_heal_phase(&self, scan: &ScanState) -> BTreeMap<String, HealStats> {
        let mut stats: BTreeMap<String, HealStats> = BTreeMap::new();
        let issues: Vec<Value> = scan.issues.clone();
        let semaphore = Arc::new(Semaphore::new(self.config.heal_concurrency.max(1)));
        let mut tasks: Vec<tokio::task::JoinHandle<HealReport>> = Vec::new();

        for issue in issues {
            let issue_type = issue
                .get("issue_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let bucket = issue
                .get("bucket")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let key = issue
                .get("key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let detail = issue
                .get("detail")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            stats.entry(issue_type.clone()).or_default().found += 1;

            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let storage = self.storage.clone();
            let storage_root = self.storage_root.clone();
            let peer_fetcher = self.peer_fetcher.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                heal_issue(
                    &storage,
                    &storage_root,
                    peer_fetcher.as_deref(),
                    &issue_type,
                    &bucket,
                    &key,
                    &detail,
                )
                .await
            }));
        }

        for task in tasks {
            if let Ok(report) = task.await {
                let entry = stats.entry(report.issue_type).or_default();
                match report.status {
                    HealStatus::Healed => entry.healed += 1,
                    HealStatus::Poisoned => entry.poisoned += 1,
                    HealStatus::PeerMismatch => entry.peer_mismatch += 1,
                    HealStatus::PeerUnavailable => entry.peer_unavailable += 1,
                    HealStatus::VerifyFailed => entry.verify_failed += 1,
                    HealStatus::Failed => entry.failed += 1,
                    HealStatus::Skipped => entry.skipped += 1,
                }
            }
        }

        stats
    }

    async fn save_history(&self) -> Result<(), String> {
        let data = {
            let history = self.history.read().await;
            json!({ "executions": *history })
        };
        let history_path = self.history_path.clone();
        tokio::task::spawn_blocking(move || {
            myfsio_common::fs_util::atomic_write_json(&history_path, &data)
                .map_err(|error| error.to_string())
        })
        .await
        .map_err(|error| format!("integrity history task failed: {error}"))?
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs_f64(self.config.interval_hours * 3600.0);
        let auto_heal = self.config.auto_heal;
        let dry_run = self.config.dry_run;
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                tracing::info!("Integrity check starting");
                match Arc::clone(&self).run_now(dry_run, auto_heal).await {
                    Ok(result) => tracing::info!("Integrity check complete: {:?}", result),
                    Err(e) => tracing::warn!("Integrity check failed: {}", e),
                }
            }
        })
    }

    pub(crate) async fn handle_read_corruption(
        &self,
        bucket: &str,
        key: &str,
        expected_etag: &str,
        actual_etag: &str,
    ) {
        let detail = format!(
            "stored_etag={} actual_etag={} detected_on_read=true",
            expected_etag, actual_etag
        );
        let status = heal_corrupted(
            &self.storage,
            self.peer_fetcher.as_deref(),
            bucket,
            key,
            &detail,
        )
        .await;
        tracing::error!(
            bucket,
            key,
            expected_etag,
            actual_etag,
            status = ?status,
            "Verify-on-read corruption handling completed"
        );
    }
}

#[derive(Debug)]
enum HealStatus {
    Healed,
    Poisoned,
    PeerMismatch,
    PeerUnavailable,
    VerifyFailed,
    Failed,
    Skipped,
}

struct HealReport {
    issue_type: String,
    status: HealStatus,
}

async fn heal_issue(
    storage: &FsStorageBackend,
    storage_root: &Path,
    peer_fetcher: Option<&PeerFetcher>,
    issue_type: &str,
    bucket: &str,
    key: &str,
    detail: &str,
) -> HealReport {
    let status = match issue_type {
        "corrupted_object" => heal_corrupted(storage, peer_fetcher, bucket, key, detail).await,
        "poisoned_object" => recover_poisoned(storage, peer_fetcher, bucket, key).await,
        "stale_version" => heal_stale_version(storage_root, bucket, key).await,
        "phantom_metadata" => heal_phantom_metadata(storage, bucket, key, detail).await,
        _ => HealStatus::Skipped,
    };
    HealReport {
        issue_type: issue_type.to_string(),
        status,
    }
}

async fn heal_corrupted(
    storage: &FsStorageBackend,
    peer_fetcher: Option<&PeerFetcher>,
    bucket: &str,
    key: &str,
    detail: &str,
) -> HealStatus {
    let stored_etag = parse_stored_etag(detail);
    if stored_etag.is_empty() {
        return HealStatus::Skipped;
    }
    let quarantine_rel = quarantine_relative_path(bucket, key);
    match storage
        .quarantine_corrupted_object(bucket, key, &stored_etag, &quarantine_rel, detail)
        .await
    {
        Ok(IntegrityQuarantineOutcome::Quarantined) => {
            tracing::warn!("Quarantined corrupted object {}/{}", bucket, key);
        }
        Ok(IntegrityQuarantineOutcome::Healthy | IntegrityQuarantineOutcome::Skipped) => {
            return HealStatus::Skipped;
        }
        Err(error) => {
            tracing::error!("Failed to quarantine {}/{}: {}", bucket, key, error);
            return HealStatus::Failed;
        }
    }
    recover_poisoned(storage, peer_fetcher, bucket, key).await
}

async fn recover_poisoned(
    storage: &FsStorageBackend,
    peer_fetcher: Option<&PeerFetcher>,
    bucket: &str,
    key: &str,
) -> HealStatus {
    let live_path = match storage.validated_object_path(bucket, key) {
        Ok(path) => path,
        Err(error) => {
            tracing::error!("Invalid poisoned object path {}/{}: {}", bucket, key, error);
            return HealStatus::Failed;
        }
    };
    let metadata = match storage.get_object_metadata(bucket, key).await {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::error!(
                "Read poisoned metadata {}/{} failed: {}",
                bucket,
                key,
                error
            );
            return HealStatus::Failed;
        }
    };
    if !metadata_is_corrupted(&metadata) || tokio::fs::try_exists(&live_path).await.unwrap_or(false)
    {
        return HealStatus::Skipped;
    }
    let stored_etag = metadata.get("__etag__").cloned().unwrap_or_default();
    if stored_etag.is_empty()
        || is_multipart_etag(&stored_etag)
        || EncryptionMetadata::is_encrypted(&metadata)
    {
        return HealStatus::Skipped;
    }
    let Some(fetcher) = peer_fetcher else {
        return HealStatus::Poisoned;
    };

    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let temp_path = live_path.with_file_name(format!(
        "{}.healing.{}",
        live_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "healing".to_string()),
        nonce
    ));
    match fetcher
        .fetch_for_heal(bucket, key, &stored_etag, &temp_path)
        .await
    {
        HealOutcome::Healed { peer_etag, bytes } => match storage
            .install_healed_object_if_still_poisoned(bucket, key, &stored_etag, &temp_path)
            .await
        {
            Ok(true) => {
                tracing::info!(
                    "Healed {}/{} from peer (etag={}, bytes={})",
                    bucket,
                    key,
                    peer_etag,
                    bytes
                );
                HealStatus::Healed
            }
            Ok(false) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                tracing::info!(
                    "Heal {}/{} lost a race to a fresh write; preserving the fresh object",
                    bucket,
                    key
                );
                HealStatus::Skipped
            }
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                tracing::error!("Install healed object {}/{} failed: {}", bucket, key, error);
                HealStatus::Failed
            }
        },
        HealOutcome::PeerMismatch { stored, peer } => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let detail = format!("peer etag {peer} != stored {stored}");
            record_recovery_failure(
                storage,
                bucket,
                key,
                &stored_etag,
                &detail,
                HealStatus::PeerMismatch,
            )
            .await
        }
        HealOutcome::PeerUnavailable { error } => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let detail =
                format!("peer unavailable while recovering stored_etag={stored_etag}: {error}");
            record_recovery_failure(
                storage,
                bucket,
                key,
                &stored_etag,
                &detail,
                HealStatus::PeerUnavailable,
            )
            .await
        }
        HealOutcome::VerifyFailed { expected, actual } => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let detail = format!("peer verification failed: expected={expected} actual={actual}");
            record_recovery_failure(
                storage,
                bucket,
                key,
                &stored_etag,
                &detail,
                HealStatus::VerifyFailed,
            )
            .await
        }
        HealOutcome::NotConfigured => {
            let _ = tokio::fs::remove_file(&temp_path).await;
            let detail =
                format!("recovery pending: no peer configured for stored_etag={stored_etag}");
            record_recovery_failure(
                storage,
                bucket,
                key,
                &stored_etag,
                &detail,
                HealStatus::Poisoned,
            )
            .await
        }
    }
}

async fn record_recovery_failure(
    storage: &FsStorageBackend,
    bucket: &str,
    key: &str,
    expected_etag: &str,
    detail: &str,
    status: HealStatus,
) -> HealStatus {
    match storage
        .record_poisoned_recovery_failure(bucket, key, expected_etag, detail)
        .await
    {
        Ok(true) => status,
        Ok(false) => HealStatus::Skipped,
        Err(error) => {
            tracing::error!(
                "Record recovery failure {}/{} failed: {}",
                bucket,
                key,
                error
            );
            HealStatus::Failed
        }
    }
}

async fn heal_stale_version(storage_root: &Path, bucket: &str, key: &str) -> HealStatus {
    let storage_root = storage_root.to_path_buf();
    let bucket = bucket.to_string();
    let key = key.to_string();
    tokio::task::spawn_blocking(move || {
        let versions_root = storage_root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(&bucket)
            .join(BUCKET_VERSIONS_DIR);
        let src = versions_root.join(&key);
        if !src.exists() || recently_modified(&src, STALE_VERSION_GRACE) {
            return HealStatus::Skipped;
        }
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string();
        let dst = storage_root
            .join(SYSTEM_ROOT)
            .join(QUARANTINE_DIR)
            .join(&bucket)
            .join(&ts)
            .join("versions")
            .join(&key);
        if let Some(parent) = dst.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::error!(
                    "Stale-version quarantine mkdir failed {}/{}: {}",
                    bucket,
                    key,
                    e
                );
                return HealStatus::Failed;
            }
        }
        if let Err(e) = std::fs::rename(&src, &dst) {
            tracing::error!(
                "Stale-version quarantine rename failed {}/{}: {}",
                bucket,
                key,
                e
            );
            return HealStatus::Failed;
        }
        tracing::info!("Quarantined stale version {}/{}", bucket, key);
        HealStatus::Healed
    })
    .await
    .unwrap_or(HealStatus::Failed)
}

async fn heal_phantom_metadata(
    storage: &FsStorageBackend,
    bucket: &str,
    key: &str,
    detail: &str,
) -> HealStatus {
    let expected_etag = parse_stored_etag(detail);
    match storage
        .delete_phantom_metadata_if_still_missing(
            bucket,
            key,
            (!expected_etag.is_empty()).then_some(expected_etag.as_str()),
        )
        .await
    {
        Ok(true) => {
            tracing::info!("Dropped phantom metadata for {}/{}", bucket, key);
            HealStatus::Healed
        }
        Ok(false) => HealStatus::Skipped,
        Err(e) => {
            tracing::error!("Failed to drop phantom metadata {}/{}: {}", bucket, key, e);
            HealStatus::Failed
        }
    }
}

fn quarantine_relative_path(bucket: &str, key: &str) -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string();
    PathBuf::from(SYSTEM_ROOT)
        .join(QUARANTINE_DIR)
        .join(bucket)
        .join(ts)
        .join(key)
}

fn parse_stored_etag(detail: &str) -> String {
    detail
        .split_whitespace()
        .find_map(|s| s.strip_prefix("stored_etag="))
        .unwrap_or("")
        .to_string()
}

fn preview_heal_phase(scan: &ScanState) -> BTreeMap<String, HealStats> {
    let mut stats: BTreeMap<String, HealStats> = BTreeMap::new();
    for issue in &scan.issues {
        let issue_type = issue
            .get("issue_type")
            .and_then(Value::as_str)
            .unwrap_or("");
        let entry = stats.entry(issue_type.to_string()).or_default();
        entry.found += 1;
        let detail = issue.get("detail").and_then(Value::as_str).unwrap_or("");
        let supported_corruption = {
            let etag = parse_stored_etag(detail);
            !etag.is_empty() && !is_multipart_etag(&etag)
        };
        if matches!(issue_type, "stale_version" | "phantom_metadata")
            || matches!(issue_type, "corrupted_object" | "poisoned_object") && supported_corruption
        {
            entry.would_heal += 1;
        } else {
            entry.skipped += 1;
        }
    }
    stats
}

fn total_issue_count(result: &Value) -> u64 {
    [
        "corrupted_objects",
        "orphaned_objects",
        "phantom_metadata",
        "stale_versions",
        "legacy_metadata_drifts",
        "poisoned_objects",
        "invalid_metadata_keys",
    ]
    .iter()
    .map(|key| result.get(key).and_then(Value::as_u64).unwrap_or(0))
    .sum()
}

fn unresolved_issue_count(result: &Value) -> u64 {
    let healed = result
        .get("issues_healed")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    total_issue_count(result).saturating_sub(healed)
}

fn build_result_json(
    state: ScanState,
    heal_stats: BTreeMap<String, HealStats>,
    elapsed: f64,
) -> Value {
    let issues_healed: u64 = heal_stats.values().map(|s| s.healed).sum();
    let issues_would_heal: u64 = heal_stats.values().map(|s| s.would_heal).sum();
    let heal_stats_json: serde_json::Map<String, Value> = heal_stats
        .iter()
        .map(|(k, v)| (k.clone(), v.to_value()))
        .collect();

    json!({
        "objects_scanned": state.objects_scanned,
        "buckets_scanned": state.buckets_scanned,
        "corrupted_objects": state.corrupted_objects,
        "orphaned_objects": state.orphaned_objects,
        "phantom_metadata": state.phantom_metadata,
        "stale_versions": state.stale_versions,
        "poisoned_objects": state.poisoned_objects,
        "checksummed_objects": state.checksummed_objects,
        "checksum_skipped_unchanged": state.checksum_skipped_unchanged,
        "multipart_objects_checked": state.multipart_objects_checked,
        "multipart_objects_unverifiable": state.multipart_objects_unverifiable,
        "encrypted_objects_unverifiable": state.encrypted_objects_unverifiable,
        "version_contents_unverifiable": state.version_contents_unverifiable,
        "invalid_metadata_keys": state.invalid_metadata_keys,
        "issues_healed": issues_healed,
        "issues_would_heal": issues_would_heal,
        "heal_stats": Value::Object(heal_stats_json),
        "issues": state.issues,
        "errors": state.errors,
        "execution_time_seconds": elapsed,
    })
}

#[cfg(test)]
fn scan_all_buckets(storage_root: &Path, batch_size: usize, pacing_ms: u64) -> ScanState {
    scan_all_buckets_with_reverify(storage_root, batch_size, pacing_ms, 30)
}

fn scan_all_buckets_with_reverify(
    storage_root: &Path,
    batch_size: usize,
    pacing_ms: u64,
    reverify_days: u64,
) -> ScanState {
    let mut state = ScanState::default();
    let mut pacer = Pacer::new(pacing_ms);
    let mut buckets = match list_bucket_names(storage_root) {
        Ok(b) => b,
        Err(e) => {
            state.errors.push(format!("list buckets: {}", e));
            return state;
        }
    };
    buckets.sort();

    for bucket in &buckets {
        state.buckets_scanned += 1;
        let bucket_path = storage_root.join(bucket);
        let index_entries = collect_all_metadata(storage_root, bucket);

        check_phantom(&mut state, bucket, &bucket_path, &index_entries, &mut pacer);
        check_orphaned(&mut state, bucket, &bucket_path, &index_entries, &mut pacer);
        check_stale_versions(&mut state, storage_root, bucket, &mut pacer);
    }

    if buckets.is_empty() || batch_size == 0 {
        return state;
    }

    let cursor_path = cursor_path_for(storage_root);
    let cursor = match load_cursor(&cursor_path) {
        Ok(cursor) => cursor,
        Err(error) => {
            state.errors.push(error);
            CorruptionCursor::default()
        }
    };

    let start_idx = buckets
        .iter()
        .position(|b| b == &cursor.bucket)
        .unwrap_or(0);
    let mut remaining = batch_size;
    let mut new_cursor = CorruptionCursor::default();
    let mut bailed_mid_bucket = false;
    let mut last_offset_visited: Option<usize> = None;

    for offset in 0..buckets.len() {
        let idx = (start_idx + offset) % buckets.len();
        let bucket = &buckets[idx];
        let after_key: &str = if offset == 0 && bucket == &cursor.bucket {
            cursor.after_key.as_str()
        } else {
            ""
        };

        let bucket_path = storage_root.join(bucket);
        let index_entries = collect_all_metadata(storage_root, bucket);
        let verified_path = verified_index_path(storage_root, bucket);
        let mut verified_index = if reverify_days == 0 {
            VerifiedIndex::default()
        } else {
            load_verified_index(&verified_path)
        };

        last_offset_visited = Some(offset);
        let result = check_corrupted(
            &mut state,
            storage_root,
            bucket,
            &bucket_path,
            &index_entries,
            after_key,
            &mut remaining,
            &mut pacer,
            &mut verified_index,
            reverify_days,
        );
        if reverify_days > 0 {
            verified_index.retain(|key, _| index_entries.contains_key(key));
            if let Err(error) = save_verified_index(&verified_path, &verified_index) {
                state.errors.push(error);
            }
        }

        if let Some(k) = result.last_examined {
            new_cursor = CorruptionCursor {
                bucket: bucket.clone(),
                after_key: k,
            };
        } else if !result.finished_bucket {
            new_cursor = CorruptionCursor {
                bucket: bucket.clone(),
                after_key: String::new(),
            };
        }

        if !result.finished_bucket {
            bailed_mid_bucket = true;
            break;
        }
    }

    let visited_all_buckets = last_offset_visited == Some(buckets.len() - 1);
    if visited_all_buckets && !bailed_mid_bucket {
        new_cursor = CorruptionCursor::default();
    }

    if let Err(error) = save_cursor(&cursor_path, &new_cursor) {
        state.errors.push(error);
    }
    state
}

fn list_bucket_names(storage_root: &Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    if !storage_root.exists() {
        return Ok(names);
    }
    for entry in std::fs::read_dir(storage_root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name == SYSTEM_ROOT {
            continue;
        }
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            names.push(name);
        }
    }
    Ok(names)
}

#[allow(dead_code)]
struct IndexEntryInfo {
    entry: Value,
    index_file: PathBuf,
    key_name: String,
}

fn collect_all_metadata(storage_root: &Path, bucket: &str) -> HashMap<String, IndexEntryInfo> {
    let modern_meta_root = storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join(BUCKET_META_DIR);
    let mut out = collect_index_entries(&modern_meta_root);

    let legacy_meta_root = storage_root.join(bucket).join(".meta");
    if legacy_meta_root.exists() {
        for (k, v) in collect_index_entries(&legacy_meta_root) {
            out.entry(k).or_insert(v);
        }
    }
    out
}

fn collect_index_entries(meta_root: &Path) -> HashMap<String, IndexEntryInfo> {
    let mut out: HashMap<String, IndexEntryInfo> = HashMap::new();
    if !meta_root.exists() {
        return out;
    }

    let mut sidecar_keys: HashSet<String> = HashSet::new();
    let mut stack: Vec<PathBuf> = vec![meta_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            let file_name = entry.file_name().to_string_lossy().to_string();

            let rel_dir = match path.parent().and_then(|p| p.strip_prefix(meta_root).ok()) {
                Some(p) => p.to_path_buf(),
                None => continue,
            };
            let dir_prefix = if rel_dir.as_os_str().is_empty() {
                String::new()
            } else {
                rel_dir
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .collect::<Vec<_>>()
                    .join("/")
            };

            if file_name.starts_with(SIDECAR_FILE_PREFIX) && file_name.ends_with(SIDECAR_FILE_EXT) {
                let fallback_name = file_name
                    .strip_prefix(SIDECAR_FILE_PREFIX)
                    .and_then(|s| s.strip_suffix(SIDECAR_FILE_EXT))
                    .map(str::to_string);
                let parsed: Option<Value> = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|c| serde_json::from_str(&c).ok());
                let (entry_name, entry_val) = match parsed {
                    Some(entry_val) => {
                        let entry_name = entry_val
                            .get(SIDECAR_ENTRY_NAME_FIELD)
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                            .or(fallback_name);
                        let Some(entry_name) = entry_name else {
                            continue;
                        };
                        (entry_name, entry_val)
                    }
                    None => {
                        let Some(entry_name) = fallback_name else {
                            continue;
                        };
                        let entry_val = json!({
                            "metadata": {
                                META_KEY_CORRUPTED: "true",
                                META_KEY_CORRUPTION_DETAIL: "metadata sidecar unreadable",
                            }
                        });
                        (entry_name, entry_val)
                    }
                };
                let full_key = if dir_prefix.is_empty() {
                    entry_name.clone()
                } else {
                    format!("{}/{}", dir_prefix, entry_name)
                };
                sidecar_keys.insert(full_key.clone());
                out.insert(
                    full_key,
                    IndexEntryInfo {
                        entry: entry_val,
                        index_file: path.clone(),
                        key_name: entry_name,
                    },
                );
            } else if file_name == INDEX_FILE {
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let index_data: Map<String, Value> = match serde_json::from_str(&content) {
                    Ok(Value::Object(m)) => m,
                    _ => continue,
                };

                for (key_name, entry_val) in index_data {
                    let full_key = if dir_prefix.is_empty() {
                        key_name.clone()
                    } else {
                        format!("{}/{}", dir_prefix, key_name)
                    };
                    if sidecar_keys.contains(&full_key) {
                        continue;
                    }
                    out.insert(
                        full_key,
                        IndexEntryInfo {
                            entry: entry_val,
                            index_file: path.clone(),
                            key_name,
                        },
                    );
                }
            } else if let Some(stem) = file_name.strip_suffix(".meta.json") {
                let full_key = if dir_prefix.is_empty() {
                    stem.to_string()
                } else {
                    format!("{}/{}", dir_prefix, stem)
                };
                if out.contains_key(&full_key) {
                    continue;
                }
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                let entry_val: Value = match serde_json::from_str(&content) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                out.insert(
                    full_key,
                    IndexEntryInfo {
                        entry: entry_val,
                        index_file: path.clone(),
                        key_name: stem.to_string(),
                    },
                );
            }
        }
    }
    out
}

fn resolve_data_path(bucket_path: &Path, full_key: &str) -> Result<PathBuf, String> {
    if let Some(error) =
        myfsio_storage::validation::validate_object_key(full_key, usize::MAX, cfg!(windows), None)
    {
        return Err(error);
    }
    if let Some(stripped) = full_key.strip_suffix('/') {
        return Ok(bucket_path.join(stripped).join(DIR_MARKER_FILE));
    }
    let direct = bucket_path.join(full_key);
    if direct.is_dir() {
        Ok(direct.join(KEY_DATA_MARKER_FILE))
    } else {
        Ok(direct)
    }
}

fn stored_etag(entry: &Value) -> Option<String> {
    entry
        .get("metadata")
        .and_then(|m| m.get("__etag__"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn entry_metadata_map(entry: &Value) -> HashMap<String, String> {
    entry
        .get("metadata")
        .and_then(|m| m.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

struct CorruptionScanResult {
    last_examined: Option<String>,
    finished_bucket: bool,
}

fn hash_exact_part<R: Read>(reader: &mut R, size: u64) -> std::io::Result<[u8; 16]> {
    let mut hasher = Md5::new();
    let mut remaining = size;
    let mut buffer = [0u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("multipart part ended with {remaining} bytes remaining"),
            ));
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(hasher.finalize().into())
}

fn ensure_eof<R: Read>(reader: &mut R) -> std::io::Result<()> {
    let mut extra = [0u8; 1];
    if reader.read(&mut extra)? != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "multipart data contains bytes beyond the recorded part sizes",
        ));
    }
    Ok(())
}

fn is_content_damage(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
    )
}

fn part_size_manifest(metadata: &HashMap<String, String>) -> Option<Vec<u64>> {
    metadata
        .get(META_KEY_PART_SIZES)
        .and_then(|raw| myfsio_storage::fs_backend::parse_part_sizes(raw))
}

fn multipart_etag(
    storage_root: &Path,
    bucket: &str,
    object_path: &Path,
    metadata: &HashMap<String, String>,
) -> std::io::Result<String> {
    let sizes = part_size_manifest(metadata).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "multipart object has no valid part-size manifest",
        )
    })?;
    let mut composite = Md5::new();

    if let Some(segment_id) = metadata.get(myfsio_storage::segments::META_KEY_SEGMENTS) {
        if !myfsio_storage::validation::is_valid_multipart_id(segment_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "multipart object has an invalid segment identifier",
            ));
        }
        let segment_dir = storage_root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(myfsio_storage::segments::SEGMENTS_DIR)
            .join(segment_id);
        for (ordinal, expected_size) in sizes.iter().copied().enumerate() {
            let path =
                segment_dir.join(myfsio_storage::segments::SegmentSet::seg_file_name(ordinal));
            let mut file = std::fs::File::open(&path)?;
            if file.metadata()?.len() != expected_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("segment {} has an unexpected size", path.display()),
                ));
            }
            composite.update(hash_exact_part(&mut file, expected_size)?);
            ensure_eof(&mut file)?;
        }
    } else {
        let mut file = std::fs::File::open(object_path)?;
        for expected_size in sizes.iter().copied() {
            composite.update(hash_exact_part(&mut file, expected_size)?);
        }
        ensure_eof(&mut file)?;
    }

    Ok(format!("{:x}-{}", composite.finalize(), sizes.len()))
}

fn check_corrupted(
    state: &mut ScanState,
    storage_root: &Path,
    bucket: &str,
    bucket_path: &Path,
    entries: &HashMap<String, IndexEntryInfo>,
    after_key: &str,
    remaining: &mut usize,
    pacer: &mut Pacer,
    verified_index: &mut VerifiedIndex,
    reverify_days: u64,
) -> CorruptionScanResult {
    let mut keys: Vec<&String> = entries.keys().collect();
    keys.sort();

    let start = keys.partition_point(|k| k.as_str() <= after_key);
    let mut last_examined: Option<String> = None;
    let now_unix_ms = chrono::Utc::now().timestamp_millis();

    for full_key in &keys[start..] {
        let info = &entries[*full_key];
        let object_path = resolve_data_path(bucket_path, full_key).ok();
        let meta_map = entry_metadata_map(&info.entry);
        let stored = stored_etag(&info.entry);
        let metadata = object_path
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok());
        let stat = metadata.as_ref().and_then(object_stat);
        let cacheable = reverify_days > 0
            && metadata.as_ref().is_some_and(std::fs::Metadata::is_file)
            && !metadata_is_corrupted(&meta_map)
            && !EncryptionMetadata::is_encrypted(&meta_map)
            && !meta_map.contains_key(myfsio_storage::segments::META_KEY_SEGMENTS)
            && stored.as_ref().is_some_and(|etag| {
                !is_multipart_etag(etag) || part_size_manifest(&meta_map).is_some()
            });
        let skip_unchanged = cacheable
            && stored.as_deref().is_some_and(|etag| {
                stat.is_some_and(|stat| {
                    verified_index.get(*full_key).is_some_and(|entry| {
                        verified_entry_matches(entry, stat, etag, now_unix_ms, reverify_days)
                    })
                })
            });
        if skip_unchanged {
            last_examined = Some((*full_key).clone());
            pacer.tick();
            state.checksum_skipped_unchanged += 1;
            continue;
        }
        if *remaining == 0 {
            return CorruptionScanResult {
                last_examined,
                finished_bucket: false,
            };
        }
        *remaining -= 1;
        last_examined = Some((*full_key).clone());
        pacer.tick();

        let Some(object_path) = object_path else {
            continue;
        };
        if !metadata.as_ref().is_some_and(std::fs::Metadata::is_file) {
            continue;
        }
        if metadata_is_corrupted(&meta_map) {
            verified_index.remove(*full_key);
            continue;
        }
        if EncryptionMetadata::is_encrypted(&meta_map) {
            state.encrypted_objects_unverifiable += 1;
            continue;
        }

        let Some(stored) = stored else {
            continue;
        };

        let is_multipart = is_multipart_etag(&stored);
        if is_multipart && part_size_manifest(&meta_map).is_none() {
            state.multipart_objects_unverifiable += 1;
            continue;
        }

        let actual = if is_multipart {
            multipart_etag(storage_root, bucket, &object_path, &meta_map)
        } else {
            myfsio_crypto::hashing::md5_file(&object_path)
        };
        if let Err(e) = &actual {
            if !is_content_damage(e) {
                state
                    .errors
                    .push(format!("hash {}/{}: {}", bucket, full_key, e));
                continue;
            }
        }

        state.checksummed_objects += 1;
        if is_multipart {
            state.multipart_objects_checked += 1;
        }
        match actual {
            Ok(actual) if actual == stored => {
                if cacheable {
                    let current_stat = std::fs::metadata(&object_path)
                        .ok()
                        .and_then(|metadata| object_stat(&metadata));
                    if let Some(stat) = stat.filter(|stat| Some(*stat) == current_stat) {
                        verified_index.insert(
                            (*full_key).clone(),
                            VerifiedEntry {
                                size: stat.size,
                                mtime_unix_secs: stat.mtime_unix_secs,
                                mtime_nanos: stat.mtime_nanos,
                                etag: stored,
                                verified_at_unix_ms: now_unix_ms,
                            },
                        );
                    }
                }
            }
            Ok(actual) => {
                verified_index.remove(*full_key);
                state.corrupted_objects += 1;
                state.push_issue(
                    "corrupted_object",
                    bucket,
                    full_key,
                    format!("stored_etag={} actual_etag={}", stored, actual),
                );
            }
            Err(e) => {
                verified_index.remove(*full_key);
                state.corrupted_objects += 1;
                state.push_issue(
                    "corrupted_object",
                    bucket,
                    full_key,
                    format!("stored_etag={} checksum_error={}", stored, e),
                );
            }
        }
    }
    CorruptionScanResult {
        last_examined,
        finished_bucket: true,
    }
}

fn check_phantom(
    state: &mut ScanState,
    bucket: &str,
    bucket_path: &Path,
    entries: &HashMap<String, IndexEntryInfo>,
    pacer: &mut Pacer,
) {
    let mut ranked: Vec<(&String, Option<(u64, &str)>)> = entries
        .iter()
        .map(|(key, info)| (key, poisoned_retry_rank(&info.entry)))
        .collect();
    ranked.sort_by(
        |(left, left_rank), (right, right_rank)| match (left_rank, right_rank) {
            (Some(left_rank), Some(right_rank)) => left_rank
                .cmp(right_rank)
                .then_with(|| left.as_str().cmp(right.as_str())),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => left.as_str().cmp(right.as_str()),
        },
    );

    for (full_key, _) in ranked {
        pacer.tick();
        let info = &entries[full_key];
        state.objects_scanned += 1;
        let object_path = match resolve_data_path(bucket_path, full_key) {
            Ok(path) => path,
            Err(error) => {
                state.invalid_metadata_keys += 1;
                state.errors.push(format!(
                    "invalid metadata key {}/{}: {}",
                    bucket, full_key, error
                ));
                state.push_issue("invalid_metadata_key", bucket, full_key, error);
                continue;
            }
        };
        let meta_map = entry_metadata_map(&info.entry);
        if metadata_is_corrupted(&meta_map) {
            if !object_path.is_file() {
                state.poisoned_objects += 1;
                let stored = meta_map.get("__etag__").cloned().unwrap_or_default();
                let detail = meta_map
                    .get(META_KEY_CORRUPTION_DETAIL)
                    .cloned()
                    .unwrap_or_else(|| "quarantined object is awaiting recovery".to_string());
                state.push_issue(
                    "poisoned_object",
                    bucket,
                    full_key,
                    format!("stored_etag={} {}", stored, detail),
                );
            }
            continue;
        }
        if !object_path.is_file() {
            state.phantom_metadata += 1;
            let stored = stored_etag(&info.entry).unwrap_or_default();
            state.push_issue(
                "phantom_metadata",
                bucket,
                full_key,
                format!("metadata entry without file on disk stored_etag={stored}"),
            );
        } else if let Some(seg_id) = meta_map.get(myfsio_storage::segments::META_KEY_SEGMENTS) {
            let seg_dir = bucket_path
                .parent()
                .filter(|_| myfsio_storage::validation::is_valid_multipart_id(seg_id))
                .map(|root| {
                    root.join(".myfsio.sys")
                        .join("buckets")
                        .join(bucket)
                        .join(myfsio_storage::segments::SEGMENTS_DIR)
                        .join(seg_id)
                });
            let sizes = meta_map
                .get("__part_sizes__")
                .and_then(|raw| myfsio_storage::fs_backend::parse_part_sizes(raw));
            let intact = match (seg_dir, sizes) {
                (Some(dir), Some(sizes)) => myfsio_storage::segments::SegmentSet::new(dir, sizes)
                    .verify_files()
                    .is_ok(),
                _ => false,
            };
            if !intact {
                state.phantom_metadata += 1;
                state.push_issue(
                    "missing_segments",
                    bucket,
                    full_key,
                    "segmented object is missing or has mismatched segment files".to_string(),
                );
            }
        }
    }
}

fn poisoned_retry_rank(entry: &Value) -> Option<(u64, &str)> {
    let metadata = entry.get("metadata")?.as_object()?;
    let field = |name: &str| metadata.get(name).and_then(Value::as_str);
    if !field(META_KEY_CORRUPTED).is_some_and(|value| value.eq_ignore_ascii_case("true")) {
        return None;
    }
    let retries = field(META_KEY_CORRUPTION_RETRY_COUNT)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    Some((
        retries,
        field(META_KEY_CORRUPTION_LAST_RETRY_AT).unwrap_or(""),
    ))
}

fn check_orphaned(
    state: &mut ScanState,
    bucket: &str,
    bucket_path: &Path,
    entries: &HashMap<String, IndexEntryInfo>,
    pacer: &mut Pacer,
) {
    let indexed: HashSet<&String> = entries.keys().collect();
    let mut stack: Vec<(PathBuf, String)> = vec![(bucket_path.to_path_buf(), String::new())];

    while let Some((dir, prefix)) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                if prefix.is_empty() && INTERNAL_FOLDERS.contains(&name.as_str()) {
                    continue;
                }
                let new_prefix = if prefix.is_empty() {
                    name
                } else {
                    format!("{}/{}", prefix, name)
                };
                stack.push((entry.path(), new_prefix));
            } else if ft.is_file() {
                pacer.tick();
                let full_key = if name == KEY_DATA_MARKER_FILE {
                    if prefix.is_empty() {
                        continue;
                    }
                    prefix.clone()
                } else if prefix.is_empty() {
                    name
                } else {
                    format!("{}/{}", prefix, name)
                };
                if !indexed.contains(&full_key) {
                    state.orphaned_objects += 1;
                    state.push_issue(
                        "orphaned_object",
                        bucket,
                        &full_key,
                        "file exists without metadata entry".to_string(),
                    );
                }
            }
        }
    }
}

fn check_stale_versions(
    state: &mut ScanState,
    storage_root: &Path,
    bucket: &str,
    pacer: &mut Pacer,
) {
    let versions_root = storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join(BUCKET_VERSIONS_DIR);
    if !versions_root.exists() {
        return;
    }

    let mut stack: Vec<PathBuf> = vec![versions_root.clone()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let mut bin_stems: HashMap<String, PathBuf> = HashMap::new();
        let mut json_stems: HashMap<String, PathBuf> = HashMap::new();
        let mut subdirs: Vec<PathBuf> = Vec::new();

        for entry in rd.flatten() {
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let path = entry.path();
            if ft.is_dir() {
                subdirs.push(path);
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(stem) = name.strip_suffix(".bin") {
                bin_stems.insert(stem.to_string(), path);
            } else if let Some(stem) = name.strip_suffix(".json") {
                json_stems.insert(stem.to_string(), path);
            }
        }

        for (stem, path) in &bin_stems {
            pacer.tick();
            if !json_stems.contains_key(stem) {
                state.stale_versions += 1;
                let key = path
                    .strip_prefix(&versions_root)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.display().to_string());
                state.push_issue(
                    "stale_version",
                    bucket,
                    &key,
                    "version data without manifest".to_string(),
                );
            }
        }

        for (stem, path) in &json_stems {
            pacer.tick();
            if !bin_stems.contains_key(stem) {
                if manifest_is_delete_marker(path) {
                    continue;
                }
                state.stale_versions += 1;
                let key = path
                    .strip_prefix(&versions_root)
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| path.display().to_string());
                state.push_issue(
                    "stale_version",
                    bucket,
                    &key,
                    "version manifest without data".to_string(),
                );
            }
        }

        state.version_contents_unverifiable += bin_stems
            .keys()
            .filter(|stem| json_stems.contains_key(*stem))
            .count() as u64;

        stack.extend(subdirs);
    }
}

fn manifest_is_delete_marker(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<Value>(&content) else {
        return false;
    };
    value
        .get("is_delete_marker")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn md5_hex(bytes: &[u8]) -> String {
        myfsio_crypto::hashing::md5_bytes(bytes)
    }

    fn multipart_fixture(parts: &[&[u8]]) -> (Vec<u8>, String, String) {
        let mut body = Vec::new();
        let mut digests = Vec::new();
        let mut sizes = Vec::new();
        for part in parts {
            body.extend_from_slice(part);
            digests.extend_from_slice(&Md5::digest(part));
            sizes.push(part.len() as u64);
        }
        (
            body,
            format!("{:x}-{}", Md5::digest(&digests), parts.len()),
            myfsio_storage::fs_backend::encode_part_sizes(&sizes),
        )
    }

    fn write_index(meta_dir: &Path, entries: &[(&str, &str)]) {
        fs::create_dir_all(meta_dir).unwrap();
        let mut map = Map::new();
        for (name, etag) in entries {
            map.insert(
                name.to_string(),
                json!({ "metadata": { "__etag__": etag } }),
            );
        }
        fs::write(
            meta_dir.join(INDEX_FILE),
            serde_json::to_string(&Value::Object(map)).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn encrypted_objects_are_not_flagged_corrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "encbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        fs::write(bucket_path.join("secret.bin"), b"ciphertext-bytes-on-disk").unwrap();

        let mut map = Map::new();
        map.insert(
            "secret.bin".to_string(),
            json!({
                "metadata": {
                    "__etag__": "00000000000000000000000000000000",
                    "x-amz-server-side-encryption": "AES256",
                    "x-amz-encryption-nonce": "abc",
                }
            }),
        );
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&Value::Object(map)).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.corrupted_objects, 0,
            "encrypted objects must be skipped by the corruption scan"
        );
    }

    #[test]
    fn scan_detects_each_issue_type() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();

        let clean_bytes = b"clean file contents";
        let clean_etag = md5_hex(clean_bytes);
        fs::write(bucket_path.join("clean.txt"), clean_bytes).unwrap();

        let corrupted_bytes = b"actual content";
        fs::write(bucket_path.join("corrupted.txt"), corrupted_bytes).unwrap();

        fs::write(bucket_path.join("orphan.txt"), b"no metadata").unwrap();

        write_index(
            &meta_root,
            &[
                ("clean.txt", &clean_etag),
                ("corrupted.txt", "00000000000000000000000000000000"),
                ("phantom.txt", "deadbeefdeadbeefdeadbeefdeadbeef"),
            ],
        );

        let versions_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_VERSIONS_DIR)
            .join("someobject");
        fs::create_dir_all(&versions_root).unwrap();
        fs::write(versions_root.join("v1.bin"), b"orphan bin").unwrap();
        fs::write(versions_root.join("v2.json"), b"{}").unwrap();

        let state = scan_all_buckets(root, 10_000, 0);

        assert_eq!(state.corrupted_objects, 1, "corrupted");
        assert_eq!(state.phantom_metadata, 1, "phantom");
        assert_eq!(state.orphaned_objects, 1, "orphaned");
        assert_eq!(state.stale_versions, 2, "stale versions");
        assert_eq!(state.buckets_scanned, 1);
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
    }

    #[test]
    fn scan_handles_collided_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let folder_dir = bucket_path.join("folder");
        fs::create_dir_all(&folder_dir).unwrap();

        let outer = b"outer value";
        let outer_etag = md5_hex(outer);
        fs::write(folder_dir.join(KEY_DATA_MARKER_FILE), outer).unwrap();

        let inner = b"inner value";
        let inner_etag = md5_hex(inner);
        fs::write(folder_dir.join("file"), inner).unwrap();

        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        write_index(&meta_root, &[("folder", &outer_etag)]);
        write_index(&meta_root.join("folder"), &[("file", &inner_etag)]);

        let state = scan_all_buckets(root, 10_000, 0);

        assert_eq!(
            state.corrupted_objects, 0,
            "marker should hash to stored etag: {:?}",
            state.errors
        );
        assert_eq!(state.phantom_metadata, 0, "no phantoms for collided keys");
        assert_eq!(
            state.orphaned_objects, 0,
            "marker file must not leak as orphan"
        );
        assert!(
            state.errors.is_empty(),
            "no errors expected: {:?}",
            state.errors
        );
    }

    #[test]
    fn skips_system_root_as_bucket() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join(SYSTEM_ROOT).join("config")).unwrap();
        let state = scan_all_buckets(tmp.path(), 100, 0);
        assert_eq!(state.buckets_scanned, 0);
    }

    #[test]
    fn poisoned_entries_are_skipped_during_corruption_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        let bytes = b"some bytes that wont match";
        fs::write(bucket_path.join("rotted.txt"), bytes).unwrap();

        let mut map = Map::new();
        map.insert(
            "rotted.txt".to_string(),
            json!({
                "metadata": {
                    "__etag__": "00000000000000000000000000000000",
                    "__corrupted__": "true",
                    "__corruption_detail__": "etag mismatch (already poisoned)",
                }
            }),
        );
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&Value::Object(map)).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.corrupted_objects, 0,
            "poisoned entries must not re-flag"
        );
    }

    #[test]
    fn delete_marker_manifests_are_not_flagged_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "vbucket";
        fs::create_dir_all(root.join(bucket)).unwrap();

        let versions_dir = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_VERSIONS_DIR)
            .join("v.txt");
        fs::create_dir_all(&versions_dir).unwrap();

        let dm = json!({
            "version_id": "dm-vid-1",
            "key": "v.txt",
            "size": 0,
            "etag": "",
            "is_delete_marker": true,
        });
        fs::write(
            versions_dir.join("dm-vid-1.json"),
            serde_json::to_string(&dm).unwrap(),
        )
        .unwrap();

        let truly_stale = json!({
            "version_id": "broken-vid-2",
            "key": "v.txt",
            "size": 12,
            "etag": "abc",
            "is_delete_marker": false,
        });
        fs::write(
            versions_dir.join("broken-vid-2.json"),
            serde_json::to_string(&truly_stale).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.stale_versions, 1,
            "delete-marker manifest must not be flagged; only the data-bearing orphan should count"
        );
    }

    #[test]
    fn parse_etag_helpers() {
        let detail = "stored_etag=abc123 actual_etag=def456";
        assert_eq!(parse_stored_etag(detail), "abc123");
    }

    #[test]
    fn heal_preview_reports_only_supported_actions() {
        let mut state = ScanState::default();
        state.push_issue(
            "corrupted_object",
            "bucket",
            "single.bin",
            "stored_etag=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa actual_etag=bbbb".to_string(),
        );
        state.push_issue(
            "corrupted_object",
            "bucket",
            "multi.bin",
            "stored_etag=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-2 actual_etag=bbbb-2".to_string(),
        );
        state.push_issue(
            "orphaned_object",
            "bucket",
            "orphan.bin",
            "file exists without metadata".to_string(),
        );

        let preview = preview_heal_phase(&state);
        assert_eq!(preview["corrupted_object"].found, 2);
        assert_eq!(preview["corrupted_object"].would_heal, 1);
        assert_eq!(preview["corrupted_object"].skipped, 1);
        assert_eq!(preview["orphaned_object"].would_heal, 0);
        assert_eq!(preview["orphaned_object"].skipped, 1);
    }

    #[test]
    fn malformed_cursor_is_reported_in_scan_results() {
        let tmp = tempfile::tempdir().unwrap();
        let cursor_path = cursor_path_for(tmp.path());
        std::fs::create_dir_all(cursor_path.parent().unwrap()).unwrap();
        std::fs::write(&cursor_path, b"not-json").unwrap();
        std::fs::create_dir_all(tmp.path().join("bucket")).unwrap();

        let state = scan_all_buckets(tmp.path(), 10, 0);
        assert!(state
            .errors
            .iter()
            .any(|error| error.contains("parse checksum cursor")));
        assert!(load_cursor(&cursor_path).is_ok());
    }

    #[test]
    fn poisoned_entry_with_missing_file_is_not_phantom() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        let mut map = Map::new();
        map.insert(
            "quarantined.txt".to_string(),
            json!({
                "metadata": {
                    "__etag__": "deadbeefdeadbeefdeadbeefdeadbeef",
                    "__corrupted__": "true",
                    "__corruption_detail__": "etag mismatch (no peer)",
                    "__quarantine_path__": ".myfsio.sys/quarantine/testbucket/2026/quarantined.txt",
                }
            }),
        );
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&Value::Object(map)).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.phantom_metadata, 0,
            "poisoned entries with quarantined files must not be reported as phantom metadata"
        );
        assert_eq!(state.poisoned_objects, 1);
        assert!(state
            .issues
            .iter()
            .any(|issue| issue["issue_type"] == "poisoned_object"));
        assert_eq!(state.corrupted_objects, 0);
    }

    #[test]
    fn invalid_metadata_key_cannot_escape_bucket() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(root.join(bucket)).unwrap();
        fs::create_dir_all(&meta_root).unwrap();
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&json!({
                "../outside.bin": {
                    "metadata": {"__etag__": "00000000000000000000000000000000"}
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(state.invalid_metadata_keys, 1);
        assert_eq!(state.corrupted_objects, 0);
        assert_eq!(state.phantom_metadata, 0);
        assert!(state
            .errors
            .iter()
            .any(|error| error.contains("invalid metadata key")));
    }

    #[test]
    fn poisoned_retry_order_prevents_failed_keys_from_starving_others() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(root.join(bucket)).unwrap();
        fs::create_dir_all(&meta_root).unwrap();
        let mut entries = Map::new();
        for index in 0..=MAX_ISSUES_PER_TYPE {
            let retries = if index == 0 { "10" } else { "0" };
            entries.insert(
                format!("item-{index:03}.bin"),
                json!({
                    "metadata": {
                        "__etag__": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "__corrupted__": "true",
                        "__corruption_retry_count__": retries,
                        "__corruption_last_retry_at__": if index == 0 { "later" } else { "earlier" },
                    }
                }),
            );
        }
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&Value::Object(entries)).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        let retried_keys: Vec<&str> = state
            .issues
            .iter()
            .filter(|issue| issue["issue_type"] == "poisoned_object")
            .filter_map(|issue| issue["key"].as_str())
            .collect();
        assert_eq!(retried_keys.len(), MAX_ISSUES_PER_TYPE);
        assert!(!retried_keys.contains(&"item-000.bin"));
        assert!(retried_keys.contains(&"item-100.bin"));
    }

    #[test]
    fn healthy_multipart_object_is_not_flagged_corrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();

        let (body, etag, part_sizes) = multipart_fixture(&[b"healthy ", b"multipart ", b"body"]);
        fs::write(bucket_path.join("multi.bin"), body).unwrap();
        fs::create_dir_all(&meta_root).unwrap();
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&json!({
                "multi.bin": {
                    "metadata": {
                        "__etag__": etag,
                        "__part_sizes__": part_sizes,
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.corrupted_objects, 0,
            "multipart objects must use their composite checksum"
        );
        assert_eq!(state.multipart_objects_checked, 1);
        assert_eq!(state.checksummed_objects, 1);
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
    }

    #[test]
    fn corrupted_multipart_object_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        let (mut body, etag, part_sizes) = multipart_fixture(&[b"first", b"second"]);
        body[0] ^= 0xff;
        fs::write(bucket_path.join("multi.bin"), body).unwrap();
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&json!({
                "multi.bin": {
                    "metadata": {
                        "__etag__": etag,
                        "__part_sizes__": part_sizes,
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(state.corrupted_objects, 1);
        assert_eq!(state.multipart_objects_checked, 1);
    }

    #[test]
    fn multipart_object_without_part_manifest_is_unverifiable_not_corrupted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        fs::write(
            bucket_path.join("legacy.bin"),
            b"body written by an older build",
        )
        .unwrap();
        write_index(
            &meta_root,
            &[("legacy.bin", "deadbeefdeadbeefdeadbeefdeadbeef-3")],
        );

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.corrupted_objects, 0,
            "a missing part-size manifest is not evidence of corruption"
        );
        assert_eq!(state.multipart_objects_unverifiable, 1);
        assert_eq!(state.multipart_objects_checked, 0);
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
    }

    #[test]
    fn truncated_multipart_data_is_reported_as_corruption() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "testbucket";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        let (body, etag, part_sizes) = multipart_fixture(&[b"first", b"second"]);
        fs::write(bucket_path.join("multi.bin"), &body[..body.len() - 2]).unwrap();
        fs::write(
            meta_root.join(INDEX_FILE),
            serde_json::to_string(&json!({
                "multi.bin": {
                    "metadata": {
                        "__etag__": etag,
                        "__part_sizes__": part_sizes,
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(state.corrupted_objects, 1);
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
    }

    #[test]
    fn healed_findings_are_not_reported_as_unresolved() {
        let result = json!({
            "phantom_metadata": 3,
            "legacy_metadata_drifts": 2,
            "issues_healed": 3,
        });
        assert_eq!(total_issue_count(&result), 5);
        assert_eq!(unresolved_issue_count(&result), 2);

        let fully_healed = json!({ "phantom_metadata": 3, "issues_healed": 3 });
        assert_eq!(unresolved_issue_count(&fully_healed), 0);
    }

    fn write_object(root: &Path, bucket: &str, key: &str, bytes: &[u8]) -> String {
        let etag = md5_hex(bytes);
        fs::write(root.join(bucket).join(key), bytes).unwrap();
        etag
    }

    fn seed_bucket_with_objects(root: &Path, bucket: &str, keys: &[&str]) {
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        let mut entries: Vec<(String, String)> = Vec::new();
        for k in keys {
            let etag = write_object(root, bucket, k, k.as_bytes());
            entries.push((k.to_string(), etag));
        }
        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(k, e)| (k.as_str(), e.as_str()))
            .collect();
        write_index(&meta_root, &pairs);
    }

    #[test]
    fn second_scan_skips_unchanged_verified_objects_without_using_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt", "b.txt"]);

        let first = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(first.checksummed_objects, 2);
        assert_eq!(first.checksum_skipped_unchanged, 0);

        let second = scan_all_buckets_with_reverify(root, 1, 0, 30);
        assert_eq!(second.checksummed_objects, 0);
        assert_eq!(second.checksum_skipped_unchanged, 2);
        let result = build_result_json(second, BTreeMap::new(), 0.0);
        assert_eq!(result["checksum_skipped_unchanged"], 2);
        let cursor = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(cursor.bucket, "");
        assert_eq!(cursor.after_key, "");
    }

    #[test]
    fn changed_mtime_or_size_forces_rehash() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt"]);
        let object_path = root.join("alpha").join("a.txt");

        let first = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(first.checksummed_objects, 1);

        let modified = fs::metadata(&object_path).unwrap().modified().unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&object_path)
            .unwrap();
        file.set_times(
            fs::FileTimes::new().set_modified(modified + std::time::Duration::from_secs(2)),
        )
        .unwrap();
        let touched = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(touched.checksummed_objects, 1);
        assert_eq!(touched.corrupted_objects, 0);

        let touched_mtime = fs::metadata(&object_path).unwrap().modified().unwrap();
        fs::write(&object_path, b"a.txt-expanded").unwrap();
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&object_path)
            .unwrap();
        file.set_times(fs::FileTimes::new().set_modified(touched_mtime))
            .unwrap();
        let resized = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(resized.checksummed_objects, 1);
        assert_eq!(resized.corrupted_objects, 1);
    }

    #[test]
    fn changed_stored_etag_forces_rehash() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt"]);

        let first = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(first.checksummed_objects, 1);

        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join("alpha")
            .join(BUCKET_META_DIR);
        write_index(&meta_root, &[("a.txt", "00000000000000000000000000000000")]);
        let changed = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(changed.checksummed_objects, 1);
        assert_eq!(changed.corrupted_objects, 1);
        let index = load_verified_index(&verified_index_path(root, "alpha"));
        assert!(!index.contains_key("a.txt"));
    }

    #[test]
    fn zero_reverify_days_always_rehashes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt"]);

        let first = scan_all_buckets_with_reverify(root, 10, 0, 0);
        let second = scan_all_buckets_with_reverify(root, 10, 0, 0);
        assert_eq!(first.checksummed_objects, 1);
        assert_eq!(second.checksummed_objects, 1);
        assert_eq!(second.checksum_skipped_unchanged, 0);
        assert!(!verified_index_path(root, "alpha").exists());
    }

    #[test]
    fn corrupt_verified_index_is_tolerated_and_rebuilt() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt"]);
        let index_path = verified_index_path(root, "alpha");
        fs::write(&index_path, b"not-json").unwrap();

        let rebuilt = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(rebuilt.checksummed_objects, 1);
        assert!(rebuilt.errors.is_empty());
        let index = load_verified_index(&index_path);
        assert!(index.contains_key("a.txt"));

        let cached = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(cached.checksummed_objects, 0);
        assert_eq!(cached.checksum_skipped_unchanged, 1);
    }

    #[test]
    fn deleted_objects_are_pruned_from_verified_index() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt", "b.txt"]);

        let first = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(first.checksummed_objects, 2);
        let index = load_verified_index(&verified_index_path(root, "alpha"));
        assert!(index.contains_key("a.txt"));
        assert!(index.contains_key("b.txt"));

        fs::remove_file(root.join("alpha").join("b.txt")).unwrap();
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join("alpha")
            .join(BUCKET_META_DIR);
        write_index(&meta_root, &[("a.txt", &md5_hex(b"a.txt"))]);

        let second = scan_all_buckets_with_reverify(root, 10, 0, 30);
        assert_eq!(second.checksum_skipped_unchanged, 1);
        let index = load_verified_index(&verified_index_path(root, "alpha"));
        assert!(index.contains_key("a.txt"));
        assert!(!index.contains_key("b.txt"));
    }

    #[test]
    fn cursor_advances_across_runs_when_budget_smaller_than_corpus() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(
            root,
            "alpha",
            &["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"],
        );

        let _ = scan_all_buckets(root, 2, 0);
        let cursor1 = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(cursor1.bucket, "alpha");
        assert_eq!(cursor1.after_key, "b.txt");

        let _ = scan_all_buckets(root, 2, 0);
        let cursor2 = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(cursor2.bucket, "alpha");
        assert_eq!(cursor2.after_key, "d.txt");

        let _ = scan_all_buckets(root, 2, 0);
        let cursor3 = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(
            cursor3.bucket, "",
            "completing a full sweep should reset the cursor"
        );
        assert_eq!(cursor3.after_key, "");
    }

    #[test]
    fn cursor_wraps_across_buckets_alphabetically() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["x.txt", "y.txt"]);
        seed_bucket_with_objects(root, "bravo", &["m.txt", "n.txt"]);

        let _ = scan_all_buckets(root, 3, 0);
        let c1 = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(c1.bucket, "bravo");
        assert_eq!(c1.after_key, "m.txt");

        let _ = scan_all_buckets(root, 3, 0);
        let c2 = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(c2.bucket, "", "second run should finish the sweep");
    }

    #[tokio::test]
    async fn bit_rot_is_detected_quarantined_and_reads_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let backend = FsStorageBackend::new(root.to_path_buf());
        backend.create_bucket("rot").await.unwrap();
        let pristine = b"pristine object content";
        let stream: myfsio_storage::traits::AsyncReadStream =
            Box::pin(std::io::Cursor::new(pristine.to_vec()));
        backend
            .put_object("rot", "victim.txt", stream, None)
            .await
            .unwrap();

        let rotten = b"rotted!! object content";
        assert_eq!(pristine.len(), rotten.len());
        fs::write(root.join("rot").join("victim.txt"), rotten).unwrap();

        let (meta, mut body_stream) = backend.get_object("rot", "victim.txt").await.unwrap();
        let mut served = Vec::new();
        use tokio::io::AsyncReadExt;
        body_stream.read_to_end(&mut served).await.unwrap();
        assert_eq!(
            served, rotten,
            "before a scan, rotten bytes are served (the documented gap)"
        );
        let stored_etag = meta.etag.clone().unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(state.corrupted_objects, 1, "the scan must detect the flip");
        let issue = state
            .issues
            .iter()
            .find(|i| i.get("issue_type").and_then(|v| v.as_str()) == Some("corrupted_object"))
            .expect("a corrupted_object issue must be reported");
        let detail = issue.get("detail").and_then(|v| v.as_str()).unwrap();
        assert_eq!(
            parse_stored_etag(detail),
            stored_etag,
            "the issue detail must carry the stored etag for healing"
        );

        let status = heal_corrupted(&backend, None, "rot", "victim.txt", detail).await;
        assert!(
            !matches!(status, HealStatus::Skipped),
            "healing a genuinely corrupted object must not be skipped"
        );

        match backend.get_object("rot", "victim.txt").await {
            Err(myfsio_storage::error::StorageError::ObjectCorrupted { .. }) => {}
            other => panic!(
                "a quarantined object must fail closed, got {:?}",
                other.map(|(m, _)| m.key)
            ),
        }

        let quarantine_root = root.join(SYSTEM_ROOT).join(QUARANTINE_DIR);
        let mut found_rotten_copy = false;
        let mut stack = vec![quarantine_root];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if fs::read(&path).map(|b| b == rotten).unwrap_or(false) {
                    found_rotten_copy = true;
                }
            }
        }
        assert!(
            found_rotten_copy,
            "the corrupted bytes must be preserved in quarantine for forensics"
        );
    }

    #[test]
    fn cursor_falls_back_when_recorded_bucket_is_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_bucket_with_objects(root, "alpha", &["a.txt", "b.txt"]);
        let cursor = CorruptionCursor {
            bucket: "ghost".to_string(),
            after_key: "zzz".to_string(),
        };
        save_cursor(&cursor_path_for(root), &cursor).unwrap();

        let state = scan_all_buckets(root, 100, 0);
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
        let after = load_cursor(&cursor_path_for(root)).unwrap();
        assert_eq!(
            after.bucket, "",
            "stale cursor should be reset after a complete sweep"
        );
    }

    #[test]
    fn phantom_storm_does_not_starve_corruption_issue_list() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "noisy";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();

        let mut entries: Vec<(String, String)> = Vec::new();
        for i in 0..(MAX_ISSUES_PER_TYPE + 50) {
            entries.push((
                format!("phantom-{:04}.txt", i),
                "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ));
        }
        let real_bytes = b"actual rotted contents";
        fs::write(bucket_path.join("rotted.txt"), real_bytes).unwrap();
        entries.push((
            "rotted.txt".to_string(),
            "00000000000000000000000000000000".to_string(),
        ));

        let pairs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(k, e)| (k.as_str(), e.as_str()))
            .collect();
        write_index(&meta_root, &pairs);

        let state = scan_all_buckets(root, 100_000, 0);

        let phantom_in_list = state
            .issues
            .iter()
            .filter(|i| i.get("issue_type").and_then(|v| v.as_str()) == Some("phantom_metadata"))
            .count();
        let corrupted_in_list = state
            .issues
            .iter()
            .filter(|i| i.get("issue_type").and_then(|v| v.as_str()) == Some("corrupted_object"))
            .count();

        assert_eq!(
            phantom_in_list, MAX_ISSUES_PER_TYPE,
            "phantom phase should be capped at the per-type limit"
        );
        assert_eq!(
            corrupted_in_list, 1,
            "corruption issue must still land even after phantom phase saturates its quota"
        );
        assert_eq!(state.corrupted_objects, 1);
    }

    #[test]
    fn cheap_phases_run_on_every_bucket_regardless_of_corruption_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket_a_path = root.join("alpha");
        let bucket_b_path = root.join("bravo");
        let meta_a = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join("alpha")
            .join(BUCKET_META_DIR);
        let meta_b = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join("bravo")
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_a_path).unwrap();
        fs::create_dir_all(&bucket_b_path).unwrap();

        write_index(
            &meta_a,
            &[("ghost-a.txt", "deadbeefdeadbeefdeadbeefdeadbeef")],
        );
        write_index(
            &meta_b,
            &[("ghost-b.txt", "deadbeefdeadbeefdeadbeefdeadbeef")],
        );

        let state = scan_all_buckets(root, 1, 0);
        assert_eq!(
            state.phantom_metadata, 2,
            "phantom-metadata phase must visit every bucket each run, not be gated by the corruption budget"
        );
        assert_eq!(state.buckets_scanned, 2);
    }

    #[test]
    fn legacy_per_key_meta_json_files_are_recognized_as_indexed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "ente";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR)
            .join("1580559962386438");
        fs::create_dir_all(bucket_path.join("1580559962386438")).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        let key = "1580559962386438/b82bb2e0-061c-4b54-9b7f-524fa2a1d374";
        let bytes = b"encrypted blob";
        let etag = md5_hex(bytes);
        fs::write(root.join(bucket).join(key), bytes).unwrap();

        let payload = json!({ "metadata": { "__etag__": etag } });
        fs::write(
            meta_root.join("b82bb2e0-061c-4b54-9b7f-524fa2a1d374.meta.json"),
            serde_json::to_string(&payload).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.orphaned_objects, 0,
            "legacy per-key .meta.json must count as indexed metadata"
        );
        assert_eq!(state.corrupted_objects, 0);
        assert_eq!(state.phantom_metadata, 0);
    }

    #[test]
    fn aggregate_index_takes_precedence_over_legacy_per_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "mixed";
        let bucket_path = root.join(bucket);
        let meta_root = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);
        fs::create_dir_all(&bucket_path).unwrap();
        fs::create_dir_all(&meta_root).unwrap();

        let bytes = b"hello";
        let real_etag = md5_hex(bytes);
        fs::write(bucket_path.join("a.txt"), bytes).unwrap();

        write_index(&meta_root, &[("a.txt", &real_etag)]);
        let stale = json!({ "metadata": { "__etag__": "00000000000000000000000000000000" } });
        fs::write(
            meta_root.join("a.txt.meta.json"),
            serde_json::to_string(&stale).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.corrupted_objects, 0,
            "aggregate index must win over legacy per-key file"
        );
        assert_eq!(state.orphaned_objects, 0);
    }

    #[test]
    fn legacy_meta_dir_at_bucket_root_is_recognized() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bucket = "older";
        let bucket_path = root.join(bucket);
        let legacy_meta = bucket_path.join(".meta");
        fs::create_dir_all(&legacy_meta).unwrap();

        let bytes = b"older bytes";
        let etag = md5_hex(bytes);
        fs::write(bucket_path.join("old.txt"), bytes).unwrap();

        let payload = json!({ "metadata": { "__etag__": etag } });
        fs::write(
            legacy_meta.join("old.txt.meta.json"),
            serde_json::to_string(&payload).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000, 0);
        assert_eq!(
            state.orphaned_objects, 0,
            "legacy <bucket>/.meta/<key>.meta.json must also count as indexed"
        );
        assert_eq!(state.corrupted_objects, 0);
    }
}
