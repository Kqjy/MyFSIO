use myfsio_common::constants::{
    BUCKET_META_DIR, BUCKET_VERSIONS_DIR, INDEX_FILE, SYSTEM_BUCKETS_DIR, SYSTEM_ROOT,
};
use myfsio_storage::fs_backend::{
    is_multipart_etag, metadata_is_corrupted, FsStorageBackend, META_KEY_CORRUPTED,
    META_KEY_CORRUPTED_AT, META_KEY_CORRUPTION_DETAIL, META_KEY_QUARANTINE_PATH,
};
use myfsio_storage::traits::StorageEngine;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, Semaphore};

use crate::services::peer_fetch::{HealOutcome, PeerFetcher};

const MAX_ISSUES: usize = 500;
const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];
const QUARANTINE_DIR: &str = "quarantine";

pub struct IntegrityConfig {
    pub interval_hours: f64,
    pub batch_size: usize,
    pub auto_heal: bool,
    pub dry_run: bool,
    pub heal_concurrency: usize,
    pub quarantine_retention_days: u64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            interval_hours: 24.0,
            batch_size: 10_000,
            auto_heal: false,
            dry_run: false,
            heal_concurrency: 4,
            quarantine_retention_days: 7,
        }
    }
}

pub struct IntegrityService {
    storage: Arc<FsStorageBackend>,
    storage_root: PathBuf,
    config: IntegrityConfig,
    peer_fetcher: Option<Arc<PeerFetcher>>,
    running: Arc<RwLock<bool>>,
    started_at: Arc<RwLock<Option<Instant>>>,
    history: Arc<RwLock<Vec<Value>>>,
    history_path: PathBuf,
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
    etag_cache_inconsistencies: u64,
    issues: Vec<Value>,
    errors: Vec<String>,
}

impl ScanState {
    fn batch_exhausted(&self, batch_size: usize) -> bool {
        self.objects_scanned >= batch_size as u64
    }

    fn push_issue(&mut self, issue_type: &str, bucket: &str, key: &str, detail: String) {
        if self.issues.len() < MAX_ISSUES {
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
        config: IntegrityConfig,
        peer_fetcher: Option<Arc<PeerFetcher>>,
    ) -> Self {
        let history_path = storage_root
            .join(SYSTEM_ROOT)
            .join("config")
            .join("integrity_history.json");

        let history = if history_path.exists() {
            std::fs::read_to_string(&history_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| v.get("executions").and_then(|e| e.as_array().cloned()))
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        Self {
            storage,
            storage_root: storage_root.to_path_buf(),
            config,
            peer_fetcher,
            running: Arc::new(RwLock::new(false)),
            started_at: Arc::new(RwLock::new(None)),
            history: Arc::new(RwLock::new(history)),
            history_path,
        }
    }

    pub async fn status(&self) -> Value {
        let running = *self.running.read().await;
        let scan_elapsed_seconds = self
            .started_at
            .read()
            .await
            .as_ref()
            .map(|started| started.elapsed().as_secs_f64());
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
            "peer_heal_available": self.peer_fetcher.is_some(),
        })
    }

    pub async fn history(&self) -> Value {
        let history = self.history.read().await;
        let mut executions: Vec<Value> = history.iter().cloned().collect();
        executions.reverse();
        json!({ "executions": executions })
    }

    pub async fn run_now(&self, dry_run: bool, auto_heal: bool) -> Result<Value, String> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("Integrity check already running".to_string());
            }
            *running = true;
        }
        *self.started_at.write().await = Some(Instant::now());

        let start = Instant::now();
        let storage_root = self.storage_root.clone();
        let batch_size = self.config.batch_size;
        let scan_state =
            tokio::task::spawn_blocking(move || scan_all_buckets(&storage_root, batch_size))
                .await
                .unwrap_or_else(|e| {
                    let mut st = ScanState::default();
                    st.errors.push(format!("scan task failed: {}", e));
                    st
                });

        let heal_stats = if auto_heal && !dry_run {
            self.run_heal_phase(&scan_state).await
        } else {
            BTreeMap::new()
        };

        let elapsed = start.elapsed().as_secs_f64();

        *self.running.write().await = false;
        *self.started_at.write().await = None;

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
        self.save_history().await;

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

    async fn save_history(&self) {
        let history = self.history.read().await;
        let data = json!({ "executions": *history });
        if let Some(parent) = self.history_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &self.history_path,
            serde_json::to_string_pretty(&data).unwrap_or_default(),
        );
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
                match self.run_now(dry_run, auto_heal).await {
                    Ok(result) => tracing::info!("Integrity check complete: {:?}", result),
                    Err(e) => tracing::warn!("Integrity check failed: {}", e),
                }
            }
        })
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
        "corrupted_object" => {
            heal_corrupted(storage, storage_root, peer_fetcher, bucket, key, detail).await
        }
        "stale_version" => heal_stale_version(storage_root, bucket, key).await,
        "etag_cache_inconsistency" => heal_etag_cache(storage_root, bucket, key, detail).await,
        "phantom_metadata" => heal_phantom_metadata(storage, bucket, key).await,
        _ => HealStatus::Skipped,
    };
    HealReport {
        issue_type: issue_type.to_string(),
        status,
    }
}

async fn heal_corrupted(
    storage: &FsStorageBackend,
    storage_root: &Path,
    peer_fetcher: Option<&PeerFetcher>,
    bucket: &str,
    key: &str,
    detail: &str,
) -> HealStatus {
    let stored_etag = parse_stored_etag(detail);
    let actual_etag = parse_actual_etag(detail);

    let live_path = storage_root.join(bucket).join(key);
    let quarantine_rel = quarantine_relative_path(bucket, key);
    let quarantine_full = storage_root.join(&quarantine_rel);

    if let Some(parent) = quarantine_full.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!("Heal {}/{}: mkdir quarantine failed: {}", bucket, key, e);
            return HealStatus::Failed;
        }
    }

    {
        let _guard = storage.lock_object_write(bucket, key);
        if live_path.exists() {
            if let Err(e) = std::fs::rename(&live_path, &quarantine_full) {
                tracing::error!("Heal {}/{}: quarantine rename failed: {}", bucket, key, e);
                return HealStatus::Failed;
            }
        }
    }

    let quarantine_rel_str = quarantine_rel.to_string_lossy().replace('\\', "/");

    if !stored_etag.is_empty() {
        if let Some(fetcher) = peer_fetcher {
            let nonce = uuid::Uuid::new_v4().simple().to_string();
            let temp_path = live_path.with_file_name(format!(
                "{}.healing.{}",
                live_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "healing".to_string()),
                nonce
            ));
            match fetcher
                .fetch_for_heal(bucket, key, &stored_etag, &temp_path)
                .await
            {
                HealOutcome::Healed { peer_etag, bytes } => {
                    let swap_result = {
                        let _guard = storage.lock_object_write(bucket, key);
                        if live_path.exists() {
                            let _ = std::fs::remove_file(&temp_path);
                            tracing::info!(
                                "Heal {}/{}: concurrent PUT raced; preserving fresh write",
                                bucket,
                                key
                            );
                            return HealStatus::Skipped;
                        }
                        atomic_swap(&temp_path, &live_path)
                    };
                    if let Err(e) = swap_result {
                        tracing::error!(
                            "Heal {}/{}: atomic swap failed: {} (restoring from quarantine)",
                            bucket,
                            key,
                            e
                        );
                        let _guard = storage.lock_object_write(bucket, key);
                        if !live_path.exists() {
                            let _ = std::fs::rename(&quarantine_full, &live_path);
                        }
                        let _ = std::fs::remove_file(&temp_path);
                        return HealStatus::Failed;
                    }
                    let _ = clear_poison_metadata(storage, bucket, key).await;
                    tracing::info!(
                        "Healed {}/{} from peer (etag={}, bytes={})",
                        bucket,
                        key,
                        peer_etag,
                        bytes
                    );
                    return HealStatus::Healed;
                }
                HealOutcome::PeerMismatch { stored, peer } => {
                    let msg = format!("peer etag {} != stored {}", peer, stored);
                    let _ = poison_metadata(storage, bucket, key, &msg, &quarantine_rel_str).await;
                    tracing::warn!("Heal {}/{}: peer mismatch ({}), poisoned", bucket, key, msg);
                    return HealStatus::PeerMismatch;
                }
                HealOutcome::PeerUnavailable { error } => {
                    tracing::warn!(
                        "Heal {}/{}: peer unavailable ({}), poisoning",
                        bucket,
                        key,
                        error
                    );
                    let msg = format!(
                        "etag mismatch (stored={}, actual={}) — peer unavailable: {}",
                        stored_etag, actual_etag, error
                    );
                    let _ = poison_metadata(storage, bucket, key, &msg, &quarantine_rel_str).await;
                    return HealStatus::PeerUnavailable;
                }
                HealOutcome::VerifyFailed { expected, actual } => {
                    let msg = format!(
                        "peer download verify failed: expected={} actual={}",
                        expected, actual
                    );
                    let _ = poison_metadata(storage, bucket, key, &msg, &quarantine_rel_str).await;
                    tracing::warn!("Heal {}/{}: {}", bucket, key, msg);
                    return HealStatus::VerifyFailed;
                }
                HealOutcome::NotConfigured => {
                    let msg = format!(
                        "etag mismatch (stored={}, actual={}); no peer configured",
                        stored_etag, actual_etag
                    );
                    let _ = poison_metadata(storage, bucket, key, &msg, &quarantine_rel_str).await;
                    return HealStatus::Poisoned;
                }
            }
        }
    }

    let msg = format!(
        "etag mismatch (stored={}, actual={}); no peer fetcher",
        stored_etag, actual_etag
    );
    let _ = poison_metadata(storage, bucket, key, &msg, &quarantine_rel_str).await;
    HealStatus::Poisoned
}

async fn heal_stale_version(storage_root: &Path, bucket: &str, key: &str) -> HealStatus {
    let versions_root = storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join(BUCKET_VERSIONS_DIR);
    let src = versions_root.join(key);
    if !src.exists() {
        return HealStatus::Skipped;
    }
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string();
    let dst = storage_root
        .join(SYSTEM_ROOT)
        .join(QUARANTINE_DIR)
        .join(bucket)
        .join(&ts)
        .join("versions")
        .join(key);
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
}

async fn heal_etag_cache(
    storage_root: &Path,
    bucket: &str,
    key: &str,
    _detail: &str,
) -> HealStatus {
    let etag_index_path = storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join("etag_index.json");
    if !etag_index_path.exists() {
        return HealStatus::Skipped;
    }

    let meta_root = storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join(BUCKET_META_DIR);
    let entries = collect_index_entries(&meta_root);
    let canonical = entries.get(key).and_then(|info| stored_etag(&info.entry));

    let mut cache: HashMap<String, Value> = match std::fs::read_to_string(&etag_index_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(Value::Object(m)) => m.into_iter().collect(),
        _ => return HealStatus::Failed,
    };

    match canonical {
        Some(etag) => {
            cache.insert(key.to_string(), Value::String(etag));
        }
        None => {
            cache.remove(key);
        }
    }

    let json_obj: serde_json::Map<String, Value> = cache.into_iter().collect();
    match std::fs::write(
        &etag_index_path,
        serde_json::to_string_pretty(&Value::Object(json_obj)).unwrap_or_default(),
    ) {
        Ok(_) => HealStatus::Healed,
        Err(e) => {
            tracing::error!("etag-cache rewrite failed {}/{}: {}", bucket, key, e);
            HealStatus::Failed
        }
    }
}

async fn heal_phantom_metadata(storage: &FsStorageBackend, bucket: &str, key: &str) -> HealStatus {
    match storage.delete_object_metadata_entry(bucket, key).await {
        Ok(_) => {
            tracing::info!("Dropped phantom metadata for {}/{}", bucket, key);
            HealStatus::Healed
        }
        Err(e) => {
            tracing::error!("Failed to drop phantom metadata {}/{}: {}", bucket, key, e);
            HealStatus::Failed
        }
    }
}

async fn poison_metadata(
    storage: &FsStorageBackend,
    bucket: &str,
    key: &str,
    detail: &str,
    quarantine_rel: &str,
) -> Result<(), String> {
    let mut meta = storage
        .get_object_metadata(bucket, key)
        .await
        .unwrap_or_default();
    meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
    meta.insert(
        META_KEY_CORRUPTED_AT.to_string(),
        chrono::Utc::now().to_rfc3339(),
    );
    meta.insert(META_KEY_CORRUPTION_DETAIL.to_string(), detail.to_string());
    meta.insert(
        META_KEY_QUARANTINE_PATH.to_string(),
        quarantine_rel.to_string(),
    );
    storage
        .put_object_metadata(bucket, key, &meta)
        .await
        .map_err(|e| e.to_string())
}

async fn clear_poison_metadata(
    storage: &FsStorageBackend,
    bucket: &str,
    key: &str,
) -> Result<(), String> {
    let mut meta = storage
        .get_object_metadata(bucket, key)
        .await
        .unwrap_or_default();
    meta.remove(META_KEY_CORRUPTED);
    meta.remove(META_KEY_CORRUPTED_AT);
    meta.remove(META_KEY_CORRUPTION_DETAIL);
    meta.remove(META_KEY_QUARANTINE_PATH);
    storage
        .put_object_metadata(bucket, key, &meta)
        .await
        .map_err(|e| e.to_string())
}

fn quarantine_relative_path(bucket: &str, key: &str) -> PathBuf {
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S").to_string();
    PathBuf::from(SYSTEM_ROOT)
        .join(QUARANTINE_DIR)
        .join(bucket)
        .join(ts)
        .join(key)
}

fn atomic_swap(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(src, dst)
}

fn parse_stored_etag(detail: &str) -> String {
    detail
        .split_whitespace()
        .find_map(|s| s.strip_prefix("stored_etag="))
        .unwrap_or("")
        .to_string()
}

fn parse_actual_etag(detail: &str) -> String {
    detail
        .split_whitespace()
        .find_map(|s| s.strip_prefix("actual_etag="))
        .unwrap_or("")
        .to_string()
}

fn build_result_json(
    state: ScanState,
    heal_stats: BTreeMap<String, HealStats>,
    elapsed: f64,
) -> Value {
    let issues_healed: u64 = heal_stats.values().map(|s| s.healed).sum();
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
        "etag_cache_inconsistencies": state.etag_cache_inconsistencies,
        "issues_healed": issues_healed,
        "heal_stats": Value::Object(heal_stats_json),
        "issues": state.issues,
        "errors": state.errors,
        "execution_time_seconds": elapsed,
    })
}

fn scan_all_buckets(storage_root: &Path, batch_size: usize) -> ScanState {
    let mut state = ScanState::default();
    let buckets = match list_bucket_names(storage_root) {
        Ok(b) => b,
        Err(e) => {
            state.errors.push(format!("list buckets: {}", e));
            return state;
        }
    };

    for bucket in &buckets {
        if state.batch_exhausted(batch_size) {
            break;
        }
        state.buckets_scanned += 1;

        let bucket_path = storage_root.join(bucket);
        let meta_root = storage_root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join(BUCKET_META_DIR);

        let index_entries = collect_index_entries(&meta_root);

        check_corrupted(&mut state, bucket, &bucket_path, &index_entries, batch_size);
        check_phantom(&mut state, bucket, &bucket_path, &index_entries, batch_size);
        check_orphaned(&mut state, bucket, &bucket_path, &index_entries, batch_size);
        check_stale_versions(&mut state, storage_root, bucket, batch_size);
        check_etag_cache(&mut state, storage_root, bucket, &index_entries, batch_size);
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

fn collect_index_entries(meta_root: &Path) -> HashMap<String, IndexEntryInfo> {
    let mut out: HashMap<String, IndexEntryInfo> = HashMap::new();
    if !meta_root.exists() {
        return out;
    }

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
            if entry.file_name().to_string_lossy() != INDEX_FILE {
                continue;
            }
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
                out.insert(
                    full_key,
                    IndexEntryInfo {
                        entry: entry_val,
                        index_file: path.clone(),
                        key_name,
                    },
                );
            }
        }
    }
    out
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

fn check_corrupted(
    state: &mut ScanState,
    bucket: &str,
    bucket_path: &Path,
    entries: &HashMap<String, IndexEntryInfo>,
    batch_size: usize,
) {
    let mut keys: Vec<&String> = entries.keys().collect();
    keys.sort();

    for full_key in keys {
        if state.batch_exhausted(batch_size) {
            return;
        }
        let info = &entries[full_key];
        let object_path = bucket_path.join(full_key);
        if !object_path.exists() {
            continue;
        }
        let meta_map = entry_metadata_map(&info.entry);
        if metadata_is_corrupted(&meta_map) {
            continue;
        }
        state.objects_scanned += 1;

        let Some(stored) = stored_etag(&info.entry) else {
            continue;
        };

        if is_multipart_etag(&stored) {
            continue;
        }

        match myfsio_crypto::hashing::md5_file(&object_path) {
            Ok(actual) => {
                if actual != stored {
                    state.corrupted_objects += 1;
                    state.push_issue(
                        "corrupted_object",
                        bucket,
                        full_key,
                        format!("stored_etag={} actual_etag={}", stored, actual),
                    );
                }
            }
            Err(e) => state
                .errors
                .push(format!("hash {}/{}: {}", bucket, full_key, e)),
        }
    }
}

fn check_phantom(
    state: &mut ScanState,
    bucket: &str,
    bucket_path: &Path,
    entries: &HashMap<String, IndexEntryInfo>,
    batch_size: usize,
) {
    let mut keys: Vec<&String> = entries.keys().collect();
    keys.sort();

    for full_key in keys {
        if state.batch_exhausted(batch_size) {
            return;
        }
        let info = &entries[full_key];
        if metadata_is_corrupted(&entry_metadata_map(&info.entry)) {
            continue;
        }
        state.objects_scanned += 1;
        let object_path = bucket_path.join(full_key);
        if !object_path.exists() {
            state.phantom_metadata += 1;
            state.push_issue(
                "phantom_metadata",
                bucket,
                full_key,
                "metadata entry without file on disk".to_string(),
            );
        }
    }
}

fn check_orphaned(
    state: &mut ScanState,
    bucket: &str,
    bucket_path: &Path,
    entries: &HashMap<String, IndexEntryInfo>,
    batch_size: usize,
) {
    let indexed: HashSet<&String> = entries.keys().collect();
    let mut stack: Vec<(PathBuf, String)> = vec![(bucket_path.to_path_buf(), String::new())];

    while let Some((dir, prefix)) = stack.pop() {
        if state.batch_exhausted(batch_size) {
            return;
        }
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            if state.batch_exhausted(batch_size) {
                return;
            }
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
                let full_key = if prefix.is_empty() {
                    name
                } else {
                    format!("{}/{}", prefix, name)
                };
                state.objects_scanned += 1;
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
    batch_size: usize,
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
        if state.batch_exhausted(batch_size) {
            return;
        }
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
            if state.batch_exhausted(batch_size) {
                return;
            }
            state.objects_scanned += 1;
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
            if state.batch_exhausted(batch_size) {
                return;
            }
            state.objects_scanned += 1;
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

fn check_etag_cache(
    state: &mut ScanState,
    storage_root: &Path,
    bucket: &str,
    entries: &HashMap<String, IndexEntryInfo>,
    batch_size: usize,
) {
    let etag_index_path = storage_root
        .join(SYSTEM_ROOT)
        .join(SYSTEM_BUCKETS_DIR)
        .join(bucket)
        .join("etag_index.json");
    if !etag_index_path.exists() {
        return;
    }

    let cache: HashMap<String, Value> = match std::fs::read_to_string(&etag_index_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(Value::Object(m)) => m.into_iter().collect(),
        _ => return,
    };

    for (full_key, cached_val) in cache {
        if state.batch_exhausted(batch_size) {
            return;
        }
        state.objects_scanned += 1;
        let Some(cached_etag) = cached_val.as_str() else {
            continue;
        };
        let Some(info) = entries.get(&full_key) else {
            continue;
        };
        let Some(stored) = stored_etag(&info.entry) else {
            continue;
        };
        if cached_etag != stored {
            state.etag_cache_inconsistencies += 1;
            state.push_issue(
                "etag_cache_inconsistency",
                bucket,
                &full_key,
                format!("cached_etag={} index_etag={}", cached_etag, stored),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn md5_hex(bytes: &[u8]) -> String {
        myfsio_crypto::hashing::md5_bytes(bytes)
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

        let etag_index = root
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join(bucket)
            .join("etag_index.json");
        fs::write(
            &etag_index,
            serde_json::to_string(&json!({ "clean.txt": "stale-cached-etag" })).unwrap(),
        )
        .unwrap();

        let state = scan_all_buckets(root, 10_000);

        assert_eq!(state.corrupted_objects, 1, "corrupted");
        assert_eq!(state.phantom_metadata, 1, "phantom");
        assert_eq!(state.orphaned_objects, 1, "orphaned");
        assert_eq!(state.stale_versions, 2, "stale versions");
        assert_eq!(state.etag_cache_inconsistencies, 1, "etag cache");
        assert_eq!(state.buckets_scanned, 1);
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
    }

    #[test]
    fn skips_system_root_as_bucket() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join(SYSTEM_ROOT).join("config")).unwrap();
        let state = scan_all_buckets(tmp.path(), 100);
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

        let state = scan_all_buckets(root, 10_000);
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

        let state = scan_all_buckets(root, 10_000);
        assert_eq!(
            state.stale_versions, 1,
            "delete-marker manifest must not be flagged; only the data-bearing orphan should count"
        );
    }

    #[test]
    fn parse_etag_helpers() {
        let detail = "stored_etag=abc123 actual_etag=def456";
        assert_eq!(parse_stored_etag(detail), "abc123");
        assert_eq!(parse_actual_etag(detail), "def456");
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

        let state = scan_all_buckets(root, 10_000);
        assert_eq!(
            state.phantom_metadata, 0,
            "poisoned entries with quarantined files must not be reported as phantom metadata"
        );
        assert_eq!(state.corrupted_objects, 0);
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

        fs::write(bucket_path.join("multi.bin"), b"healthy multipart body").unwrap();

        write_index(
            &meta_root,
            &[("multi.bin", "deadbeefdeadbeefdeadbeefdeadbeef-3")],
        );

        let state = scan_all_buckets(root, 10_000);
        assert_eq!(
            state.corrupted_objects, 0,
            "multipart-style ETags must not be checked against whole-body MD5"
        );
        assert!(
            state.errors.is_empty(),
            "unexpected errors: {:?}",
            state.errors
        );
    }
}
