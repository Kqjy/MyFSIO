use myfsio_common::constants::{
    BUCKET_META_DIR, BUCKET_VERSIONS_DIR, INDEX_FILE, SYSTEM_BUCKETS_DIR, SYSTEM_ROOT,
};
use myfsio_storage::fs_backend::FsStorageBackend;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

const MAX_ISSUES: usize = 500;
const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];

pub struct IntegrityConfig {
    pub interval_hours: f64,
    pub batch_size: usize,
    pub auto_heal: bool,
    pub dry_run: bool,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            interval_hours: 24.0,
            batch_size: 10_000,
            auto_heal: false,
            dry_run: false,
        }
    }
}

pub struct IntegrityService {
    #[allow(dead_code)]
    storage: Arc<FsStorageBackend>,
    storage_root: PathBuf,
    config: IntegrityConfig,
    running: Arc<RwLock<bool>>,
    started_at: Arc<RwLock<Option<Instant>>>,
    history: Arc<RwLock<Vec<Value>>>,
    history_path: PathBuf,
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

    fn into_json(self, elapsed: f64) -> Value {
        json!({
            "objects_scanned": self.objects_scanned,
            "buckets_scanned": self.buckets_scanned,
            "corrupted_objects": self.corrupted_objects,
            "orphaned_objects": self.orphaned_objects,
            "phantom_metadata": self.phantom_metadata,
            "stale_versions": self.stale_versions,
            "etag_cache_inconsistencies": self.etag_cache_inconsistencies,
            "issues_healed": 0,
            "issues": self.issues,
            "errors": self.errors,
            "execution_time_seconds": elapsed,
        })
    }
}

impl IntegrityService {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        storage_root: &Path,
        config: IntegrityConfig,
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
        let result =
            tokio::task::spawn_blocking(move || scan_all_buckets(&storage_root, batch_size))
                .await
                .unwrap_or_else(|e| {
                    let mut st = ScanState::default();
                    st.errors.push(format!("scan task failed: {}", e));
                    st
                });
        let elapsed = start.elapsed().as_secs_f64();

        *self.running.write().await = false;
        *self.started_at.write().await = None;

        let result_json = result.into_json(elapsed);

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
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                tracing::info!("Integrity check starting");
                match self.run_now(false, false).await {
                    Ok(result) => tracing::info!("Integrity check complete: {:?}", result),
                    Err(e) => tracing::warn!("Integrity check failed: {}", e),
                }
            }
        })
    }
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
        state.objects_scanned += 1;

        let Some(stored) = stored_etag(&info.entry) else {
            continue;
        };

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
}
