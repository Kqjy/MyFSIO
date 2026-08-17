use myfsio_common::constants::{BUCKET_META_DIR, SYSTEM_BUCKETS_DIR, SYSTEM_ROOT};
use myfsio_storage::fs_backend::META_KEY_QUARANTINE_PATH;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::sync::RwLock;

const LEGACY_BUCKET_META_DIR: &str = ".meta";
const QUARANTINE_DIR: &str = "quarantine";

pub struct GcConfig {
    pub interval_hours: f64,
    pub temp_file_max_age_hours: f64,
    pub multipart_max_age_days: u64,
    pub lock_file_max_age_hours: f64,
    pub quarantine_max_age_days: u64,
    pub segment_max_age_hours: f64,
    pub dry_run: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            interval_hours: 6.0,
            temp_file_max_age_hours: 24.0,
            multipart_max_age_days: 7,
            lock_file_max_age_hours: 1.0,
            quarantine_max_age_days: 7,
            segment_max_age_hours: 24.0,
            dry_run: false,
        }
    }
}

pub struct GcService {
    storage_root: PathBuf,
    config: GcConfig,
    running: Arc<AtomicBool>,
    started_at: Arc<StdMutex<Option<Instant>>>,
    history: Arc<RwLock<Vec<Value>>>,
    history_path: PathBuf,
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

impl GcService {
    pub fn new(storage_root: PathBuf, config: GcConfig) -> Self {
        let history_path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("gc_history.json");

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
            storage_root,
            config,
            running: Arc::new(AtomicBool::new(false)),
            started_at: Arc::new(StdMutex::new(None)),
            history: Arc::new(RwLock::new(history)),
            history_path,
        }
    }

    pub async fn status(&self) -> Value {
        let running = self.running.load(Ordering::SeqCst);
        let scan_elapsed_seconds = self.started_at.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .map(|started| started.elapsed().as_secs_f64())
        });
        json!({
            "enabled": true,
            "running": running,
            "scanning": running,
            "scan_elapsed_seconds": scan_elapsed_seconds,
            "interval_hours": self.config.interval_hours,
            "temp_file_max_age_hours": self.config.temp_file_max_age_hours,
            "multipart_max_age_days": self.config.multipart_max_age_days,
            "lock_file_max_age_hours": self.config.lock_file_max_age_hours,
            "quarantine_max_age_days": self.config.quarantine_max_age_days,
            "segment_max_age_hours": self.config.segment_max_age_hours,
            "dry_run": self.config.dry_run,
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
            return Err("GC already running".to_string());
        }
        if let Ok(mut guard) = self.started_at.lock() {
            *guard = Some(Instant::now());
        }
        Ok(())
    }

    pub async fn run_now(self: Arc<Self>, dry_run: bool) -> Result<Value, String> {
        self.try_claim()?;
        let svc = self.clone();
        let handle = tokio::spawn(async move {
            let _guard = RunGuard {
                running: svc.running.clone(),
                started_at: svc.started_at.clone(),
            };
            svc.execute(dry_run).await
        });
        handle
            .await
            .unwrap_or_else(|e| Err(format!("GC task aborted: {}", e)))
    }

    pub fn start_run(self: Arc<Self>, dry_run: bool) -> Result<(), String> {
        self.try_claim()?;
        let svc = self.clone();
        tokio::spawn(async move {
            let _guard = RunGuard {
                running: svc.running.clone(),
                started_at: svc.started_at.clone(),
            };
            if let Err(e) = svc.execute(dry_run).await {
                tracing::warn!("GC cycle failed: {}", e);
            }
        });
        Ok(())
    }

    async fn execute(&self, dry_run: bool) -> Result<Value, String> {
        let start = Instant::now();
        let result = self.execute_gc(dry_run || self.config.dry_run).await;
        let elapsed = start.elapsed().as_secs_f64();

        let mut result_json = result.clone();
        if let Some(obj) = result_json.as_object_mut() {
            obj.insert("execution_time_seconds".to_string(), json!(elapsed));
        }

        let record = json!({
            "timestamp": chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            "dry_run": dry_run || self.config.dry_run,
            "result": result_json,
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

        Ok(result)
    }

    async fn execute_gc(&self, dry_run: bool) -> Value {
        let mut temp_files_deleted = 0u64;
        let mut temp_bytes_freed = 0u64;
        let mut multipart_uploads_deleted = 0u64;
        let mut lock_files_deleted = 0u64;
        let mut empty_dirs_removed = 0u64;
        let mut quarantine_entries_deleted = 0u64;
        let mut quarantine_entries_protected = 0u64;
        let mut quarantine_bytes_freed = 0u64;
        let mut errors: Vec<String> = Vec::new();

        let now = std::time::SystemTime::now();
        let temp_max_age =
            std::time::Duration::from_secs_f64(self.config.temp_file_max_age_hours * 3600.0);
        let multipart_max_age =
            std::time::Duration::from_secs(self.config.multipart_max_age_days * 86400);
        let lock_max_age =
            std::time::Duration::from_secs_f64(self.config.lock_file_max_age_hours * 3600.0);
        let quarantine_max_age =
            std::time::Duration::from_secs(self.config.quarantine_max_age_days * 86400);

        let tmp_dir = self.storage_root.join(".myfsio.sys").join("tmp");
        if tmp_dir.exists() {
            match std::fs::read_dir(&tmp_dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if entry
                            .file_name()
                            .to_string_lossy()
                            .ends_with(".sidecar-stage")
                        {
                            continue;
                        }
                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(modified) = metadata.modified() {
                                if let Ok(age) = now.duration_since(modified) {
                                    if age > temp_max_age {
                                        let size = metadata.len();
                                        if !dry_run {
                                            if let Err(e) = std::fs::remove_file(entry.path()) {
                                                errors.push(format!(
                                                    "Failed to remove temp file: {}",
                                                    e
                                                ));
                                                continue;
                                            }
                                        }
                                        temp_files_deleted += 1;
                                        temp_bytes_freed += size;
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => errors.push(format!("Failed to read tmp dir: {}", e)),
            }
        }

        let multipart_dir = self.storage_root.join(".myfsio.sys").join("multipart");
        if multipart_dir.exists() {
            if let Ok(bucket_dirs) = std::fs::read_dir(&multipart_dir) {
                for bucket_entry in bucket_dirs.flatten() {
                    if let Ok(uploads) = std::fs::read_dir(bucket_entry.path()) {
                        for upload in uploads.flatten() {
                            if let Ok(metadata) = upload.metadata() {
                                if let Ok(modified) = metadata.modified() {
                                    if let Ok(age) = now.duration_since(modified) {
                                        if age > multipart_max_age {
                                            if !dry_run {
                                                let _ = std::fs::remove_dir_all(upload.path());
                                            }
                                            multipart_uploads_deleted += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let buckets_dir = self.storage_root.join(".myfsio.sys").join("buckets");
        if buckets_dir.exists() {
            if let Ok(bucket_dirs) = std::fs::read_dir(&buckets_dir) {
                for bucket_entry in bucket_dirs.flatten() {
                    let locks_dir = bucket_entry.path().join("locks");
                    if locks_dir.exists() {
                        if let Ok(locks) = std::fs::read_dir(&locks_dir) {
                            for lock in locks.flatten() {
                                if let Ok(metadata) = lock.metadata() {
                                    if let Ok(modified) = metadata.modified() {
                                        if let Ok(age) = now.duration_since(modified) {
                                            if age > lock_max_age {
                                                if !dry_run {
                                                    let _ = std::fs::remove_file(lock.path());
                                                }
                                                lock_files_deleted += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let quarantine_dir = self.storage_root.join(SYSTEM_ROOT).join(QUARANTINE_DIR);
        let mut quarantine_references: Option<(HashSet<String>, bool)> = None;
        if quarantine_dir.exists() {
            if let Ok(bucket_dirs) = std::fs::read_dir(&quarantine_dir) {
                for bucket_entry in bucket_dirs.flatten() {
                    if !bucket_entry.path().is_dir() {
                        continue;
                    }
                    if let Ok(ts_dirs) = std::fs::read_dir(bucket_entry.path()) {
                        for ts_entry in ts_dirs.flatten() {
                            let ts_path = ts_entry.path();
                            if !ts_path.is_dir() {
                                continue;
                            }
                            let modified = ts_entry.metadata().ok().and_then(|m| m.modified().ok());
                            let Some(modified) = modified else {
                                continue;
                            };
                            let Ok(age) = now.duration_since(modified) else {
                                continue;
                            };
                            if age <= quarantine_max_age {
                                continue;
                            }
                            let (references, scan_ok) =
                                quarantine_references.get_or_insert_with(|| {
                                    let (references, mut reference_errors) =
                                        collect_quarantine_references(&self.storage_root);
                                    let scan_ok = reference_errors.is_empty();
                                    errors.append(&mut reference_errors);
                                    (references, scan_ok)
                                });
                            let relative = ts_path
                                .strip_prefix(&self.storage_root)
                                .map(|path| path.to_string_lossy().replace('\\', "/"))
                                .ok();
                            let protected = !*scan_ok
                                || match relative {
                                    None => true,
                                    Some(relative) => references.iter().any(|reference| {
                                        reference == &relative
                                            || reference.starts_with(&format!("{relative}/"))
                                    }),
                                };
                            if protected {
                                quarantine_entries_protected += 1;
                                continue;
                            }
                            let bytes = dir_total_bytes(&ts_path);
                            if !dry_run {
                                if let Err(e) = std::fs::remove_dir_all(&ts_path) {
                                    errors.push(format!(
                                        "Failed to remove quarantine {}: {}",
                                        ts_path.display(),
                                        e
                                    ));
                                    continue;
                                }
                            }
                            quarantine_entries_deleted += 1;
                            quarantine_bytes_freed += bytes;
                        }
                    }
                    if !dry_run {
                        if let Ok(mut remaining) = std::fs::read_dir(bucket_entry.path()) {
                            if remaining.next().is_none() {
                                let _ = std::fs::remove_dir(bucket_entry.path());
                            }
                        }
                    }
                }
            }
        }

        let mut segment_dirs_deleted = 0u64;
        let mut segment_bytes_freed = 0u64;
        let segment_max_age =
            std::time::Duration::from_secs_f64(self.config.segment_max_age_hours * 3600.0);
        if buckets_dir.exists() {
            if let Ok(bucket_dirs) = std::fs::read_dir(&buckets_dir) {
                for bucket_entry in bucket_dirs.flatten() {
                    let segments_dir = bucket_entry.path().join("segments");
                    if !segments_dir.is_dir() {
                        continue;
                    }
                    let bucket_name = bucket_entry.file_name().to_string_lossy().to_string();
                    let mut referenced: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    let mut scan_errors = collect_segment_refs(
                        &self.storage_root.join(&bucket_name),
                        &mut referenced,
                    );
                    scan_errors.extend(collect_segment_refs(
                        &bucket_entry.path().join("versions"),
                        &mut referenced,
                    ));
                    if !scan_errors.is_empty() {
                        let detail = scan_errors.join("; ");
                        tracing::warn!(
                            "Skipping segment sweep for bucket {}: reference scan incomplete: {}",
                            bucket_name,
                            detail
                        );
                        errors.push(format!(
                            "Skipped segment sweep for bucket {}: reference scan incomplete: {}",
                            bucket_name, detail
                        ));
                        continue;
                    }
                    if let Ok(seg_dirs) = std::fs::read_dir(&segments_dir) {
                        for seg_entry in seg_dirs.flatten() {
                            let seg_path = seg_entry.path();
                            if !seg_path.is_dir() {
                                continue;
                            }
                            let seg_id = seg_entry.file_name().to_string_lossy().to_string();
                            if referenced.contains(&seg_id) {
                                continue;
                            }
                            let Some(modified) =
                                seg_entry.metadata().ok().and_then(|m| m.modified().ok())
                            else {
                                continue;
                            };
                            let Ok(age) = now.duration_since(modified) else {
                                continue;
                            };
                            if age <= segment_max_age {
                                continue;
                            }
                            let bytes = dir_total_bytes(&seg_path);
                            if !dry_run {
                                if let Err(e) = std::fs::remove_dir_all(&seg_path) {
                                    errors.push(format!(
                                        "Failed to remove orphaned segment dir {}: {}",
                                        seg_path.display(),
                                        e
                                    ));
                                    continue;
                                }
                            }
                            segment_dirs_deleted += 1;
                            segment_bytes_freed += bytes;
                        }
                    }
                }
            }
        }

        if !dry_run {
            for dir in [&tmp_dir, &multipart_dir] {
                if dir.exists() {
                    if let Ok(entries) = std::fs::read_dir(dir) {
                        for entry in entries.flatten() {
                            if entry.path().is_dir() {
                                if let Ok(mut contents) = std::fs::read_dir(entry.path()) {
                                    if contents.next().is_none() {
                                        let _ = std::fs::remove_dir(entry.path());
                                        empty_dirs_removed += 1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        json!({
            "temp_files_deleted": temp_files_deleted,
            "temp_bytes_freed": temp_bytes_freed,
            "multipart_uploads_deleted": multipart_uploads_deleted,
            "lock_files_deleted": lock_files_deleted,
            "empty_dirs_removed": empty_dirs_removed,
            "quarantine_entries_deleted": quarantine_entries_deleted,
            "quarantine_entries_protected": quarantine_entries_protected,
            "quarantine_bytes_freed": quarantine_bytes_freed,
            "segment_dirs_deleted": segment_dirs_deleted,
            "segment_bytes_freed": segment_bytes_freed,
            "total_bytes_freed": temp_bytes_freed
                .saturating_add(quarantine_bytes_freed)
                .saturating_add(segment_bytes_freed),
            "errors": errors,
        })
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
                tracing::info!("GC cycle starting");
                match Arc::clone(&self).run_now(false).await {
                    Ok(result) => tracing::info!("GC cycle complete: {:?}", result),
                    Err(e) => tracing::warn!("GC cycle failed: {}", e),
                }
            }
        })
    }
}

fn collect_quarantine_references(storage_root: &std::path::Path) -> (HashSet<String>, Vec<String>) {
    let mut metadata_roots: HashSet<PathBuf> = HashSet::new();
    let mut errors = Vec::new();
    let modern_buckets = storage_root.join(SYSTEM_ROOT).join(SYSTEM_BUCKETS_DIR);
    if modern_buckets.exists() {
        match std::fs::read_dir(&modern_buckets) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry) if entry.path().is_dir() => {
                            metadata_roots.insert(entry.path().join(BUCKET_META_DIR));
                        }
                        Ok(_) => {}
                        Err(error) => errors.push(format!(
                            "failed to enumerate modern metadata roots: {error}"
                        )),
                    }
                }
            }
            Err(error) => errors.push(format!(
                "failed to inspect modern metadata roots in {}: {}",
                modern_buckets.display(),
                error
            )),
        }
    }
    match std::fs::read_dir(storage_root) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) if entry.file_name() != SYSTEM_ROOT && entry.path().is_dir() => {
                        metadata_roots.insert(entry.path().join(LEGACY_BUCKET_META_DIR));
                    }
                    Ok(_) => {}
                    Err(error) => errors.push(format!(
                        "failed to enumerate legacy metadata roots: {error}"
                    )),
                }
            }
        }
        Err(error) => errors.push(format!(
            "failed to inspect storage root {} for metadata: {}",
            storage_root.display(),
            error
        )),
    }

    let mut references = HashSet::new();
    for root in metadata_roots {
        if !root.is_dir() {
            continue;
        }
        let mut stack = vec![root];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(error) => {
                    errors.push(format!(
                        "failed to inspect quarantine references in {}: {}",
                        dir.display(),
                        error
                    ));
                    continue;
                }
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        errors.push(format!(
                            "failed to enumerate metadata in {}: {}",
                            dir.display(),
                            error
                        ));
                        continue;
                    }
                };
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                let value = match std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|contents| serde_json::from_str::<Value>(&contents).ok())
                {
                    Some(value) => value,
                    None => {
                        errors.push(format!(
                            "failed to parse metadata while protecting quarantine: {}",
                            path.display()
                        ));
                        continue;
                    }
                };
                if !collect_quarantine_references_from_value(&value, &mut references) {
                    errors.push(format!(
                        "invalid quarantine reference in metadata: {}",
                        path.display()
                    ));
                }
            }
        }
    }
    (references, errors)
}

fn collect_quarantine_references_from_value(value: &Value, out: &mut HashSet<String>) -> bool {
    let mut valid = true;
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == META_KEY_QUARANTINE_PATH {
                    match child.as_str().and_then(normalize_quarantine_reference) {
                        Some(path) => {
                            out.insert(path);
                        }
                        None => valid = false,
                    }
                } else {
                    valid &= collect_quarantine_references_from_value(child, out);
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                valid &= collect_quarantine_references_from_value(child, out);
            }
        }
        _ => {}
    }
    valid
}

fn normalize_quarantine_reference(raw: &str) -> Option<String> {
    let normalized = raw.replace('\\', "/");
    if !normalized.starts_with(&format!("{SYSTEM_ROOT}/{QUARANTINE_DIR}/"))
        || normalized
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return None;
    }
    Some(normalized)
}

fn collect_segment_refs(
    root: &std::path::Path,
    out: &mut std::collections::HashSet<String>,
) -> Vec<String> {
    let mut scan_errors: Vec<String> = Vec::new();
    if !root.is_dir() {
        return scan_errors;
    }
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                scan_errors.push(format!("failed to read {}: {}", dir.display(), e));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    scan_errors.push(format!("failed to read entry in {}: {}", dir.display(), e));
                    continue;
                }
            };
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    scan_errors.push(format!("failed to stat {}: {}", path.display(), e));
                    continue;
                }
            };
            if ft.is_dir() {
                stack.push(path);
                continue;
            }
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(e) => {
                    scan_errors.push(format!(
                        "failed to read metadata of {}: {}",
                        path.display(),
                        e
                    ));
                    continue;
                }
            };
            if meta.len() < myfsio_storage::segments::SEGMENT_MIN_TOTAL {
                continue;
            }
            match myfsio_storage::segments::read_stub_header(&path) {
                Ok(Some(header)) => {
                    out.insert(header.segment_id);
                }
                Ok(None) => {}
                Err(e) => {
                    scan_errors.push(format!(
                        "failed to read segment stub header of {}: {}",
                        path.display(),
                        e
                    ));
                }
            }
        }
    }
    scan_errors
}

fn dir_total_bytes(path: &std::path::Path) -> u64 {
    let mut total: u64 = 0;
    let mut stack: Vec<PathBuf> = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                total = total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_reports_but_does_not_delete_temp_files() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join(".myfsio.sys").join("tmp");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let file_path = tmp_dir.join("stale.tmp");
        std::fs::write(&file_path, b"temporary").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let service = Arc::new(GcService::new(
            tmp.path().to_path_buf(),
            GcConfig {
                temp_file_max_age_hours: 0.0,
                dry_run: true,
                ..GcConfig::default()
            },
        ));

        let result = service.run_now(false).await.unwrap();

        assert_eq!(result["temp_files_deleted"], 1);
        assert!(file_path.exists());
    }

    #[tokio::test]
    async fn temp_sweep_never_deletes_commit_intents() {
        let tmp = tempfile::tempdir().unwrap();
        let tmp_dir = tmp.path().join(".myfsio.sys").join("tmp");
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let stale_tmp = tmp_dir.join("stale.tmp");
        std::fs::write(&stale_tmp, b"temporary").unwrap();
        let intent = tmp_dir.join("retained.sidecar-stage");
        std::fs::write(&intent, b"{}").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let service = Arc::new(GcService::new(
            tmp.path().to_path_buf(),
            GcConfig {
                temp_file_max_age_hours: 0.0,
                dry_run: false,
                ..GcConfig::default()
            },
        ));

        let result = service.run_now(false).await.unwrap();

        assert_eq!(result["temp_files_deleted"], 1);
        assert!(!stale_tmp.exists());
        assert!(
            intent.exists(),
            "commit intents are recovery records owned by startup reconciliation, never GC"
        );
    }

    fn write_segment_fixture(root: &std::path::Path, bucket: &str, segment_id: &str) -> PathBuf {
        let live_dir = root.join(bucket);
        std::fs::create_dir_all(&live_dir).unwrap();
        let header = myfsio_storage::segments::StubHeader::new(
            segment_id.to_string(),
            vec![myfsio_storage::segments::SEGMENT_MIN_TOTAL],
            "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        );
        myfsio_storage::segments::write_stub(&live_dir.join("stub.bin"), &header).unwrap();
        let segments_dir = root
            .join(".myfsio.sys")
            .join("buckets")
            .join(bucket)
            .join("segments");
        std::fs::create_dir_all(segments_dir.join(segment_id)).unwrap();
        std::fs::write(segments_dir.join(segment_id).join("0"), b"part").unwrap();
        segments_dir
    }

    #[tokio::test]
    async fn segment_sweep_deletes_only_unreferenced_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let segments_dir = write_segment_fixture(tmp.path(), "photos", "referenced");
        let orphan_dir = segments_dir.join("orphaned");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("0"), b"part").unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let service = Arc::new(GcService::new(
            tmp.path().to_path_buf(),
            GcConfig {
                segment_max_age_hours: 0.0,
                ..GcConfig::default()
            },
        ));

        let result = service.run_now(false).await.unwrap();

        assert_eq!(result["segment_dirs_deleted"], 1);
        assert!(segments_dir.join("referenced").exists());
        assert!(!orphan_dir.exists());
        assert_eq!(result["errors"].as_array().unwrap().len(), 0);
    }

    fn seed_quarantine_pair(root: &std::path::Path) -> (PathBuf, PathBuf) {
        let quarantine_root = root.join(SYSTEM_ROOT).join(QUARANTINE_DIR).join("photos");
        let protected_dir = quarantine_root.join("protected");
        let deletable_dir = quarantine_root.join("deletable");
        std::fs::create_dir_all(&protected_dir).unwrap();
        std::fs::create_dir_all(&deletable_dir).unwrap();
        std::fs::write(protected_dir.join("image.bin"), b"recoverable").unwrap();
        std::fs::write(deletable_dir.join("old.bin"), b"unreferenced").unwrap();
        (protected_dir, deletable_dir)
    }

    fn poisoned_metadata_value() -> Value {
        json!({
            "__entry_name__": "image.bin",
            "metadata": {
                "__corrupted__": "true",
                "__quarantine_path__": ".myfsio.sys/quarantine/photos/protected/image.bin"
            }
        })
    }

    async fn run_quarantine_sweep(root: &std::path::Path) -> Value {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let service = Arc::new(GcService::new(
            root.to_path_buf(),
            GcConfig {
                quarantine_max_age_days: 0,
                ..GcConfig::default()
            },
        ));
        service.run_now(false).await.unwrap()
    }

    #[tokio::test]
    async fn quarantine_sweep_preserves_entries_referenced_by_sidecar_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let (protected_dir, deletable_dir) = seed_quarantine_pair(tmp.path());

        let metadata_root = tmp
            .path()
            .join(SYSTEM_ROOT)
            .join(SYSTEM_BUCKETS_DIR)
            .join("photos")
            .join(BUCKET_META_DIR);
        std::fs::create_dir_all(&metadata_root).unwrap();
        std::fs::write(
            metadata_root.join(".__myfsio_meta__image.bin.json"),
            serde_json::to_string(&poisoned_metadata_value()).unwrap(),
        )
        .unwrap();

        let result = run_quarantine_sweep(tmp.path()).await;

        assert_eq!(result["quarantine_entries_protected"], 1);
        assert_eq!(result["quarantine_entries_deleted"], 1);
        assert!(protected_dir.exists());
        assert!(!deletable_dir.exists());
    }

    #[tokio::test]
    async fn quarantine_sweep_preserves_entries_referenced_by_legacy_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let (protected_dir, deletable_dir) = seed_quarantine_pair(tmp.path());

        let legacy_root = tmp.path().join("photos").join(LEGACY_BUCKET_META_DIR);
        std::fs::create_dir_all(&legacy_root).unwrap();
        std::fs::write(
            legacy_root.join("image.bin.meta.json"),
            serde_json::to_string(&poisoned_metadata_value()).unwrap(),
        )
        .unwrap();

        let result = run_quarantine_sweep(tmp.path()).await;

        assert_eq!(result["quarantine_entries_protected"], 1);
        assert_eq!(result["quarantine_entries_deleted"], 1);
        assert!(protected_dir.exists());
        assert!(!deletable_dir.exists());
    }

    #[tokio::test]
    async fn quarantine_sweep_deletes_aged_entries_without_references() {
        let tmp = tempfile::tempdir().unwrap();
        let (protected_dir, deletable_dir) = seed_quarantine_pair(tmp.path());

        let result = run_quarantine_sweep(tmp.path()).await;

        assert_eq!(result["quarantine_entries_protected"], 0);
        assert_eq!(result["quarantine_entries_deleted"], 2);
        assert!(!protected_dir.exists());
        assert!(!deletable_dir.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn segment_sweep_skips_bucket_when_reference_scan_fails() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let segments_dir = write_segment_fixture(tmp.path(), "photos", "referenced");
        let orphan_dir = segments_dir.join("orphaned");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("0"), b"part").unwrap();
        let blocked_dir = tmp.path().join("photos").join("nested");
        std::fs::create_dir_all(&blocked_dir).unwrap();
        std::fs::set_permissions(&blocked_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        let service = Arc::new(GcService::new(
            tmp.path().to_path_buf(),
            GcConfig {
                segment_max_age_hours: 0.0,
                ..GcConfig::default()
            },
        ));

        let result = service.run_now(false).await.unwrap();
        std::fs::set_permissions(&blocked_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(result["segment_dirs_deleted"], 0);
        assert!(orphan_dir.exists());
        assert!(segments_dir.join("referenced").exists());
        let errors = result["errors"].as_array().unwrap();
        assert!(errors
            .iter()
            .any(|e| e.as_str().unwrap_or_default().contains("photos")));
    }
}
