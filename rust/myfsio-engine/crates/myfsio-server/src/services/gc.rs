use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

pub struct GcConfig {
    pub interval_hours: f64,
    pub temp_file_max_age_hours: f64,
    pub multipart_max_age_days: u64,
    pub lock_file_max_age_hours: f64,
    pub dry_run: bool,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            interval_hours: 6.0,
            temp_file_max_age_hours: 24.0,
            multipart_max_age_days: 7,
            lock_file_max_age_hours: 1.0,
            dry_run: false,
        }
    }
}

pub struct GcService {
    storage_root: PathBuf,
    config: GcConfig,
    running: Arc<RwLock<bool>>,
    history: Arc<RwLock<Vec<Value>>>,
    history_path: PathBuf,
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
            running: Arc::new(RwLock::new(false)),
            history: Arc::new(RwLock::new(history)),
            history_path,
        }
    }

    pub async fn status(&self) -> Value {
        let running = *self.running.read().await;
        json!({
            "enabled": true,
            "running": running,
            "interval_hours": self.config.interval_hours,
            "temp_file_max_age_hours": self.config.temp_file_max_age_hours,
            "multipart_max_age_days": self.config.multipart_max_age_days,
            "lock_file_max_age_hours": self.config.lock_file_max_age_hours,
            "dry_run": self.config.dry_run,
        })
    }

    pub async fn history(&self) -> Value {
        let history = self.history.read().await;
        json!({ "executions": *history })
    }

    pub async fn run_now(&self, dry_run: bool) -> Result<Value, String> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("GC already running".to_string());
            }
            *running = true;
        }

        let start = Instant::now();
        let result = self.execute_gc(dry_run || self.config.dry_run).await;
        let elapsed = start.elapsed().as_secs_f64();

        *self.running.write().await = false;

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
        let mut errors: Vec<String> = Vec::new();

        let now = std::time::SystemTime::now();
        let temp_max_age = std::time::Duration::from_secs_f64(self.config.temp_file_max_age_hours * 3600.0);
        let multipart_max_age = std::time::Duration::from_secs(self.config.multipart_max_age_days * 86400);
        let lock_max_age = std::time::Duration::from_secs_f64(self.config.lock_file_max_age_hours * 3600.0);

        let tmp_dir = self.storage_root.join(".myfsio.sys").join("tmp");
        if tmp_dir.exists() {
            match std::fs::read_dir(&tmp_dir) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(modified) = metadata.modified() {
                                if let Ok(age) = now.duration_since(modified) {
                                    if age > temp_max_age {
                                        let size = metadata.len();
                                        if !dry_run {
                                            if let Err(e) = std::fs::remove_file(entry.path()) {
                                                errors.push(format!("Failed to remove temp file: {}", e));
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
            "errors": errors,
        })
    }

    async fn save_history(&self) {
        let history = self.history.read().await;
        let data = json!({ "executions": *history });
        if let Some(parent) = self.history_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&self.history_path, serde_json::to_string_pretty(&data).unwrap_or_default());
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs_f64(self.config.interval_hours * 3600.0);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                tracing::info!("GC cycle starting");
                match self.run_now(false).await {
                    Ok(result) => tracing::info!("GC cycle complete: {:?}", result),
                    Err(e) => tracing::warn!("GC cycle failed: {}", e),
                }
            }
        })
    }
}
