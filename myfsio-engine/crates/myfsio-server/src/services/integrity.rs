use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

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
            batch_size: 1000,
            auto_heal: false,
            dry_run: false,
        }
    }
}

pub struct IntegrityService {
    storage: Arc<FsStorageBackend>,
    config: IntegrityConfig,
    running: Arc<RwLock<bool>>,
    history: Arc<RwLock<Vec<Value>>>,
    history_path: PathBuf,
}

impl IntegrityService {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        storage_root: &std::path::Path,
        config: IntegrityConfig,
    ) -> Self {
        let history_path = storage_root
            .join(".myfsio.sys")
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
            "batch_size": self.config.batch_size,
            "auto_heal": self.config.auto_heal,
            "dry_run": self.config.dry_run,
        })
    }

    pub async fn history(&self) -> Value {
        let history = self.history.read().await;
        json!({ "executions": *history })
    }

    pub async fn run_now(&self, dry_run: bool, auto_heal: bool) -> Result<Value, String> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("Integrity check already running".to_string());
            }
            *running = true;
        }

        let start = Instant::now();
        let result = self.check_integrity(dry_run, auto_heal).await;
        let elapsed = start.elapsed().as_secs_f64();

        *self.running.write().await = false;

        let mut result_json = result.clone();
        if let Some(obj) = result_json.as_object_mut() {
            obj.insert("execution_time_seconds".to_string(), json!(elapsed));
        }

        let record = json!({
            "timestamp": chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
            "dry_run": dry_run,
            "auto_heal": auto_heal,
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

    async fn check_integrity(&self, _dry_run: bool, _auto_heal: bool) -> Value {
        let buckets = match self.storage.list_buckets().await {
            Ok(b) => b,
            Err(e) => return json!({"error": e.to_string()}),
        };

        let mut objects_scanned = 0u64;
        let mut corrupted = 0u64;
        let mut phantom_metadata = 0u64;
        let mut errors: Vec<String> = Vec::new();

        for bucket in &buckets {
            let params = myfsio_common::types::ListParams {
                max_keys: self.config.batch_size,
                ..Default::default()
            };
            let objects = match self.storage.list_objects(&bucket.name, &params).await {
                Ok(r) => r.objects,
                Err(e) => {
                    errors.push(format!("{}: {}", bucket.name, e));
                    continue;
                }
            };

            for obj in &objects {
                objects_scanned += 1;
                match self.storage.get_object_path(&bucket.name, &obj.key).await {
                    Ok(path) => {
                        if !path.exists() {
                            phantom_metadata += 1;
                        } else if let Some(ref expected_etag) = obj.etag {
                            match myfsio_crypto::hashing::md5_file(&path) {
                                Ok(actual_etag) => {
                                    if &actual_etag != expected_etag {
                                        corrupted += 1;
                                    }
                                }
                                Err(e) => errors.push(format!("{}:{}: {}", bucket.name, obj.key, e)),
                            }
                        }
                    }
                    Err(e) => errors.push(format!("{}:{}: {}", bucket.name, obj.key, e)),
                }
            }
        }

        json!({
            "objects_scanned": objects_scanned,
            "buckets_scanned": buckets.len(),
            "corrupted_objects": corrupted,
            "phantom_metadata": phantom_metadata,
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
                tracing::info!("Integrity check starting");
                match self.run_now(false, false).await {
                    Ok(result) => tracing::info!("Integrity check complete: {:?}", result),
                    Err(e) => tracing::warn!("Integrity check failed: {}", e),
                }
            }
        })
    }
}
