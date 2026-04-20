use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct LifecycleConfig {
    pub interval_seconds: u64,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 3600,
        }
    }
}

pub struct LifecycleService {
    storage: Arc<FsStorageBackend>,
    config: LifecycleConfig,
    running: Arc<RwLock<bool>>,
}

impl LifecycleService {
    pub fn new(storage: Arc<FsStorageBackend>, config: LifecycleConfig) -> Self {
        Self {
            storage,
            config,
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn run_cycle(&self) -> Result<Value, String> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("Lifecycle already running".to_string());
            }
            *running = true;
        }

        let result = self.evaluate_rules().await;
        *self.running.write().await = false;
        Ok(result)
    }

    async fn evaluate_rules(&self) -> Value {
        let buckets = match self.storage.list_buckets().await {
            Ok(b) => b,
            Err(e) => return json!({"error": e.to_string()}),
        };

        let mut total_expired = 0u64;
        let mut total_multipart_aborted = 0u64;
        let mut errors: Vec<String> = Vec::new();

        for bucket in &buckets {
            let config = match self.storage.get_bucket_config(&bucket.name).await {
                Ok(c) => c,
                Err(_) => continue,
            };

            let lifecycle = match &config.lifecycle {
                Some(lc) => lc,
                None => continue,
            };

            let rules = match lifecycle
                .as_str()
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
            {
                Some(v) => v,
                None => continue,
            };

            let rules_arr = match rules.get("Rules").and_then(|r| r.as_array()) {
                Some(a) => a.clone(),
                None => continue,
            };

            for rule in &rules_arr {
                if rule.get("Status").and_then(|s| s.as_str()) != Some("Enabled") {
                    continue;
                }

                let prefix = rule
                    .get("Filter")
                    .and_then(|f| f.get("Prefix"))
                    .and_then(|p| p.as_str())
                    .or_else(|| rule.get("Prefix").and_then(|p| p.as_str()))
                    .unwrap_or("");

                if let Some(exp) = rule.get("Expiration") {
                    if let Some(days) = exp.get("Days").and_then(|d| d.as_u64()) {
                        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                        let params = myfsio_common::types::ListParams {
                            max_keys: 1000,
                            prefix: if prefix.is_empty() {
                                None
                            } else {
                                Some(prefix.to_string())
                            },
                            ..Default::default()
                        };
                        if let Ok(result) = self.storage.list_objects(&bucket.name, &params).await {
                            for obj in &result.objects {
                                if obj.last_modified < cutoff {
                                    match self.storage.delete_object(&bucket.name, &obj.key).await {
                                        Ok(()) => total_expired += 1,
                                        Err(e) => errors
                                            .push(format!("{}:{}: {}", bucket.name, obj.key, e)),
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(abort) = rule.get("AbortIncompleteMultipartUpload") {
                    if let Some(days) = abort.get("DaysAfterInitiation").and_then(|d| d.as_u64()) {
                        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                        if let Ok(uploads) = self.storage.list_multipart_uploads(&bucket.name).await
                        {
                            for upload in &uploads {
                                if upload.initiated < cutoff {
                                    match self
                                        .storage
                                        .abort_multipart(&bucket.name, &upload.upload_id)
                                        .await
                                    {
                                        Ok(()) => total_multipart_aborted += 1,
                                        Err(e) => errors
                                            .push(format!("abort {}: {}", upload.upload_id, e)),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        json!({
            "objects_expired": total_expired,
            "multipart_aborted": total_multipart_aborted,
            "buckets_evaluated": buckets.len(),
            "errors": errors,
        })
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs(self.config.interval_seconds);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                tracing::info!("Lifecycle evaluation starting");
                match self.run_cycle().await {
                    Ok(result) => tracing::info!("Lifecycle cycle complete: {:?}", result),
                    Err(e) => tracing::warn!("Lifecycle cycle failed: {}", e),
                }
            }
        })
    }
}
