use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfiguration {
    pub target_bucket: String,
    #[serde(default)]
    pub target_prefix: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Serialize, Deserialize)]
struct StoredLoggingFile {
    #[serde(rename = "LoggingEnabled")]
    logging_enabled: Option<StoredLoggingEnabled>,
}

#[derive(Serialize, Deserialize)]
struct StoredLoggingEnabled {
    #[serde(rename = "TargetBucket")]
    target_bucket: String,
    #[serde(rename = "TargetPrefix", default)]
    target_prefix: String,
}

pub struct AccessLoggingService {
    storage_root: PathBuf,
    cache: RwLock<HashMap<String, Option<LoggingConfiguration>>>,
}

impl AccessLoggingService {
    pub fn new(storage_root: &Path) -> Self {
        Self {
            storage_root: storage_root.to_path_buf(),
            cache: RwLock::new(HashMap::new()),
        }
    }

    fn config_path(&self, bucket: &str) -> PathBuf {
        self.storage_root
            .join(".myfsio.sys")
            .join("buckets")
            .join(bucket)
            .join("logging.json")
    }

    pub fn get(&self, bucket: &str) -> Option<LoggingConfiguration> {
        if let Some(cached) = self.cache.read().get(bucket).cloned() {
            return cached;
        }

        let path = self.config_path(bucket);
        let config = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str::<StoredLoggingFile>(&s).ok())
                .and_then(|f| f.logging_enabled)
                .map(|e| LoggingConfiguration {
                    target_bucket: e.target_bucket,
                    target_prefix: e.target_prefix,
                    enabled: true,
                })
        } else {
            None
        };

        self.cache
            .write()
            .insert(bucket.to_string(), config.clone());
        config
    }

    pub fn set(&self, bucket: &str, config: LoggingConfiguration) -> std::io::Result<()> {
        let path = self.config_path(bucket);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let stored = StoredLoggingFile {
            logging_enabled: Some(StoredLoggingEnabled {
                target_bucket: config.target_bucket.clone(),
                target_prefix: config.target_prefix.clone(),
            }),
        };
        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&path, json)?;
        self.cache.write().insert(bucket.to_string(), Some(config));
        Ok(())
    }

    pub fn delete(&self, bucket: &str) {
        let path = self.config_path(bucket);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        self.cache.write().insert(bucket.to_string(), None);
    }
}
