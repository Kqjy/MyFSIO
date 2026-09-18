use chrono::Utc;
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
        let config = match read_logging_file(&path) {
            Ok(stored) => stored
                .and_then(|f| f.logging_enabled)
                .map(|e| LoggingConfiguration {
                    target_bucket: e.target_bucket,
                    target_prefix: e.target_prefix,
                    enabled: true,
                }),
            Err(err) => {
                preserve_unreadable_logging_file(&path, &err.to_string(), bucket);
                None
            }
        };

        self.cache
            .write()
            .insert(bucket.to_string(), config.clone());
        config
    }

    pub fn set(&self, bucket: &str, config: LoggingConfiguration) -> std::io::Result<()> {
        let path = self.config_path(bucket);
        let stored = StoredLoggingFile {
            logging_enabled: Some(StoredLoggingEnabled {
                target_bucket: config.target_bucket.clone(),
                target_prefix: config.target_prefix.clone(),
            }),
        };
        let mut bytes = serde_json::to_vec_pretty(&stored).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        myfsio_common::fs_util::atomic_write_file(&path, &bytes)?;
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

fn read_logging_file(path: &Path) -> std::io::Result<Option<StoredLoggingFile>> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<StoredLoggingFile>(&text)
            .map(Some)
            .map_err(std::io::Error::other),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn preserve_unreadable_logging_file(path: &Path, reason: &str, bucket: &str) {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("logging.json");
    let preserved = path.with_file_name(format!("{name}.corrupt-{}", Utc::now().timestamp()));
    match std::fs::rename(path, &preserved) {
        Ok(()) => tracing::error!(
            path = %path.display(),
            preserved_path = %preserved.display(),
            reason,
            "Access logging configuration for bucket {} is unreadable; preserved it and treated the bucket as not logging",
            bucket
        ),
        Err(rename_error) => tracing::error!(
            path = %path.display(),
            reason,
            rename_error = %rename_error,
            "Access logging configuration for bucket {} is unreadable and could not be preserved; treated the bucket as not logging",
            bucket
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_names(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .expect("read bucket dir")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn absent_logging_file_reads_as_unconfigured_without_failing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let service = AccessLoggingService::new(tmp.path());

        assert!(service.get("photos").is_none());
        assert!(!tmp.path().join(".myfsio.sys").exists());
    }

    #[test]
    fn damaged_logging_file_is_preserved_instead_of_silently_disabling_logging() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let service = AccessLoggingService::new(tmp.path());
        let path = service.config_path("photos");
        std::fs::create_dir_all(path.parent().unwrap()).expect("create bucket dir");
        std::fs::write(&path, "{not json").expect("write config");

        assert!(read_logging_file(&path).is_err());
        assert!(service.get("photos").is_none());
        assert!(!path.exists());
        assert!(file_names(path.parent().unwrap())
            .iter()
            .any(|name| name.starts_with("logging.json.corrupt-")));
    }

    #[test]
    fn logging_configuration_round_trips_and_leaves_no_temp_residue() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let service = AccessLoggingService::new(tmp.path());
        service
            .set(
                "photos",
                LoggingConfiguration {
                    target_bucket: "audit".to_string(),
                    target_prefix: "photos/".to_string(),
                    enabled: true,
                },
            )
            .expect("set logging");

        let reopened = AccessLoggingService::new(tmp.path());
        let config = reopened.get("photos").expect("logging configuration");
        assert_eq!(config.target_bucket, "audit");
        assert_eq!(config.target_prefix, "photos/");

        let bucket_dir = service.config_path("photos");
        assert!(!file_names(bucket_dir.parent().unwrap())
            .iter()
            .any(|name| name.contains(".tmp-")));
    }
}
