use crate::error::StorageError;
use crate::traits::{AsyncReadStream, StorageResult};
use crate::validation;
use myfsio_common::constants::*;
use myfsio_common::types::*;

use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use md5::{Digest, Md5};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

pub struct FsStorageBackend {
    root: PathBuf,
    object_key_max_length_bytes: usize,
    object_cache_max_size: usize,
    bucket_config_cache: DashMap<String, (BucketConfig, Instant)>,
    bucket_config_cache_ttl: std::time::Duration,
    meta_read_cache: DashMap<(String, String), Option<HashMap<String, Value>>>,
    meta_index_locks: DashMap<String, Arc<Mutex<()>>>,
    stats_cache: DashMap<String, (BucketStats, Instant)>,
    stats_cache_ttl: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct FsStorageBackendConfig {
    pub object_key_max_length_bytes: usize,
    pub object_cache_max_size: usize,
    pub bucket_config_cache_ttl: std::time::Duration,
}

impl Default for FsStorageBackendConfig {
    fn default() -> Self {
        Self {
            object_key_max_length_bytes: DEFAULT_OBJECT_KEY_MAX_BYTES,
            object_cache_max_size: 100,
            bucket_config_cache_ttl: std::time::Duration::from_secs(30),
        }
    }
}

impl FsStorageBackend {
    pub fn new(root: PathBuf) -> Self {
        Self::new_with_config(root, FsStorageBackendConfig::default())
    }

    pub fn new_with_config(root: PathBuf, config: FsStorageBackendConfig) -> Self {
        let backend = Self {
            root,
            object_key_max_length_bytes: config.object_key_max_length_bytes,
            object_cache_max_size: config.object_cache_max_size,
            bucket_config_cache: DashMap::new(),
            bucket_config_cache_ttl: config.bucket_config_cache_ttl,
            meta_read_cache: DashMap::new(),
            meta_index_locks: DashMap::new(),
            stats_cache: DashMap::new(),
            stats_cache_ttl: std::time::Duration::from_secs(60),
        };
        backend.ensure_system_roots();
        backend
    }

    fn ensure_system_roots(&self) {
        let dirs = [
            self.system_root_path(),
            self.system_buckets_root(),
            self.multipart_root(),
            self.system_root_path().join("tmp"),
        ];
        for dir in &dirs {
            std::fs::create_dir_all(dir).ok();
        }
    }

    fn bucket_path(&self, bucket_name: &str) -> PathBuf {
        self.root.join(bucket_name)
    }

    fn system_root_path(&self) -> PathBuf {
        self.root.join(SYSTEM_ROOT)
    }

    fn system_buckets_root(&self) -> PathBuf {
        self.system_root_path().join(SYSTEM_BUCKETS_DIR)
    }

    fn system_bucket_root(&self, bucket_name: &str) -> PathBuf {
        self.system_buckets_root().join(bucket_name)
    }

    fn bucket_meta_root(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name).join(BUCKET_META_DIR)
    }

    fn bucket_versions_root(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name)
            .join(BUCKET_VERSIONS_DIR)
    }

    fn multipart_root(&self) -> PathBuf {
        self.system_root_path().join(SYSTEM_MULTIPART_DIR)
    }

    fn multipart_bucket_root(&self, bucket_name: &str) -> PathBuf {
        self.multipart_root().join(bucket_name)
    }

    fn tmp_dir(&self) -> PathBuf {
        self.system_root_path().join("tmp")
    }

    fn object_path(&self, bucket_name: &str, object_key: &str) -> StorageResult<PathBuf> {
        self.validate_key(object_key)?;
        Ok(self.bucket_path(bucket_name).join(object_key))
    }

    fn validate_key(&self, object_key: &str) -> StorageResult<()> {
        let is_windows = cfg!(windows);
        if let Some(err) = validation::validate_object_key(
            object_key,
            self.object_key_max_length_bytes,
            is_windows,
            None,
        ) {
            return Err(StorageError::InvalidObjectKey(err));
        }
        Ok(())
    }

    fn require_bucket(&self, bucket_name: &str) -> StorageResult<PathBuf> {
        let path = self.bucket_path(bucket_name);
        if !path.exists() {
            return Err(StorageError::BucketNotFound(bucket_name.to_string()));
        }
        Ok(path)
    }

    fn index_file_for_key(&self, bucket_name: &str, key: &str) -> (PathBuf, String) {
        let meta_root = self.bucket_meta_root(bucket_name);
        let key_path = Path::new(key);
        let entry_name = key_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| key.to_string());

        let parent = key_path.parent();
        match parent {
            Some(p) if p != Path::new("") && p != Path::new(".") => {
                (meta_root.join(p).join(INDEX_FILE), entry_name)
            }
            _ => (meta_root.join(INDEX_FILE), entry_name),
        }
    }

    fn get_meta_index_lock(&self, index_path: &str) -> Arc<Mutex<()>> {
        self.meta_index_locks
            .entry(index_path.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn prune_meta_read_cache(&self) {
        if self.object_cache_max_size == 0 {
            self.meta_read_cache.clear();
            return;
        }
        let len = self.meta_read_cache.len();
        if len <= self.object_cache_max_size {
            return;
        }
        let excess = len - self.object_cache_max_size;
        let keys = self
            .meta_read_cache
            .iter()
            .take(excess)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.meta_read_cache.remove(&key);
        }
    }

    fn bucket_config_path(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name)
            .join(BUCKET_CONFIG_FILE)
    }

    fn legacy_bucket_policies_path(&self) -> PathBuf {
        self.system_root_path()
            .join("config")
            .join("bucket_policies.json")
    }

    fn version_dir(&self, bucket_name: &str, key: &str) -> PathBuf {
        self.bucket_versions_root(bucket_name).join(key)
    }

    fn legacy_meta_root(&self, bucket_name: &str) -> PathBuf {
        self.bucket_path(bucket_name).join(".meta")
    }

    fn legacy_metadata_file(&self, bucket_name: &str, key: &str) -> PathBuf {
        self.legacy_meta_root(bucket_name)
            .join(format!("{}.meta.json", key))
    }

    fn legacy_versions_root(&self, bucket_name: &str) -> PathBuf {
        self.bucket_path(bucket_name).join(".versions")
    }

    fn legacy_multipart_root(&self, bucket_name: &str) -> PathBuf {
        self.bucket_path(bucket_name).join(".multipart")
    }
}

impl FsStorageBackend {
    fn atomic_write_json_sync(path: &Path, data: &Value, sync: bool) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension("tmp");
        let result = (|| {
            let file = std::fs::File::create(&tmp_path)?;
            let mut writer = std::io::BufWriter::new(file);
            serde_json::to_writer(&mut writer, data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            let file = writer.into_inner()?;
            if sync {
                file.sync_all()?;
            }
            drop(file);
            std::fs::rename(&tmp_path, path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    fn read_index_entry_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> Option<HashMap<String, Value>> {
        let cache_key = (bucket_name.to_string(), key.to_string());
        if let Some(entry) = self.meta_read_cache.get(&cache_key) {
            return entry.value().clone();
        }

        let (index_path, entry_name) = self.index_file_for_key(bucket_name, key);
        let result = if index_path.exists() {
            std::fs::read_to_string(&index_path)
                .ok()
                .and_then(|s| serde_json::from_str::<HashMap<String, Value>>(&s).ok())
                .and_then(|index| {
                    index.get(&entry_name).and_then(|v| {
                        if let Value::Object(map) = v {
                            Some(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        } else {
                            None
                        }
                    })
                })
        } else {
            None
        };

        self.meta_read_cache.insert(cache_key, result.clone());
        self.prune_meta_read_cache();
        result
    }

    fn write_index_entry_sync(
        &self,
        bucket_name: &str,
        key: &str,
        entry: &HashMap<String, Value>,
    ) -> std::io::Result<()> {
        let (index_path, entry_name) = self.index_file_for_key(bucket_name, key);
        let lock = self.get_meta_index_lock(&index_path.to_string_lossy());
        let _guard = lock.lock();

        if let Some(parent) = index_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut index_data: HashMap<String, Value> = if index_path.exists() {
            std::fs::read_to_string(&index_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        };

        index_data.insert(
            entry_name,
            serde_json::to_value(entry)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        );

        let json_val = serde_json::to_value(&index_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Self::atomic_write_json_sync(&index_path, &json_val, true)?;

        let cache_key = (bucket_name.to_string(), key.to_string());
        self.meta_read_cache.remove(&cache_key);

        Ok(())
    }

    fn delete_index_entry_sync(&self, bucket_name: &str, key: &str) -> std::io::Result<()> {
        let (index_path, entry_name) = self.index_file_for_key(bucket_name, key);
        if !index_path.exists() {
            let cache_key = (bucket_name.to_string(), key.to_string());
            self.meta_read_cache.remove(&cache_key);
            return Ok(());
        }

        let lock = self.get_meta_index_lock(&index_path.to_string_lossy());
        let _guard = lock.lock();

        let mut index_data: HashMap<String, Value> = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        if index_data.remove(&entry_name).is_some() {
            if index_data.is_empty() {
                let _ = std::fs::remove_file(&index_path);
            } else {
                let json_val = serde_json::to_value(&index_data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                Self::atomic_write_json_sync(&index_path, &json_val, true)?;
            }
        }

        let cache_key = (bucket_name.to_string(), key.to_string());
        self.meta_read_cache.remove(&cache_key);
        Ok(())
    }

    fn read_metadata_sync(&self, bucket_name: &str, key: &str) -> HashMap<String, String> {
        if let Some(entry) = self.read_index_entry_sync(bucket_name, key) {
            if let Some(Value::Object(meta)) = entry.get("metadata") {
                return meta
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect();
            }
        }

        for meta_file in [
            self.bucket_meta_root(bucket_name)
                .join(format!("{}.meta.json", key)),
            self.legacy_metadata_file(bucket_name, key),
        ] {
            if meta_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&meta_file) {
                    if let Ok(payload) = serde_json::from_str::<Value>(&content) {
                        if let Some(Value::Object(meta)) = payload.get("metadata") {
                            return meta
                                .iter()
                                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                                .collect();
                        }
                    }
                }
            }
        }

        HashMap::new()
    }

    fn write_metadata_sync(
        &self,
        bucket_name: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> std::io::Result<()> {
        if metadata.is_empty() {
            return self.delete_index_entry_sync(bucket_name, key);
        }

        let mut entry = HashMap::new();
        let meta_value = serde_json::to_value(metadata)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        entry.insert("metadata".to_string(), meta_value);
        self.write_index_entry_sync(bucket_name, key, &entry)?;

        let old_meta = self
            .bucket_meta_root(bucket_name)
            .join(format!("{}.meta.json", key));
        if old_meta.exists() {
            let _ = std::fs::remove_file(&old_meta);
        }

        Ok(())
    }

    fn delete_metadata_sync(&self, bucket_name: &str, key: &str) -> std::io::Result<()> {
        self.delete_index_entry_sync(bucket_name, key)?;

        for meta_file in [
            self.bucket_meta_root(bucket_name)
                .join(format!("{}.meta.json", key)),
            self.legacy_metadata_file(bucket_name, key),
        ] {
            if meta_file.exists() {
                let _ = std::fs::remove_file(&meta_file);
            }
        }

        Ok(())
    }

    fn compute_etag_sync(path: &Path) -> std::io::Result<String> {
        myfsio_crypto::hashing::md5_file(path)
    }

    fn read_bucket_config_sync(&self, bucket_name: &str) -> BucketConfig {
        if let Some(entry) = self.bucket_config_cache.get(bucket_name) {
            let (config, cached_at) = entry.value();
            if cached_at.elapsed() < self.bucket_config_cache_ttl {
                return config.clone();
            }
        }

        let config_path = self.bucket_config_path(bucket_name);
        let mut config = if config_path.exists() {
            std::fs::read_to_string(&config_path)
                .ok()
                .and_then(|s| serde_json::from_str::<BucketConfig>(&s).ok())
                .unwrap_or_default()
        } else {
            BucketConfig::default()
        };
        if config.policy.is_none() {
            config.policy = self.read_legacy_bucket_policy_sync(bucket_name);
        }

        self.bucket_config_cache
            .insert(bucket_name.to_string(), (config.clone(), Instant::now()));
        config
    }

    fn read_legacy_bucket_policy_sync(&self, bucket_name: &str) -> Option<Value> {
        let path = self.legacy_bucket_policies_path();
        let text = std::fs::read_to_string(path).ok()?;
        let value = serde_json::from_str::<Value>(&text).ok()?;
        value
            .get("policies")
            .and_then(|policies| policies.get(bucket_name))
            .cloned()
            .or_else(|| value.get(bucket_name).cloned())
    }

    fn remove_legacy_bucket_policy_sync(&self, bucket_name: &str) -> std::io::Result<()> {
        let path = self.legacy_bucket_policies_path();
        if !path.exists() {
            return Ok(());
        }

        let text = std::fs::read_to_string(&path)?;
        let Ok(mut value) = serde_json::from_str::<Value>(&text) else {
            return Ok(());
        };
        let changed = {
            let Some(object) = value.as_object_mut() else {
                return Ok(());
            };

            let mut changed = false;
            if let Some(policies) = object.get_mut("policies").and_then(Value::as_object_mut) {
                changed |= policies.remove(bucket_name).is_some();
            }
            changed |= object.remove(bucket_name).is_some();
            changed
        };
        if !changed {
            return Ok(());
        }

        Self::atomic_write_json_sync(&path, &value, true)
    }

    fn write_bucket_config_sync(
        &self,
        bucket_name: &str,
        config: &BucketConfig,
    ) -> std::io::Result<()> {
        let config_path = self.bucket_config_path(bucket_name);
        let json_val = serde_json::to_value(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Self::atomic_write_json_sync(&config_path, &json_val, true)?;
        if config.policy.is_none() {
            self.remove_legacy_bucket_policy_sync(bucket_name)?;
        }
        self.bucket_config_cache
            .insert(bucket_name.to_string(), (config.clone(), Instant::now()));
        Ok(())
    }

    fn check_bucket_contents_sync(&self, bucket_path: &Path) -> (bool, bool, bool) {
        let bucket_name = bucket_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let has_objects = Self::dir_has_files(bucket_path, Some(INTERNAL_FOLDERS));
        let has_versions = Self::dir_has_files(&self.bucket_versions_root(&bucket_name), None)
            || Self::dir_has_files(&self.legacy_versions_root(&bucket_name), None);
        let has_multipart = Self::dir_has_files(&self.multipart_bucket_root(&bucket_name), None)
            || Self::dir_has_files(&self.legacy_multipart_root(&bucket_name), None);

        (has_objects, has_versions, has_multipart)
    }

    fn dir_has_files(dir: &Path, skip_dirs: Option<&[&str]>) -> bool {
        if !dir.exists() {
            return false;
        }
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if current == dir {
                    if let Some(skip) = skip_dirs {
                        if skip.contains(&name_str.as_ref()) {
                            continue;
                        }
                    }
                }
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_file() {
                    return true;
                }
                if ft.is_dir() {
                    stack.push(entry.path());
                }
            }
        }
        false
    }

    fn remove_tree(path: &Path) {
        if path.exists() {
            let _ = std::fs::remove_dir_all(path);
        }
    }

    fn safe_unlink(path: &Path) -> std::io::Result<()> {
        for attempt in 0..3 {
            match std::fs::remove_file(path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && cfg!(windows) => {
                    if attempt < 2 {
                        std::thread::sleep(std::time::Duration::from_millis(
                            150 * (attempt as u64 + 1),
                        ));
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn cleanup_empty_parents(path: &Path, stop_at: &Path) {
        let mut parent = path.parent();
        while let Some(p) = parent {
            if p == stop_at || !p.exists() {
                break;
            }
            match std::fs::read_dir(p) {
                Ok(mut entries) => {
                    if entries.next().is_some() {
                        break;
                    }
                    let _ = std::fs::remove_dir(p);
                }
                Err(_) => break,
            }
            parent = p.parent();
        }
    }

    fn archive_current_version_sync(
        &self,
        bucket_name: &str,
        key: &str,
        reason: &str,
    ) -> std::io::Result<u64> {
        let bucket_path = self.bucket_path(bucket_name);
        let source = bucket_path.join(key);
        if !source.exists() {
            return Ok(0);
        }

        let version_dir = self.version_dir(bucket_name, key);
        std::fs::create_dir_all(&version_dir)?;

        let now = Utc::now();
        let version_id = format!(
            "{}-{}",
            now.format("%Y%m%dT%H%M%S%6fZ"),
            &Uuid::new_v4().to_string()[..8]
        );

        let data_path = version_dir.join(format!("{}.bin", version_id));
        std::fs::copy(&source, &data_path)?;

        let source_meta = source.metadata()?;
        let source_size = source_meta.len();

        let metadata = self.read_metadata_sync(bucket_name, key);
        let etag = Self::compute_etag_sync(&source).unwrap_or_default();

        let record = serde_json::json!({
            "version_id": version_id,
            "key": key,
            "size": source_size,
            "archived_at": now.to_rfc3339(),
            "etag": etag,
            "metadata": metadata,
            "reason": reason,
        });

        let manifest_path = version_dir.join(format!("{}.json", version_id));
        Self::atomic_write_json_sync(&manifest_path, &record, true)?;

        Ok(source_size)
    }

    fn version_record_paths(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> (PathBuf, PathBuf) {
        let version_dir = self.version_dir(bucket_name, key);
        (
            version_dir.join(format!("{}.json", version_id)),
            version_dir.join(format!("{}.bin", version_id)),
        )
    }

    fn validate_version_id(bucket_name: &str, key: &str, version_id: &str) -> StorageResult<()> {
        if version_id.is_empty()
            || version_id.contains('/')
            || version_id.contains('\\')
            || version_id.contains("..")
        {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }
        Ok(())
    }

    fn read_version_record_sync(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(Value, PathBuf)> {
        self.require_bucket(bucket_name)?;
        self.validate_key(key)?;
        Self::validate_version_id(bucket_name, key, version_id)?;
        let (manifest_path, data_path) = self.version_record_paths(bucket_name, key, version_id);
        if !manifest_path.is_file() || !data_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }

        let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let record = serde_json::from_str::<Value>(&content).map_err(StorageError::Json)?;
        Ok((record, data_path))
    }

    fn version_metadata_from_record(record: &Value) -> HashMap<String, String> {
        record
            .get("metadata")
            .and_then(Value::as_object)
            .map(|meta| {
                meta.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default()
    }

    fn object_meta_from_version_record(
        &self,
        key: &str,
        record: &Value,
        data_path: &Path,
    ) -> StorageResult<ObjectMeta> {
        let metadata = Self::version_metadata_from_record(record);

        let data_len = std::fs::metadata(data_path)
            .map(|meta| meta.len())
            .unwrap_or_default();
        let size = record
            .get("size")
            .and_then(Value::as_u64)
            .unwrap_or(data_len);
        let last_modified = record
            .get("archived_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let etag = record
            .get("etag")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| metadata.get("__etag__").cloned());

        let mut obj = ObjectMeta::new(key.to_string(), size, last_modified);
        obj.etag = etag;
        obj.content_type = metadata.get("__content_type__").cloned();
        obj.storage_class = metadata
            .get("__storage_class__")
            .cloned()
            .or_else(|| Some("STANDARD".to_string()));
        obj.metadata = metadata
            .into_iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .collect();
        Ok(obj)
    }

    fn version_info_from_record(&self, fallback_key: &str, record: &Value) -> VersionInfo {
        let version_id = record
            .get("version_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let key = record
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or(fallback_key)
            .to_string();
        let size = record.get("size").and_then(Value::as_u64).unwrap_or(0);
        let archived_at = record
            .get("archived_at")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let etag = record
            .get("etag")
            .and_then(Value::as_str)
            .map(|s| s.to_string());

        VersionInfo {
            version_id,
            key,
            size,
            last_modified: archived_at,
            etag,
            is_latest: false,
            is_delete_marker: false,
        }
    }

    fn bucket_stats_sync(&self, bucket_name: &str) -> StorageResult<BucketStats> {
        let bucket_path = self.require_bucket(bucket_name)?;

        if let Some(entry) = self.stats_cache.get(bucket_name) {
            let (stats, cached_at) = entry.value();
            if cached_at.elapsed() < self.stats_cache_ttl {
                return Ok(stats.clone());
            }
        }

        let mut object_count: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut version_count: u64 = 0;
        let mut version_bytes: u64 = 0;

        let internal = INTERNAL_FOLDERS;
        let bucket_str = bucket_path.to_string_lossy().to_string();
        let mut stack = vec![bucket_str.clone()];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if current == bucket_str && internal.contains(&name_str.as_ref()) {
                    continue;
                }
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_dir() {
                    stack.push(entry.path().to_string_lossy().to_string());
                } else if ft.is_file() {
                    object_count += 1;
                    if let Ok(meta) = entry.metadata() {
                        total_bytes += meta.len();
                    }
                }
            }
        }

        let versions_root = self.bucket_versions_root(bucket_name);
        if versions_root.exists() {
            let mut v_stack = vec![versions_root.to_string_lossy().to_string()];
            while let Some(current) = v_stack.pop() {
                let entries = match std::fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if ft.is_dir() {
                        v_stack.push(entry.path().to_string_lossy().to_string());
                    } else if ft.is_file() {
                        let name = entry.file_name();
                        if name.to_string_lossy().ends_with(".bin") {
                            version_count += 1;
                            if let Ok(meta) = entry.metadata() {
                                version_bytes += meta.len();
                            }
                        }
                    }
                }
            }
        }

        let stats = BucketStats {
            objects: object_count,
            bytes: total_bytes,
            version_count,
            version_bytes,
        };

        self.stats_cache
            .insert(bucket_name.to_string(), (stats.clone(), Instant::now()));
        Ok(stats)
    }

    fn list_objects_sync(
        &self,
        bucket_name: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        let bucket_path = self.require_bucket(bucket_name)?;

        let mut all_keys: Vec<(String, u64, f64, Option<String>)> = Vec::new();
        let internal = INTERNAL_FOLDERS;
        let bucket_str = bucket_path.to_string_lossy().to_string();
        let bucket_prefix_len = bucket_str.len() + 1;
        let mut stack = vec![bucket_str.clone()];

        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if current == bucket_str && internal.contains(&name_str.as_ref()) {
                    continue;
                }
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_dir() {
                    stack.push(entry.path().to_string_lossy().to_string());
                } else if ft.is_file() {
                    let full_path = entry.path().to_string_lossy().to_string();
                    let key = full_path[bucket_prefix_len..].replace('\\', "/");
                    if let Ok(meta) = entry.metadata() {
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);
                        all_keys.push((key, meta.len(), mtime, None));
                    }
                }
            }
        }

        all_keys.sort_by(|a, b| a.0.cmp(&b.0));

        if let Some(ref prefix) = params.prefix {
            all_keys.retain(|k| k.0.starts_with(prefix.as_str()));
        }

        let start_idx = if let Some(ref token) = params.continuation_token {
            all_keys
                .iter()
                .position(|k| k.0.as_str() > token.as_str())
                .unwrap_or(all_keys.len())
        } else if let Some(ref start_after) = params.start_after {
            all_keys
                .iter()
                .position(|k| k.0.as_str() > start_after.as_str())
                .unwrap_or(all_keys.len())
        } else {
            0
        };

        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        let end_idx = std::cmp::min(start_idx + max_keys, all_keys.len());
        let is_truncated = end_idx < all_keys.len();

        let objects: Vec<ObjectMeta> = all_keys[start_idx..end_idx]
            .iter()
            .map(|(key, size, mtime, etag)| {
                let lm = Utc
                    .timestamp_opt(*mtime as i64, ((*mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
                    .unwrap_or_else(Utc::now);
                let mut obj = ObjectMeta::new(key.clone(), *size, lm);
                obj.etag = etag.clone().or_else(|| {
                    let meta = self.read_metadata_sync(bucket_name, key);
                    meta.get("__etag__").cloned()
                });
                obj
            })
            .collect();

        let next_token = if is_truncated {
            objects.last().map(|o| o.key.clone())
        } else {
            None
        };

        Ok(ListObjectsResult {
            objects,
            is_truncated,
            next_continuation_token: next_token,
        })
    }

    fn list_objects_shallow_sync(
        &self,
        bucket_name: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult> {
        let bucket_path = self.require_bucket(bucket_name)?;

        let target_dir = if params.prefix.is_empty() {
            bucket_path.clone()
        } else {
            let prefix_path = Path::new(&params.prefix);
            let dir_part = if params.prefix.ends_with(&params.delimiter) {
                prefix_path.to_path_buf()
            } else {
                prefix_path.parent().unwrap_or(Path::new("")).to_path_buf()
            };
            bucket_path.join(dir_part)
        };

        if !target_dir.exists() {
            return Ok(ShallowListResult {
                objects: Vec::new(),
                common_prefixes: Vec::new(),
                is_truncated: false,
                next_continuation_token: None,
            });
        }

        let mut files = Vec::new();
        let mut dirs = Vec::new();

        let entries = std::fs::read_dir(&target_dir).map_err(StorageError::Io)?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();

            if target_dir == bucket_path && INTERNAL_FOLDERS.contains(&name_str.as_str()) {
                continue;
            }

            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            let rel = entry
                .path()
                .strip_prefix(&bucket_path)
                .unwrap_or(Path::new(""))
                .to_string_lossy()
                .replace('\\', "/");

            if !params.prefix.is_empty() && !rel.starts_with(&params.prefix) {
                continue;
            }

            if ft.is_dir() {
                dirs.push(format!("{}{}", rel, &params.delimiter));
            } else if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0);
                    let lm = Utc
                        .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
                        .single()
                        .unwrap_or_else(Utc::now);
                    let etag = self
                        .read_metadata_sync(bucket_name, &rel)
                        .get("__etag__")
                        .cloned();
                    let mut obj = ObjectMeta::new(rel, meta.len(), lm);
                    obj.etag = etag;
                    files.push(obj);
                }
            }
        }

        files.sort_by(|a, b| a.key.cmp(&b.key));
        dirs.sort();

        let mut merged: Vec<Either> = Vec::new();
        let mut fi = 0;
        let mut di = 0;
        while fi < files.len() && di < dirs.len() {
            if files[fi].key < dirs[di] {
                merged.push(Either::File(fi));
                fi += 1;
            } else {
                merged.push(Either::Dir(di));
                di += 1;
            }
        }
        while fi < files.len() {
            merged.push(Either::File(fi));
            fi += 1;
        }
        while di < dirs.len() {
            merged.push(Either::Dir(di));
            di += 1;
        }

        let start_idx = if let Some(ref token) = params.continuation_token {
            merged
                .iter()
                .position(|e| match e {
                    Either::File(i) => files[*i].key.as_str() > token.as_str(),
                    Either::Dir(i) => dirs[*i].as_str() > token.as_str(),
                })
                .unwrap_or(merged.len())
        } else {
            0
        };

        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        let end_idx = std::cmp::min(start_idx + max_keys, merged.len());
        let is_truncated = end_idx < merged.len();

        let mut result_objects = Vec::new();
        let mut result_prefixes = Vec::new();

        for item in &merged[start_idx..end_idx] {
            match item {
                Either::File(i) => result_objects.push(files[*i].clone()),
                Either::Dir(i) => result_prefixes.push(dirs[*i].clone()),
            }
        }

        let next_token = if is_truncated {
            match &merged[end_idx - 1] {
                Either::File(i) => Some(files[*i].key.clone()),
                Either::Dir(i) => Some(dirs[*i].clone()),
            }
        } else {
            None
        };

        Ok(ShallowListResult {
            objects: result_objects,
            common_prefixes: result_prefixes,
            is_truncated,
            next_continuation_token: next_token,
        })
    }

    fn finalize_put_sync(
        &self,
        bucket_name: &str,
        key: &str,
        tmp_path: &Path,
        etag: String,
        new_size: u64,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<ObjectMeta> {
        let bucket_path = self.require_bucket(bucket_name)?;
        let destination = bucket_path.join(key);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }

        let is_overwrite = destination.exists();
        let existing_size = if is_overwrite {
            std::fs::metadata(&destination)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };

        let bucket_config = self.read_bucket_config_sync(bucket_name);
        if let Some(quota) = bucket_config.quota.as_ref() {
            self.stats_cache.remove(bucket_name);
            let stats = self.bucket_stats_sync(bucket_name)?;
            let added_bytes = new_size.saturating_sub(existing_size);
            let added_objects: u64 = if is_overwrite { 0 } else { 1 };
            if let Some(max_bytes) = quota.max_bytes {
                let projected = stats.total_bytes().saturating_add(added_bytes);
                if projected > max_bytes {
                    let _ = std::fs::remove_file(tmp_path);
                    return Err(StorageError::QuotaExceeded(format!(
                        "Quota exceeded: adding {} bytes would result in {} bytes, exceeding limit of {} bytes",
                        added_bytes, projected, max_bytes
                    )));
                }
            }
            if let Some(max_objects) = quota.max_objects {
                let projected = stats.total_objects().saturating_add(added_objects);
                if projected > max_objects {
                    let _ = std::fs::remove_file(tmp_path);
                    return Err(StorageError::QuotaExceeded(format!(
                        "Quota exceeded: adding {} objects would result in {} objects, exceeding limit of {} objects",
                        added_objects, projected, max_objects
                    )));
                }
            }
        }

        let lock_dir = self.system_bucket_root(bucket_name).join("locks");
        std::fs::create_dir_all(&lock_dir).map_err(StorageError::Io)?;

        let versioning_enabled = bucket_config.versioning_enabled;
        if versioning_enabled && is_overwrite {
            self.archive_current_version_sync(bucket_name, key, "overwrite")
                .map_err(StorageError::Io)?;
        }

        std::fs::rename(tmp_path, &destination).map_err(|e| {
            let _ = std::fs::remove_file(tmp_path);
            StorageError::Io(e)
        })?;

        self.stats_cache.remove(bucket_name);

        let file_meta = std::fs::metadata(&destination).map_err(StorageError::Io)?;
        let mtime = file_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let mut internal_meta = HashMap::new();
        internal_meta.insert("__etag__".to_string(), etag.clone());
        internal_meta.insert("__size__".to_string(), new_size.to_string());
        internal_meta.insert("__last_modified__".to_string(), mtime.to_string());

        if let Some(ref user_meta) = metadata {
            for (k, v) in user_meta {
                internal_meta.insert(k.clone(), v.clone());
            }
        }

        self.write_metadata_sync(bucket_name, key, &internal_meta)
            .map_err(StorageError::Io)?;

        let lm = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);

        let mut obj = ObjectMeta::new(key.to_string(), new_size, lm);
        obj.etag = Some(etag);
        obj.metadata = metadata.unwrap_or_default();
        Ok(obj)
    }

    fn put_object_sync(
        &self,
        bucket_name: &str,
        key: &str,
        data: &[u8],
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(key)?;

        let tmp_dir = self.tmp_dir();
        std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let mut hasher = Md5::new();
        hasher.update(data);
        let etag = format!("{:x}", hasher.finalize());

        std::fs::write(&tmp_path, data).map_err(StorageError::Io)?;
        let new_size = data.len() as u64;

        self.finalize_put_sync(bucket_name, key, &tmp_path, etag, new_size, metadata)
    }
}

enum Either {
    File(usize),
    Dir(usize),
}

impl crate::traits::StorageEngine for FsStorageBackend {
    async fn list_buckets(&self) -> StorageResult<Vec<BucketMeta>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let mut buckets = Vec::new();
            let entries = std::fs::read_dir(&root).map_err(StorageError::Io)?;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();
                if name_str == SYSTEM_ROOT {
                    continue;
                }
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if !ft.is_dir() {
                    continue;
                }
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let created = meta
                    .created()
                    .or_else(|_| meta.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        Utc.timestamp_opt(d.as_secs() as i64, d.subsec_nanos())
                            .single()
                            .unwrap_or_else(Utc::now)
                    })
                    .unwrap_or_else(Utc::now);
                buckets.push(BucketMeta {
                    name: name_str,
                    creation_date: created,
                });
            }
            buckets.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(buckets)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    async fn create_bucket(&self, name: &str) -> StorageResult<()> {
        if let Some(err) = validation::validate_bucket_name(name) {
            return Err(StorageError::InvalidBucketName(err));
        }
        let bucket_path = self.bucket_path(name);
        if bucket_path.exists() {
            return Err(StorageError::BucketAlreadyExists(name.to_string()));
        }
        std::fs::create_dir_all(&bucket_path).map_err(StorageError::Io)?;
        std::fs::create_dir_all(self.system_bucket_root(name)).map_err(StorageError::Io)?;
        Ok(())
    }

    async fn delete_bucket(&self, name: &str) -> StorageResult<()> {
        let bucket_path = self.require_bucket(name)?;
        let (has_objects, has_versions, has_multipart) =
            self.check_bucket_contents_sync(&bucket_path);
        if has_objects {
            return Err(StorageError::BucketNotEmpty(name.to_string()));
        }
        if has_versions {
            return Err(StorageError::BucketNotEmpty(
                "Bucket contains archived object versions".to_string(),
            ));
        }
        if has_multipart {
            return Err(StorageError::BucketNotEmpty(
                "Bucket has active multipart uploads".to_string(),
            ));
        }

        Self::remove_tree(&bucket_path);
        Self::remove_tree(&self.system_bucket_root(name));
        Self::remove_tree(&self.multipart_bucket_root(name));

        self.bucket_config_cache.remove(name);
        self.stats_cache.remove(name);

        Ok(())
    }

    async fn bucket_exists(&self, name: &str) -> StorageResult<bool> {
        Ok(self.bucket_path(name).exists())
    }

    async fn bucket_stats(&self, name: &str) -> StorageResult<BucketStats> {
        self.bucket_stats_sync(name)
    }

    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        mut stream: AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(key)?;

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(StorageError::Io)?;
        let mut hasher = Md5::new();
        let mut total_size: u64 = 0;
        let mut buf = [0u8; 65536];
        loop {
            let n = stream.read(&mut buf).await.map_err(StorageError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n])
                .await
                .map_err(StorageError::Io)?;
            total_size += n as u64;
        }
        tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(StorageError::Io)?;
        drop(file);

        let etag = format!("{:x}", hasher.finalize());
        self.finalize_put_sync(bucket, key, &tmp_path, etag, total_size, metadata)
    }

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let path = self.object_path(bucket, key)?;
        if !path.is_file() {
            return Err(StorageError::ObjectNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }

        let meta = std::fs::metadata(&path).map_err(StorageError::Io)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let lm = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);

        let stored_meta = self.read_metadata_sync(bucket, key);
        let mut obj = ObjectMeta::new(key.to_string(), meta.len(), lm);
        obj.etag = stored_meta.get("__etag__").cloned();
        obj.content_type = stored_meta.get("__content_type__").cloned();
        obj.storage_class = stored_meta
            .get("__storage_class__")
            .cloned()
            .or_else(|| Some("STANDARD".to_string()));
        obj.metadata = stored_meta
            .into_iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .collect();

        let file = tokio::fs::File::open(&path)
            .await
            .map_err(StorageError::Io)?;
        let stream: AsyncReadStream = Box::pin(file);
        Ok((obj, stream))
    }

    async fn get_object_path(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        let path = self.object_path(bucket, key)?;
        if !path.is_file() {
            return Err(StorageError::ObjectNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }
        Ok(path)
    }

    async fn head_object(&self, bucket: &str, key: &str) -> StorageResult<ObjectMeta> {
        let path = self.object_path(bucket, key)?;
        if !path.is_file() {
            return Err(StorageError::ObjectNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }

        let meta = std::fs::metadata(&path).map_err(StorageError::Io)?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let lm = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);

        let stored_meta = self.read_metadata_sync(bucket, key);
        let mut obj = ObjectMeta::new(key.to_string(), meta.len(), lm);
        obj.etag = stored_meta.get("__etag__").cloned();
        obj.content_type = stored_meta.get("__content_type__").cloned();
        obj.storage_class = stored_meta
            .get("__storage_class__")
            .cloned()
            .or_else(|| Some("STANDARD".to_string()));
        obj.metadata = stored_meta
            .into_iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .collect();
        Ok(obj)
    }

    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
        let obj = self.object_meta_from_version_record(key, &record, &data_path)?;
        let file = tokio::fs::File::open(&data_path)
            .await
            .map_err(StorageError::Io)?;
        let stream: AsyncReadStream = Box::pin(file);
        Ok((obj, stream))
    }

    async fn get_object_version_path(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<PathBuf> {
        let (_record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
        Ok(data_path)
    }

    async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<ObjectMeta> {
        let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
        self.object_meta_from_version_record(key, &record, &data_path)
    }

    async fn get_object_version_metadata(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<HashMap<String, String>> {
        let (record, _data_path) = self.read_version_record_sync(bucket, key, version_id)?;
        Ok(Self::version_metadata_from_record(&record))
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> StorageResult<()> {
        let bucket_path = self.require_bucket(bucket)?;
        let path = self.object_path(bucket, key)?;
        if !path.exists() {
            return Ok(());
        }

        let versioning_enabled = self.read_bucket_config_sync(bucket).versioning_enabled;
        if versioning_enabled {
            self.archive_current_version_sync(bucket, key, "delete")
                .map_err(StorageError::Io)?;
        }

        Self::safe_unlink(&path).map_err(StorageError::Io)?;
        self.delete_metadata_sync(bucket, key)
            .map_err(StorageError::Io)?;

        Self::cleanup_empty_parents(&path, &bucket_path);
        Ok(())
    }

    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<()> {
        self.require_bucket(bucket)?;
        self.validate_key(key)?;
        Self::validate_version_id(bucket, key, version_id)?;
        let (manifest_path, data_path) = self.version_record_paths(bucket, key, version_id);
        if !manifest_path.is_file() && !data_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }

        Self::safe_unlink(&data_path).map_err(StorageError::Io)?;
        Self::safe_unlink(&manifest_path).map_err(StorageError::Io)?;
        let versions_root = self.bucket_versions_root(bucket);
        Self::cleanup_empty_parents(&manifest_path, &versions_root);
        self.stats_cache.remove(bucket);
        Ok(())
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> StorageResult<ObjectMeta> {
        let src_path = self.object_path(src_bucket, src_key)?;
        if !src_path.is_file() {
            return Err(StorageError::ObjectNotFound {
                bucket: src_bucket.to_string(),
                key: src_key.to_string(),
            });
        }

        let data = std::fs::read(&src_path).map_err(StorageError::Io)?;
        let src_metadata = self.read_metadata_sync(src_bucket, src_key);
        self.put_object_sync(dst_bucket, dst_key, &data, Some(src_metadata))
    }

    async fn get_object_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<HashMap<String, String>> {
        Ok(self.read_metadata_sync(bucket, key))
    }

    async fn put_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
        let meta_map: serde_json::Map<String, Value> = metadata
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        entry.insert("metadata".to_string(), Value::Object(meta_map));
        self.write_index_entry_sync(bucket, key, &entry)
            .map_err(StorageError::Io)?;
        Ok(())
    }

    async fn list_objects(
        &self,
        bucket: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        self.list_objects_sync(bucket, params)
    }

    async fn list_objects_shallow(
        &self,
        bucket: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult> {
        self.list_objects_shallow_sync(bucket, params)
    }

    async fn initiate_multipart(
        &self,
        bucket: &str,
        key: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<String> {
        self.require_bucket(bucket)?;
        self.validate_key(key)?;

        let upload_id = Uuid::new_v4().to_string().replace('-', "");
        let upload_dir = self.multipart_bucket_root(bucket).join(&upload_id);
        std::fs::create_dir_all(&upload_dir).map_err(StorageError::Io)?;

        let manifest = serde_json::json!({
            "upload_id": upload_id,
            "object_key": key,
            "metadata": metadata.unwrap_or_default(),
            "created_at": Utc::now().to_rfc3339(),
            "parts": {}
        });

        let manifest_path = upload_dir.join(MANIFEST_FILE);
        Self::atomic_write_json_sync(&manifest_path, &manifest, true).map_err(StorageError::Io)?;

        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        mut stream: AsyncReadStream,
    ) -> StorageResult<String> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let part_file = upload_dir.join(format!("part-{:05}.part", part_number));
        let tmp_file = upload_dir.join(format!("part-{:05}.part.tmp", part_number));

        let mut file = tokio::fs::File::create(&tmp_file)
            .await
            .map_err(StorageError::Io)?;
        let mut hasher = Md5::new();
        let mut part_size: u64 = 0;
        let mut buf = [0u8; 65536];
        loop {
            let n = stream.read(&mut buf).await.map_err(StorageError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n])
                .await
                .map_err(StorageError::Io)?;
            part_size += n as u64;
        }
        tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(StorageError::Io)?;
        drop(file);

        let etag = format!("{:x}", hasher.finalize());

        tokio::fs::rename(&tmp_file, &part_file)
            .await
            .map_err(StorageError::Io)?;

        let lock_path = upload_dir.join(".manifest.lock");
        let lock = self.get_meta_index_lock(&lock_path.to_string_lossy());
        let _guard = lock.lock();

        let manifest_content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let mut manifest: Value =
            serde_json::from_str(&manifest_content).map_err(StorageError::Json)?;

        if let Some(parts) = manifest.get_mut("parts").and_then(|p| p.as_object_mut()) {
            parts.insert(
                part_number.to_string(),
                serde_json::json!({
                    "etag": etag,
                    "size": part_size,
                    "filename": format!("part-{:05}.part", part_number),
                }),
            );
        }

        Self::atomic_write_json_sync(&manifest_path, &manifest, true).map_err(StorageError::Io)?;

        Ok(etag)
    }

    async fn upload_part_copy(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        src_bucket: &str,
        src_key: &str,
        range: Option<(u64, u64)>,
    ) -> StorageResult<(String, DateTime<Utc>)> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let src_path = self.object_path(src_bucket, src_key)?;
        if !src_path.is_file() {
            return Err(StorageError::ObjectNotFound {
                bucket: src_bucket.to_string(),
                key: src_key.to_string(),
            });
        }

        let src_meta = std::fs::metadata(&src_path).map_err(StorageError::Io)?;
        let src_size = src_meta.len();
        let src_mtime = src_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let last_modified = Utc
            .timestamp_opt(
                src_mtime as i64,
                ((src_mtime % 1.0) * 1_000_000_000.0) as u32,
            )
            .single()
            .unwrap_or_else(Utc::now);

        let (start, end) = match range {
            Some((s, e)) => {
                if s >= src_size || e >= src_size || s > e {
                    return Err(StorageError::InvalidRange);
                }
                (s, e)
            }
            None => {
                if src_size == 0 {
                    (0u64, 0u64)
                } else {
                    (0u64, src_size - 1)
                }
            }
        };
        let length = if src_size == 0 { 0 } else { end - start + 1 };

        let part_file = upload_dir.join(format!("part-{:05}.part", part_number));
        let tmp_file = upload_dir.join(format!("part-{:05}.part.tmp", part_number));

        let mut src = tokio::fs::File::open(&src_path)
            .await
            .map_err(StorageError::Io)?;
        if start > 0 {
            tokio::io::AsyncSeekExt::seek(&mut src, std::io::SeekFrom::Start(start))
                .await
                .map_err(StorageError::Io)?;
        }

        let mut dst = tokio::fs::File::create(&tmp_file)
            .await
            .map_err(StorageError::Io)?;
        let mut hasher = Md5::new();
        let mut remaining = length;
        let mut buf = vec![0u8; 65536];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining as usize, buf.len());
            let n = src
                .read(&mut buf[..to_read])
                .await
                .map_err(StorageError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            tokio::io::AsyncWriteExt::write_all(&mut dst, &buf[..n])
                .await
                .map_err(StorageError::Io)?;
            remaining -= n as u64;
        }
        tokio::io::AsyncWriteExt::flush(&mut dst)
            .await
            .map_err(StorageError::Io)?;
        drop(dst);

        let etag = format!("{:x}", hasher.finalize());

        tokio::fs::rename(&tmp_file, &part_file)
            .await
            .map_err(StorageError::Io)?;

        let lock_path = upload_dir.join(".manifest.lock");
        let lock = self.get_meta_index_lock(&lock_path.to_string_lossy());
        let _guard = lock.lock();

        let manifest_content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let mut manifest: Value =
            serde_json::from_str(&manifest_content).map_err(StorageError::Json)?;

        if let Some(parts) = manifest.get_mut("parts").and_then(|p| p.as_object_mut()) {
            parts.insert(
                part_number.to_string(),
                serde_json::json!({
                    "etag": etag,
                    "size": length,
                    "filename": format!("part-{:05}.part", part_number),
                }),
            );
        }

        Self::atomic_write_json_sync(&manifest_path, &manifest, true).map_err(StorageError::Io)?;

        Ok((etag, last_modified))
    }

    async fn complete_multipart(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[PartInfo],
    ) -> StorageResult<ObjectMeta> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let manifest_content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let manifest: Value =
            serde_json::from_str(&manifest_content).map_err(StorageError::Json)?;

        let object_key = manifest
            .get("object_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StorageError::Internal("Missing object_key in manifest".to_string()))?
            .to_string();

        let metadata: HashMap<String, String> = manifest
            .get("metadata")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let mut out_file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(StorageError::Io)?;
        let mut md5_digest_concat = Vec::new();
        let mut total_size: u64 = 0;
        let part_count = parts.len();

        for part_info in parts {
            let part_file = upload_dir.join(format!("part-{:05}.part", part_info.part_number));
            if !part_file.exists() {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(StorageError::InvalidObjectKey(format!(
                    "Part {} not found",
                    part_info.part_number
                )));
            }
            let mut part_reader = tokio::fs::File::open(&part_file)
                .await
                .map_err(StorageError::Io)?;
            let mut part_hasher = Md5::new();
            let mut buf = [0u8; 65536];
            loop {
                let n = part_reader.read(&mut buf).await.map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                part_hasher.update(&buf[..n]);
                tokio::io::AsyncWriteExt::write_all(&mut out_file, &buf[..n])
                    .await
                    .map_err(StorageError::Io)?;
                total_size += n as u64;
            }
            md5_digest_concat.extend_from_slice(&part_hasher.finalize());
        }

        tokio::io::AsyncWriteExt::flush(&mut out_file)
            .await
            .map_err(StorageError::Io)?;
        drop(out_file);

        let mut composite_hasher = Md5::new();
        composite_hasher.update(&md5_digest_concat);
        let etag = format!("{:x}-{}", composite_hasher.finalize(), part_count);

        let result = self.finalize_put_sync(
            bucket,
            &object_key,
            &tmp_path,
            etag,
            total_size,
            Some(metadata),
        )?;

        let _ = std::fs::remove_dir_all(&upload_dir);

        Ok(result)
    }

    async fn abort_multipart(&self, bucket: &str, upload_id: &str) -> StorageResult<()> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        if upload_dir.exists() {
            std::fs::remove_dir_all(&upload_dir).map_err(StorageError::Io)?;
        }
        Ok(())
    }

    async fn list_parts(&self, bucket: &str, upload_id: &str) -> StorageResult<Vec<PartMeta>> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let manifest: Value = serde_json::from_str(&content).map_err(StorageError::Json)?;

        let mut parts = Vec::new();
        if let Some(Value::Object(parts_map)) = manifest.get("parts") {
            for (num_str, info) in parts_map {
                let part_number: u32 = num_str.parse().unwrap_or(0);
                let etag = info
                    .get("etag")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = info.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                parts.push(PartMeta {
                    part_number,
                    etag,
                    size,
                    last_modified: None,
                });
            }
        }

        parts.sort_by_key(|p| p.part_number);
        Ok(parts)
    }

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> StorageResult<Vec<MultipartUploadInfo>> {
        let uploads_root = self.multipart_bucket_root(bucket);
        if !uploads_root.exists() {
            return Ok(Vec::new());
        }

        let mut uploads = Vec::new();
        let entries = std::fs::read_dir(&uploads_root).map_err(StorageError::Io)?;
        for entry in entries.flatten() {
            if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                continue;
            }
            let upload_id = entry.file_name().to_string_lossy().to_string();
            let manifest_path = entry.path().join(MANIFEST_FILE);
            if !manifest_path.exists() {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<Value>(&content) {
                    let key = manifest
                        .get("object_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let created = manifest
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or_else(Utc::now);
                    uploads.push(MultipartUploadInfo {
                        upload_id,
                        key,
                        initiated: created,
                    });
                }
            }
        }

        Ok(uploads)
    }

    async fn get_bucket_config(&self, bucket: &str) -> StorageResult<BucketConfig> {
        self.require_bucket(bucket)?;
        Ok(self.read_bucket_config_sync(bucket))
    }

    async fn set_bucket_config(&self, bucket: &str, config: &BucketConfig) -> StorageResult<()> {
        self.require_bucket(bucket)?;
        self.write_bucket_config_sync(bucket, config)
            .map_err(StorageError::Io)
    }

    async fn is_versioning_enabled(&self, bucket: &str) -> StorageResult<bool> {
        Ok(self.read_bucket_config_sync(bucket).versioning_enabled)
    }

    async fn set_versioning(&self, bucket: &str, enabled: bool) -> StorageResult<()> {
        self.require_bucket(bucket)?;
        let mut config = self.read_bucket_config_sync(bucket);
        config.versioning_enabled = enabled;
        self.write_bucket_config_sync(bucket, &config)
            .map_err(StorageError::Io)
    }

    async fn list_object_versions(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<Vec<VersionInfo>> {
        self.require_bucket(bucket)?;
        let version_dir = self.version_dir(bucket, key);
        if !version_dir.exists() {
            return Ok(Vec::new());
        }

        let mut versions = Vec::new();
        let entries = std::fs::read_dir(&version_dir).map_err(StorageError::Io)?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".json") {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(record) = serde_json::from_str::<Value>(&content) {
                    versions.push(self.version_info_from_record(key, &record));
                }
            }
        }

        versions.sort_by(|a, b| b.last_modified.cmp(&a.last_modified));

        Ok(versions)
    }

    async fn list_bucket_object_versions(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> StorageResult<Vec<VersionInfo>> {
        self.require_bucket(bucket)?;
        let root = self.bucket_versions_root(bucket);
        if !root.exists() {
            return Ok(Vec::new());
        }

        let mut versions = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !ft.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let content = match std::fs::read_to_string(&path) {
                    Ok(content) => content,
                    Err(_) => continue,
                };
                let record = match serde_json::from_str::<Value>(&content) {
                    Ok(record) => record,
                    Err(_) => continue,
                };
                let fallback_key = path
                    .parent()
                    .and_then(|parent| parent.strip_prefix(&root).ok())
                    .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                let info = self.version_info_from_record(&fallback_key, &record);
                if prefix.is_some_and(|value| !info.key.starts_with(value)) {
                    continue;
                }
                versions.push(info);
            }
        }

        versions.sort_by(|a, b| {
            a.key
                .cmp(&b.key)
                .then_with(|| b.last_modified.cmp(&a.last_modified))
        });
        Ok(versions)
    }

    async fn get_object_tags(&self, bucket: &str, key: &str) -> StorageResult<Vec<Tag>> {
        self.require_bucket(bucket)?;
        let obj_path = self.object_path(bucket, key)?;
        if !obj_path.exists() {
            return Err(StorageError::ObjectNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }

        let entry = self.read_index_entry_sync(bucket, key);
        if let Some(entry) = entry {
            if let Some(tags_val) = entry.get("tags") {
                if let Ok(tags) = serde_json::from_value::<Vec<Tag>>(tags_val.clone()) {
                    return Ok(tags);
                }
            }
        }
        Ok(Vec::new())
    }

    async fn set_object_tags(&self, bucket: &str, key: &str, tags: &[Tag]) -> StorageResult<()> {
        self.require_bucket(bucket)?;
        let obj_path = self.object_path(bucket, key)?;
        if !obj_path.exists() {
            return Err(StorageError::ObjectNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }

        let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
        if tags.is_empty() {
            entry.remove("tags");
        } else {
            entry.insert(
                "tags".to_string(),
                serde_json::to_value(tags).unwrap_or(Value::Null),
            );
        }

        self.write_index_entry_sync(bucket, key, &entry)
            .map_err(StorageError::Io)?;
        Ok(())
    }

    async fn delete_object_tags(&self, bucket: &str, key: &str) -> StorageResult<()> {
        self.set_object_tags(bucket, key, &[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::StorageEngine;

    fn create_test_backend() -> (tempfile::TempDir, FsStorageBackend) {
        let dir = tempfile::tempdir().unwrap();
        let backend = FsStorageBackend::new(dir.path().to_path_buf());
        (dir, backend)
    }

    #[tokio::test]
    async fn test_create_and_list_buckets() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();
        let buckets = backend.list_buckets().await.unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].name, "test-bucket");
    }

    #[tokio::test]
    async fn test_bucket_exists() {
        let (_dir, backend) = create_test_backend();
        assert!(!backend.bucket_exists("test-bucket").await.unwrap());
        backend.create_bucket("test-bucket").await.unwrap();
        assert!(backend.bucket_exists("test-bucket").await.unwrap());
    }

    #[tokio::test]
    async fn test_bucket_config_reads_legacy_global_policy() {
        let (dir, backend) = create_test_backend();
        backend.create_bucket("legacy-policy").await.unwrap();
        let config_dir = dir.path().join(".myfsio.sys").join("config");
        let policy_path = config_dir.join("bucket_policies.json");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            &policy_path,
            serde_json::json!({
                "policies": {
                    "legacy-policy": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::legacy-policy/*"
                        }]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let config = backend.get_bucket_config("legacy-policy").await.unwrap();
        assert!(config.policy.is_some());
        assert_eq!(
            config
                .policy
                .as_ref()
                .and_then(|p| p.get("Version"))
                .and_then(Value::as_str),
            Some("2012-10-17")
        );

        let mut config = config;
        config.policy = None;
        backend
            .set_bucket_config("legacy-policy", &config)
            .await
            .unwrap();
        let legacy_file =
            serde_json::from_str::<Value>(&std::fs::read_to_string(policy_path).unwrap()).unwrap();
        assert!(legacy_file
            .get("policies")
            .and_then(|policies| policies.get("legacy-policy"))
            .is_none());
        assert!(backend
            .get_bucket_config("legacy-policy")
            .await
            .unwrap()
            .policy
            .is_none());
    }

    #[tokio::test]
    async fn test_delete_bucket() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();
        backend.delete_bucket("test-bucket").await.unwrap();
        assert!(!backend.bucket_exists("test-bucket").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_nonempty_bucket_fails() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, None)
            .await
            .unwrap();
        let result = backend.delete_bucket("test-bucket").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_and_get_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello world".to_vec()));
        let meta = backend
            .put_object("test-bucket", "greeting.txt", data, None)
            .await
            .unwrap();
        assert_eq!(meta.size, 11);
        assert!(meta.etag.is_some());

        let (obj, mut stream) = backend
            .get_object("test-bucket", "greeting.txt")
            .await
            .unwrap();
        assert_eq!(obj.size, 11);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[tokio::test]
    async fn test_head_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"test data".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, None)
            .await
            .unwrap();

        let meta = backend
            .head_object("test-bucket", "file.txt")
            .await
            .unwrap();
        assert_eq!(meta.size, 9);
        assert!(meta.etag.is_some());
    }

    #[tokio::test]
    async fn test_delete_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"delete me".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, None)
            .await
            .unwrap();

        backend
            .delete_object("test-bucket", "file.txt")
            .await
            .unwrap();
        let result = backend.head_object("test-bucket", "file.txt").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_object_with_metadata() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let mut user_meta = HashMap::new();
        user_meta.insert("x-amz-meta-custom".to_string(), "myvalue".to_string());
        user_meta.insert("__content_type__".to_string(), "text/plain".to_string());

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, Some(user_meta))
            .await
            .unwrap();

        let stored = backend
            .get_object_metadata("test-bucket", "file.txt")
            .await
            .unwrap();
        assert_eq!(stored.get("x-amz-meta-custom").unwrap(), "myvalue");
        assert_eq!(stored.get("__content_type__").unwrap(), "text/plain");
        assert!(stored.contains_key("__etag__"));
    }

    #[tokio::test]
    async fn test_list_objects() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        for name in &["a.txt", "b.txt", "c.txt"] {
            let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
            backend
                .put_object("test-bucket", name, data, None)
                .await
                .unwrap();
        }

        let result = backend
            .list_objects("test-bucket", &ListParams::default())
            .await
            .unwrap();
        assert_eq!(result.objects.len(), 3);
        assert_eq!(result.objects[0].key, "a.txt");
        assert_eq!(result.objects[1].key, "b.txt");
        assert_eq!(result.objects[2].key, "c.txt");
        assert!(!result.is_truncated);
    }

    #[tokio::test]
    async fn test_list_objects_with_prefix() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        for name in &["docs/a.txt", "docs/b.txt", "images/c.png"] {
            let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
            backend
                .put_object("test-bucket", name, data, None)
                .await
                .unwrap();
        }

        let params = ListParams {
            prefix: Some("docs/".to_string()),
            ..Default::default()
        };
        let result = backend.list_objects("test-bucket", &params).await.unwrap();
        assert_eq!(result.objects.len(), 2);
    }

    #[tokio::test]
    async fn test_list_objects_pagination() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        for i in 0..5 {
            let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
            backend
                .put_object("test-bucket", &format!("file{}.txt", i), data, None)
                .await
                .unwrap();
        }

        let params = ListParams {
            max_keys: 2,
            ..Default::default()
        };
        let result = backend.list_objects("test-bucket", &params).await.unwrap();
        assert_eq!(result.objects.len(), 2);
        assert!(result.is_truncated);
        assert!(result.next_continuation_token.is_some());

        let params2 = ListParams {
            max_keys: 2,
            continuation_token: result.next_continuation_token,
            ..Default::default()
        };
        let result2 = backend.list_objects("test-bucket", &params2).await.unwrap();
        assert_eq!(result2.objects.len(), 2);
        assert!(result2.is_truncated);
    }

    #[tokio::test]
    async fn test_copy_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("src-bucket").await.unwrap();
        backend.create_bucket("dst-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"copy me".to_vec()));
        backend
            .put_object("src-bucket", "original.txt", data, None)
            .await
            .unwrap();

        backend
            .copy_object("src-bucket", "original.txt", "dst-bucket", "copied.txt")
            .await
            .unwrap();

        let (_, mut stream) = backend
            .get_object("dst-bucket", "copied.txt")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"copy me");
    }

    #[tokio::test]
    async fn test_multipart_upload() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let upload_id = backend
            .initiate_multipart("test-bucket", "big-file.bin", None)
            .await
            .unwrap();

        let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(b"part1-data".to_vec()));
        let etag1 = backend
            .upload_part("test-bucket", &upload_id, 1, part1)
            .await
            .unwrap();

        let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(b"part2-data".to_vec()));
        let etag2 = backend
            .upload_part("test-bucket", &upload_id, 2, part2)
            .await
            .unwrap();

        let parts = vec![
            PartInfo {
                part_number: 1,
                etag: etag1,
            },
            PartInfo {
                part_number: 2,
                etag: etag2,
            },
        ];

        let result = backend
            .complete_multipart("test-bucket", &upload_id, &parts)
            .await
            .unwrap();
        assert_eq!(result.size, 20);

        let (_, mut stream) = backend
            .get_object("test-bucket", "big-file.bin")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"part1-datapart2-data");
    }

    #[tokio::test]
    async fn test_versioning() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();
        backend.set_versioning("test-bucket", true).await.unwrap();

        let data1: AsyncReadStream = Box::pin(std::io::Cursor::new(b"version1".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data1, None)
            .await
            .unwrap();

        let data2: AsyncReadStream = Box::pin(std::io::Cursor::new(b"version2".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data2, None)
            .await
            .unwrap();

        let versions = backend
            .list_object_versions("test-bucket", "file.txt")
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].size, 8);

        let invalid_version = format!("../other/{}", versions[0].version_id);
        let result = backend
            .get_object_version("test-bucket", "file.txt", &invalid_version)
            .await;
        assert!(matches!(result, Err(StorageError::VersionNotFound { .. })));
    }

    #[tokio::test]
    async fn test_invalid_bucket_name() {
        let (_dir, backend) = create_test_backend();
        let result = backend.create_bucket("AB").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_bucket_stats() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"hello".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, None)
            .await
            .unwrap();

        let stats = backend.bucket_stats("test-bucket").await.unwrap();
        assert_eq!(stats.objects, 1);
        assert_eq!(stats.bytes, 5);
    }
}
