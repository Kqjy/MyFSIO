use crate::error::StorageError;
use crate::traits::{AsyncReadStream, StorageResult};
use crate::validation;
use myfsio_common::constants::*;
use myfsio_common::types::*;

use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use md5::{Digest, Md5};
use parking_lot::{Mutex, RwLock};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

const EMPTY_SEGMENT_SENTINEL: &str = ".__myfsio_empty__";

fn fs_encode_key(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let trailing = key.ends_with('/');
    let body = if trailing { &key[..key.len() - 1] } else { key };
    if body.is_empty() {
        return if trailing { "/".to_string() } else { String::new() };
    }
    let encoded: Vec<String> = body
        .split('/')
        .map(|seg| {
            if seg.is_empty() {
                EMPTY_SEGMENT_SENTINEL.to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();
    let mut result = encoded.join("/");
    if trailing {
        result.push('/');
    }
    result
}

fn fs_decode_key(rel_path: &str) -> String {
    let normalized: String;
    let input = if cfg!(windows) && rel_path.contains('\\') {
        normalized = rel_path.replace('\\', "/");
        normalized.as_str()
    } else {
        rel_path
    };
    input
        .split('/')
        .map(|seg| {
            if seg == EMPTY_SEGMENT_SENTINEL {
                ""
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn validate_list_prefix(prefix: &str) -> StorageResult<()> {
    if prefix.contains('\0') {
        return Err(StorageError::InvalidObjectKey(
            "prefix contains null bytes".to_string(),
        ));
    }
    if prefix.starts_with('/') || prefix.starts_with('\\') {
        return Err(StorageError::InvalidObjectKey(
            "prefix cannot start with a slash".to_string(),
        ));
    }
    for part in prefix.split(['/', '\\']) {
        if part == ".." {
            return Err(StorageError::InvalidObjectKey(
                "prefix contains parent directory references".to_string(),
            ));
        }
    }
    Ok(())
}

fn run_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

fn slice_range_for_prefix<T, F>(items: &[T], key_of: F, prefix: &str) -> (usize, usize)
where
    F: Fn(&T) -> &str,
{
    if prefix.is_empty() {
        return (0, items.len());
    }
    let start = items.partition_point(|item| key_of(item) < prefix);
    let end_from_start = items[start..]
        .iter()
        .position(|item| !key_of(item).starts_with(prefix))
        .map(|p| start + p)
        .unwrap_or(items.len());
    (start, end_from_start)
}

fn normalize_path(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Some(out)
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    match (normalize_path(candidate), normalize_path(root)) {
        (Some(c), Some(r)) => c.starts_with(&r),
        _ => false,
    }
}

type ListCacheEntry = (String, u64, f64, Option<String>, Option<String>);

#[derive(Clone, Default)]
struct ShallowCacheEntry {
    files: Vec<ObjectMeta>,
    dirs: Vec<String>,
}

const OBJECT_LOCK_STRIPES: usize = 2048;

pub struct FsStorageBackend {
    root: PathBuf,
    object_key_max_length_bytes: usize,
    object_cache_max_size: usize,
    stream_chunk_size: usize,
    bucket_config_cache: DashMap<String, (BucketConfig, Instant)>,
    bucket_config_cache_ttl: std::time::Duration,
    meta_read_cache: DashMap<(String, String), Option<HashMap<String, Value>>>,
    meta_index_locks: DashMap<String, Arc<Mutex<()>>>,
    object_lock_stripes: Box<[RwLock<()>]>,
    stats_cache: DashMap<String, (BucketStats, Instant)>,
    stats_cache_ttl: std::time::Duration,
    list_cache: DashMap<String, (Arc<Vec<ListCacheEntry>>, Instant)>,
    shallow_cache: DashMap<(String, PathBuf, String), (Arc<ShallowCacheEntry>, Instant)>,
    list_rebuild_locks: DashMap<String, Arc<Mutex<()>>>,
    shallow_rebuild_locks: DashMap<(String, PathBuf, String), Arc<Mutex<()>>>,
    list_cache_ttl: std::time::Duration,
}

#[derive(Debug, Clone)]
pub struct FsStorageBackendConfig {
    pub object_key_max_length_bytes: usize,
    pub object_cache_max_size: usize,
    pub bucket_config_cache_ttl: std::time::Duration,
    pub stream_chunk_size: usize,
}

impl Default for FsStorageBackendConfig {
    fn default() -> Self {
        Self {
            object_key_max_length_bytes: DEFAULT_OBJECT_KEY_MAX_BYTES,
            object_cache_max_size: 100,
            bucket_config_cache_ttl: std::time::Duration::from_secs(30),
            stream_chunk_size: STREAM_CHUNK_SIZE,
        }
    }
}

impl FsStorageBackend {
    pub fn new(root: PathBuf) -> Self {
        Self::new_with_config(root, FsStorageBackendConfig::default())
    }

    pub fn new_with_config(root: PathBuf, config: FsStorageBackendConfig) -> Self {
        let stream_chunk_size = if config.stream_chunk_size == 0 {
            STREAM_CHUNK_SIZE
        } else {
            config.stream_chunk_size
        };
        let object_lock_stripes = (0..OBJECT_LOCK_STRIPES)
            .map(|_| RwLock::new(()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let backend = Self {
            root,
            object_key_max_length_bytes: config.object_key_max_length_bytes,
            object_cache_max_size: config.object_cache_max_size,
            stream_chunk_size,
            bucket_config_cache: DashMap::new(),
            bucket_config_cache_ttl: config.bucket_config_cache_ttl,
            meta_read_cache: DashMap::new(),
            meta_index_locks: DashMap::new(),
            object_lock_stripes,
            stats_cache: DashMap::new(),
            stats_cache_ttl: std::time::Duration::from_secs(60),
            list_cache: DashMap::new(),
            shallow_cache: DashMap::new(),
            list_rebuild_locks: DashMap::new(),
            shallow_rebuild_locks: DashMap::new(),
            list_cache_ttl: std::time::Duration::from_secs(5),
        };
        backend.ensure_system_roots();
        backend
    }

    fn invalidate_bucket_caches(&self, bucket_name: &str) {
        self.stats_cache.remove(bucket_name);
        self.list_cache.remove(bucket_name);
        self.shallow_cache.retain(|(b, _, _), _| b != bucket_name);
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
        let encoded = fs_encode_key(object_key);
        if object_key.ends_with('/') {
            let trimmed = encoded.trim_end_matches('/');
            Ok(self
                .bucket_path(bucket_name)
                .join(trimmed)
                .join(DIR_MARKER_FILE))
        } else {
            Ok(self.bucket_path(bucket_name).join(&encoded))
        }
    }

    fn object_live_path(&self, bucket_name: &str, object_key: &str) -> PathBuf {
        let encoded = fs_encode_key(object_key);
        if object_key.ends_with('/') {
            let trimmed = encoded.trim_end_matches('/');
            self.bucket_path(bucket_name)
                .join(trimmed)
                .join(DIR_MARKER_FILE)
        } else {
            self.bucket_path(bucket_name).join(&encoded)
        }
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
        if key.ends_with('/') {
            let encoded = fs_encode_key(key);
            let trimmed = encoded.trim_end_matches('/');
            if trimmed.is_empty() {
                return (meta_root.join(INDEX_FILE), DIR_MARKER_FILE.to_string());
            }
            return (
                meta_root.join(trimmed).join(INDEX_FILE),
                DIR_MARKER_FILE.to_string(),
            );
        }
        let encoded = fs_encode_key(key);
        let encoded_path = Path::new(&encoded);
        let entry_name = encoded_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| encoded.clone());

        let parent = encoded_path.parent();
        match parent {
            Some(p) if p != Path::new("") && p != Path::new(".") => {
                (meta_root.join(p).join(INDEX_FILE), entry_name)
            }
            _ => (meta_root.join(INDEX_FILE), entry_name),
        }
    }

    fn index_file_for_dir(&self, bucket_name: &str, rel_dir: &Path) -> PathBuf {
        let meta_root = self.bucket_meta_root(bucket_name);
        if rel_dir.as_os_str().is_empty() || rel_dir == Path::new(".") {
            meta_root.join(INDEX_FILE)
        } else {
            meta_root.join(rel_dir).join(INDEX_FILE)
        }
    }

    fn load_dir_index_sync(&self, bucket_name: &str, rel_dir: &Path) -> HashMap<String, String> {
        let index_path = self.index_file_for_dir(bucket_name, rel_dir);
        if !index_path.exists() {
            return HashMap::new();
        }
        let Ok(text) = std::fs::read_to_string(&index_path) else {
            return HashMap::new();
        };
        let Ok(index) = serde_json::from_str::<HashMap<String, Value>>(&text) else {
            return HashMap::new();
        };
        let mut out = HashMap::with_capacity(index.len());
        for (name, entry) in index {
            if let Some(etag) = entry
                .get("metadata")
                .and_then(|m| m.get("__etag__"))
                .and_then(|v| v.as_str())
            {
                out.insert(name, etag.to_string());
            }
        }
        out
    }

    fn load_dir_index_full_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
    ) -> HashMap<String, (Option<String>, Option<String>)> {
        let index_path = self.index_file_for_dir(bucket_name, rel_dir);
        if !index_path.exists() {
            return HashMap::new();
        }
        let Ok(text) = std::fs::read_to_string(&index_path) else {
            return HashMap::new();
        };
        let Ok(index) = serde_json::from_str::<HashMap<String, Value>>(&text) else {
            return HashMap::new();
        };
        let mut out = HashMap::with_capacity(index.len());
        for (name, entry) in index {
            let meta = entry.get("metadata").and_then(|m| m.as_object());
            let etag = meta
                .and_then(|m| m.get("__etag__"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            let version_id = meta
                .and_then(|m| m.get("__version_id__"))
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned);
            out.insert(name, (etag, version_id));
        }
        out
    }

    fn get_meta_index_lock(&self, index_path: &str) -> Arc<Mutex<()>> {
        self.meta_index_locks
            .entry(index_path.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn get_object_lock(&self, bucket: &str, key: &str) -> &RwLock<()> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        bucket.hash(&mut h);
        key.hash(&mut h);
        let idx = (h.finish() as usize) % self.object_lock_stripes.len();
        &self.object_lock_stripes[idx]
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
        let encoded = fs_encode_key(key);
        let trimmed = encoded.trim_end_matches('/');
        self.bucket_versions_root(bucket_name).join(trimmed)
    }

    fn delete_markers_root(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name).join("delete_markers")
    }

    fn delete_marker_path(&self, bucket_name: &str, key: &str) -> PathBuf {
        let encoded = fs_encode_key(key);
        let trimmed = encoded.trim_end_matches('/');
        self.delete_markers_root(bucket_name)
            .join(format!("{}.json", trimmed))
    }

    fn read_delete_marker_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> Option<(String, chrono::DateTime<Utc>)> {
        let path = self.delete_marker_path(bucket_name, key);
        if !path.is_file() {
            return None;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        let record: Value = serde_json::from_str(&content).ok()?;
        let version_id = record
            .get("version_id")
            .and_then(Value::as_str)?
            .to_string();
        let last_modified = record
            .get("last_modified")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        Some((version_id, last_modified))
    }

    fn clear_delete_marker_sync(&self, bucket_name: &str, key: &str) {
        let path = self.delete_marker_path(bucket_name, key);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    fn new_version_id_sync() -> String {
        let now = Utc::now();
        format!(
            "{}-{}",
            now.format("%Y%m%dT%H%M%S%6fZ"),
            &Uuid::new_v4().to_string()[..8]
        )
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
            if p == stop_at {
                break;
            }
            if std::fs::remove_dir(p).is_err() {
                break;
            }
            parent = p.parent();
        }
    }

    fn archive_current_version_sync(
        &self,
        bucket_name: &str,
        key: &str,
        reason: &str,
    ) -> std::io::Result<(u64, Option<String>)> {
        let source = self.object_live_path(bucket_name, key);
        if !source.exists() {
            return Ok((0, None));
        }

        let version_dir = self.version_dir(bucket_name, key);
        std::fs::create_dir_all(&version_dir)?;

        let now = Utc::now();
        let metadata = self.read_metadata_sync(bucket_name, key);
        let version_id = metadata
            .get("__version_id__")
            .cloned()
            .filter(|v| !v.is_empty() && !v.contains('/') && !v.contains('\\') && !v.contains(".."))
            .unwrap_or_else(Self::new_version_id_sync);

        let data_path = version_dir.join(format!("{}.bin", version_id));
        std::fs::copy(&source, &data_path)?;

        let source_meta = source.metadata()?;
        let source_size = source_meta.len();

        let etag = Self::compute_etag_sync(&source).unwrap_or_default();

        let live_last_modified = metadata
            .get("__last_modified__")
            .and_then(|value| value.parse::<f64>().ok())
            .map(|mtime| {
                Utc.timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
                    .unwrap_or_else(Utc::now)
            })
            .or_else(|| {
                source_meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        Utc.timestamp_opt(d.as_secs() as i64, d.subsec_nanos())
                            .single()
                            .unwrap_or_else(Utc::now)
                    })
            })
            .unwrap_or(now);

        let record = serde_json::json!({
            "version_id": version_id,
            "key": key,
            "size": source_size,
            "archived_at": now.to_rfc3339(),
            "last_modified": live_last_modified.to_rfc3339(),
            "etag": etag,
            "metadata": metadata,
            "reason": reason,
        });

        let manifest_path = version_dir.join(format!("{}.json", version_id));
        Self::atomic_write_json_sync(&manifest_path, &record, true)?;

        Ok((source_size, Some(version_id)))
    }

    fn promote_latest_archived_to_live_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<Option<String>> {
        let version_dir = self.version_dir(bucket_name, key);
        if !version_dir.exists() {
            return Ok(None);
        }

        let entries = match std::fs::read_dir(&version_dir) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        let mut candidates: Vec<(DateTime<Utc>, String, PathBuf, Value)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_str::<Value>(&content) else {
                continue;
            };
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let version_id = record
                .get("version_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if version_id.is_empty() {
                continue;
            }
            let archived_at = record
                .get("archived_at")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            candidates.push((archived_at, version_id, path, record));
        }

        candidates.sort_by(|a, b| b.0.cmp(&a.0));
        let Some((_, version_id, manifest_path, record)) = candidates.into_iter().next() else {
            return Ok(None);
        };

        let (_, data_path) = self.version_record_paths(bucket_name, key, &version_id);
        if !data_path.is_file() {
            return Ok(None);
        }

        let live_path = self.object_live_path(bucket_name, key);
        if let Some(parent) = live_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if live_path.exists() {
            std::fs::remove_file(&live_path).ok();
        }
        std::fs::rename(&data_path, &live_path)?;

        let mut meta: HashMap<String, String> = record
            .get("metadata")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        meta.insert("__version_id__".to_string(), version_id.clone());
        if !meta.contains_key("__etag__") {
            if let Some(etag) = record.get("etag").and_then(Value::as_str) {
                if !etag.is_empty() {
                    meta.insert("__etag__".to_string(), etag.to_string());
                }
            }
        }
        self.write_metadata_sync(bucket_name, key, &meta)?;

        Self::safe_unlink(&manifest_path)?;
        Self::cleanup_empty_parents(&manifest_path, &self.bucket_versions_root(bucket_name));

        Ok(Some(version_id))
    }

    fn write_delete_marker_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<String> {
        let version_dir = self.version_dir(bucket_name, key);
        std::fs::create_dir_all(&version_dir)?;
        let now = Utc::now();
        let version_id = Self::new_version_id_sync();

        let record = serde_json::json!({
            "version_id": version_id,
            "key": key,
            "size": 0,
            "archived_at": now.to_rfc3339(),
            "etag": "",
            "metadata": HashMap::<String, String>::new(),
            "reason": "delete-marker",
            "is_delete_marker": true,
        });

        let manifest_path = version_dir.join(format!("{}.json", version_id));
        Self::atomic_write_json_sync(&manifest_path, &record, true)?;

        let marker_path = self.delete_marker_path(bucket_name, key);
        if let Some(parent) = marker_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let marker_record = serde_json::json!({
            "version_id": version_id,
            "last_modified": now.to_rfc3339(),
        });
        Self::atomic_write_json_sync(&marker_path, &marker_record, true)?;
        Ok(version_id)
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

        if let Some(record_and_path) = self.try_live_version_record_sync(bucket_name, key, version_id) {
            return Ok(record_and_path);
        }

        let (manifest_path, data_path) = self.version_record_paths(bucket_name, key, version_id);
        if !manifest_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }

        let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let record = serde_json::from_str::<Value>(&content).map_err(StorageError::Json)?;
        let is_delete_marker = record
            .get("is_delete_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !is_delete_marker && !data_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }
        Ok((record, data_path))
    }

    fn try_live_version_record_sync(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> Option<(Value, PathBuf)> {
        let live_path = self.object_live_path(bucket_name, key);
        if !live_path.is_file() {
            return None;
        }
        let metadata = self.read_metadata_sync(bucket_name, key);
        let live_version = metadata.get("__version_id__")?.clone();
        if live_version != version_id {
            return None;
        }
        let file_meta = std::fs::metadata(&live_path).ok()?;
        let mtime = file_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let archived_at = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);
        let etag = metadata.get("__etag__").cloned().unwrap_or_default();
        let mut meta_json = serde_json::Map::new();
        for (k, v) in &metadata {
            meta_json.insert(k.clone(), Value::String(v.clone()));
        }
        let record = serde_json::json!({
            "version_id": live_version,
            "key": key,
            "size": file_meta.len(),
            "archived_at": archived_at.to_rfc3339(),
            "etag": etag,
            "metadata": Value::Object(meta_json),
            "reason": "current",
            "is_delete_marker": false,
        });
        Some((record, live_path))
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
            .get("last_modified")
            .and_then(Value::as_str)
            .or_else(|| record.get("archived_at").and_then(Value::as_str))
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let etag = record
            .get("etag")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| metadata.get("__etag__").cloned());

        let version_id = record
            .get("version_id")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let is_delete_marker = record
            .get("is_delete_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut obj = ObjectMeta::new(key.to_string(), size, last_modified);
        obj.etag = etag;
        obj.content_type = metadata.get("__content_type__").cloned();
        obj.storage_class = metadata
            .get("__storage_class__")
            .cloned()
            .or_else(|| Some("STANDARD".to_string()));
        obj.metadata = metadata
            .iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        obj.internal_metadata = metadata;
        obj.version_id = version_id;
        obj.is_delete_marker = is_delete_marker;
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
        let last_modified = record
            .get("last_modified")
            .and_then(Value::as_str)
            .or_else(|| record.get("archived_at").and_then(Value::as_str))
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let etag = record
            .get("etag")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let is_delete_marker = record
            .get("is_delete_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        VersionInfo {
            version_id,
            key,
            size,
            last_modified,
            etag,
            is_latest: false,
            is_delete_marker,
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

    fn build_full_listing_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<Arc<Vec<ListCacheEntry>>> {
        let bucket_path = self.require_bucket(bucket_name)?;

        let mut all_keys: Vec<ListCacheEntry> = Vec::new();
        let mut dir_idx_cache: HashMap<PathBuf, HashMap<String, (Option<String>, Option<String>)>> =
            HashMap::new();
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
                    let mut fs_rel = full_path[bucket_prefix_len..].to_string();
                    #[cfg(windows)]
                    {
                        fs_rel = fs_rel.replace('\\', "/");
                    }
                    let is_dir_marker = name_str.as_ref() == DIR_MARKER_FILE;
                    if is_dir_marker {
                        fs_rel = fs_rel
                            .strip_suffix(DIR_MARKER_FILE)
                            .unwrap_or(&fs_rel)
                            .to_string();
                    }
                    if let Ok(meta) = entry.metadata() {
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);

                        let rel_dir = Path::new(&fs_rel)
                            .parent()
                            .map(|p| p.to_path_buf())
                            .unwrap_or_default();
                        let idx = dir_idx_cache.entry(rel_dir.clone()).or_insert_with(|| {
                            self.load_dir_index_full_sync(bucket_name, &rel_dir)
                        });
                        let (etag, version_id) = if is_dir_marker {
                            (None, None)
                        } else {
                            idx.get(name_str.as_ref())
                                .cloned()
                                .unwrap_or((None, None))
                        };

                        let key = fs_decode_key(&fs_rel);
                        all_keys.push((key, meta.len(), mtime, etag, version_id));
                    }
                }
            }
        }

        all_keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Arc::new(all_keys))
    }

    fn get_full_listing_sync(&self, bucket_name: &str) -> StorageResult<Arc<Vec<ListCacheEntry>>> {
        if let Some(entry) = self.list_cache.get(bucket_name) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let lock = self
            .list_rebuild_locks
            .entry(bucket_name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock();

        if let Some(entry) = self.list_cache.get(bucket_name) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let listing = self.build_full_listing_sync(bucket_name)?;
        self.list_cache
            .insert(bucket_name.to_string(), (listing.clone(), Instant::now()));
        Ok(listing)
    }

    fn list_objects_sync(
        &self,
        bucket_name: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        self.require_bucket(bucket_name)?;
        if let Some(ref prefix) = params.prefix {
            if !prefix.is_empty() {
                validate_list_prefix(prefix)?;
            }
        }

        let listing = self.get_full_listing_sync(bucket_name)?;

        let (slice_start, slice_end) = match params.prefix.as_deref() {
            Some(p) if !p.is_empty() => slice_range_for_prefix(&listing[..], |e| &e.0, p),
            _ => (0, listing.len()),
        };
        let prefix_filter = &listing[slice_start..slice_end];

        let start_idx = if let Some(ref token) = params.continuation_token {
            prefix_filter.partition_point(|k| k.0.as_str() <= token.as_str())
        } else if let Some(ref start_after) = params.start_after {
            prefix_filter.partition_point(|k| k.0.as_str() <= start_after.as_str())
        } else {
            0
        };

        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        let end_idx = std::cmp::min(start_idx + max_keys, prefix_filter.len());
        let is_truncated = end_idx < prefix_filter.len();

        let objects: Vec<ObjectMeta> = prefix_filter[start_idx..end_idx]
            .iter()
            .map(|(key, size, mtime, etag, version_id)| {
                let lm = Utc
                    .timestamp_opt(*mtime as i64, ((*mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
                    .unwrap_or_else(Utc::now);
                let mut obj = ObjectMeta::new(key.clone(), *size, lm);
                obj.etag = etag.clone();
                obj.version_id = version_id.clone();
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

    fn build_shallow_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
        delimiter: &str,
    ) -> StorageResult<Arc<ShallowCacheEntry>> {
        let bucket_path = self.require_bucket(bucket_name)?;
        let target_dir = bucket_path.join(rel_dir);

        if !path_is_within(&target_dir, &bucket_path) {
            return Err(StorageError::InvalidObjectKey(
                "prefix escapes bucket root".to_string(),
            ));
        }

        if !target_dir.exists() {
            return Ok(Arc::new(ShallowCacheEntry::default()));
        }

        let dir_etags = self.load_dir_index_sync(bucket_name, rel_dir);

        let mut files = Vec::new();
        let mut dirs = Vec::new();

        let rel_dir_prefix = if rel_dir.as_os_str().is_empty() {
            String::new()
        } else {
            let s = rel_dir.to_string_lossy().into_owned();
            #[cfg(windows)]
            let s = s.replace('\\', "/");
            let mut decoded = fs_decode_key(&s);
            if !decoded.ends_with('/') {
                decoded.push('/');
            }
            decoded
        };

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

            let display_name = fs_decode_key(&name_str);
            if ft.is_dir() {
                let subdir_path = entry.path();
                let marker_path = subdir_path.join(DIR_MARKER_FILE);
                if marker_path.is_file() {
                    if let Ok(meta) = std::fs::metadata(&marker_path) {
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
                        let mut obj = ObjectMeta::new(
                            format!("{}{}/", rel_dir_prefix, display_name),
                            meta.len(),
                            lm,
                        );
                        obj.etag = None;
                        files.push(obj);
                    }
                }
                dirs.push(format!("{}{}{}", rel_dir_prefix, display_name, delimiter));
            } else if ft.is_file() {
                if name_str == DIR_MARKER_FILE {
                    continue;
                }
                let rel = format!("{}{}", rel_dir_prefix, display_name);
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
                    let etag = dir_etags.get(&name_str).cloned();
                    let mut obj = ObjectMeta::new(rel, meta.len(), lm);
                    obj.etag = etag;
                    files.push(obj);
                }
            }
        }

        files.sort_by(|a, b| a.key.cmp(&b.key));
        dirs.sort();
        Ok(Arc::new(ShallowCacheEntry { files, dirs }))
    }

    fn get_shallow_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
        delimiter: &str,
    ) -> StorageResult<Arc<ShallowCacheEntry>> {
        let cache_key = (
            bucket_name.to_string(),
            rel_dir.to_path_buf(),
            delimiter.to_string(),
        );
        if let Some(entry) = self.shallow_cache.get(&cache_key) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let lock = self
            .shallow_rebuild_locks
            .entry(cache_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock();

        if let Some(entry) = self.shallow_cache.get(&cache_key) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let built = self.build_shallow_sync(bucket_name, rel_dir, delimiter)?;
        self.shallow_cache
            .insert(cache_key, (built.clone(), Instant::now()));
        Ok(built)
    }

    fn list_objects_shallow_sync(
        &self,
        bucket_name: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult> {
        self.require_bucket(bucket_name)?;

        let rel_dir: PathBuf = if params.prefix.is_empty() {
            PathBuf::new()
        } else {
            validate_list_prefix(&params.prefix)?;
            let encoded_prefix = fs_encode_key(&params.prefix);
            let prefix_path = Path::new(&encoded_prefix);
            if params.prefix.ends_with(&params.delimiter) {
                prefix_path.to_path_buf()
            } else {
                prefix_path.parent().unwrap_or(Path::new("")).to_path_buf()
            }
        };

        let cached = self.get_shallow_sync(bucket_name, &rel_dir, &params.delimiter)?;

        let (file_start, file_end) =
            slice_range_for_prefix(&cached.files, |o| &o.key, &params.prefix);
        let (dir_start, dir_end) = slice_range_for_prefix(&cached.dirs, |s| s, &params.prefix);
        let files = &cached.files[file_start..file_end];
        let dirs = &cached.dirs[dir_start..dir_end];

        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        let token_filter = |key: &str| -> bool {
            params
                .continuation_token
                .as_deref()
                .map(|t| key > t)
                .unwrap_or(true)
        };

        let file_skip = params
            .continuation_token
            .as_deref()
            .map(|t| files.partition_point(|o| o.key.as_str() <= t))
            .unwrap_or(0);
        let dir_skip = params
            .continuation_token
            .as_deref()
            .map(|t| dirs.partition_point(|d| d.as_str() <= t))
            .unwrap_or(0);

        let mut fi = file_skip;
        let mut di = dir_skip;
        let mut result_objects: Vec<ObjectMeta> = Vec::new();
        let mut result_prefixes: Vec<String> = Vec::new();
        let mut last_key: Option<String> = None;
        let mut total = 0usize;

        while total < max_keys && (fi < files.len() || di < dirs.len()) {
            let take_file = match (fi < files.len(), di < dirs.len()) {
                (true, true) => files[fi].key.as_str() < dirs[di].as_str(),
                (true, false) => true,
                (false, true) => false,
                _ => break,
            };
            if take_file {
                if token_filter(&files[fi].key) {
                    last_key = Some(files[fi].key.clone());
                    result_objects.push(files[fi].clone());
                    total += 1;
                }
                fi += 1;
            } else {
                if token_filter(&dirs[di]) {
                    last_key = Some(dirs[di].clone());
                    result_prefixes.push(dirs[di].clone());
                    total += 1;
                }
                di += 1;
            }
        }

        let remaining = fi < files.len() || di < dirs.len();
        let is_truncated = remaining;
        let next_token = if is_truncated { last_key } else { None };

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
        self.require_bucket(bucket_name)?;
        let destination = self.object_live_path(bucket_name, key);
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

        let versioning_status = bucket_config.versioning_status();
        if is_overwrite {
            match versioning_status {
                VersioningStatus::Enabled => {
                    self.archive_current_version_sync(bucket_name, key, "overwrite")
                        .map_err(StorageError::Io)?;
                }
                VersioningStatus::Suspended => {
                    let existing_meta = self.read_metadata_sync(bucket_name, key);
                    let existing_vid = existing_meta
                        .get("__version_id__")
                        .map(String::as_str)
                        .unwrap_or("");
                    if !existing_vid.is_empty() && existing_vid != "null" {
                        self.archive_current_version_sync(bucket_name, key, "overwrite")
                            .map_err(StorageError::Io)?;
                    }
                }
                VersioningStatus::Disabled => {}
            }
        }

        std::fs::rename(tmp_path, &destination).map_err(|e| {
            let _ = std::fs::remove_file(tmp_path);
            StorageError::Io(e)
        })?;

        self.invalidate_bucket_caches(bucket_name);

        let file_meta = std::fs::metadata(&destination).map_err(StorageError::Io)?;
        let mtime = file_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        let new_version_id = match versioning_status {
            VersioningStatus::Enabled => Some(Self::new_version_id_sync()),
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Disabled => None,
        };

        let mut internal_meta = HashMap::new();
        internal_meta.insert("__etag__".to_string(), etag.clone());
        internal_meta.insert("__size__".to_string(), new_size.to_string());
        internal_meta.insert("__last_modified__".to_string(), mtime.to_string());
        if let Some(ref vid) = new_version_id {
            internal_meta.insert("__version_id__".to_string(), vid.clone());
        }

        if let Some(ref user_meta) = metadata {
            for (k, v) in user_meta {
                internal_meta.insert(k.clone(), v.clone());
            }
        }

        self.write_metadata_sync(bucket_name, key, &internal_meta)
            .map_err(StorageError::Io)?;

        if versioning_status.is_active() {
            self.clear_delete_marker_sync(bucket_name, key);
        }

        let lm = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);

        let mut obj = ObjectMeta::new(key.to_string(), new_size, lm);
        obj.etag = Some(etag);
        obj.metadata = metadata.unwrap_or_default();
        obj.version_id = new_version_id;
        obj.internal_metadata = internal_meta;
        Ok(obj)
    }
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
        self.invalidate_bucket_caches(name);

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
        stream: AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(key)?;

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let chunk_size = self.stream_chunk_size;
        let drain_tmp = tmp_path.clone();

        // Drain request body + MD5 on a blocking thread: one runtime crossing
        // for the whole transfer, not one per 256 KiB chunk.
        let drain_result = tokio::task::spawn_blocking(move || -> StorageResult<(String, u64)> {
            use std::io::{BufWriter, Read, Write};
            let mut reader = tokio_util::io::SyncIoBridge::new(stream);
            let file = std::fs::File::create(&drain_tmp).map_err(StorageError::Io)?;
            let mut writer = BufWriter::with_capacity(chunk_size * 4, file);
            let mut hasher = Md5::new();
            let mut total: u64 = 0;
            let mut buf = vec![0u8; chunk_size];
            loop {
                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                writer.write_all(&buf[..n]).map_err(StorageError::Io)?;
                total += n as u64;
            }
            writer.flush().map_err(StorageError::Io)?;
            Ok((format!("{:x}", hasher.finalize()), total))
        })
        .await;

        let (etag, total_size) = match drain_result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(e);
            }
            Err(join_err) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    join_err,
                )));
            }
        };

        // Commit body+metadata atomically under the per-key write lock. The
        // lock is acquired *inside* run_blocking so the wait happens under
        // block_in_place — if a long-running GET holds the read side, the
        // runtime can migrate other async tasks off this worker instead of
        // parking it.
        let result = run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.finalize_put_sync(bucket, key, &tmp_path, etag, total_size, metadata)
        });

        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp_path).await;
        }
        result
    }

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (obj, file) = run_blocking(|| -> StorageResult<(ObjectMeta, std::fs::File)> {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                if self.read_bucket_config_sync(bucket).versioning_status().is_active() {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            // Open the fd first so that the snapshot we hand back is anchored
            // to this exact inode, even if a concurrent PUT renames over the
            // path after we release the read lock.
            let file = std::fs::File::open(&path).map_err(StorageError::Io)?;
            let meta = file.metadata().map_err(StorageError::Io)?;
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
            obj.version_id = stored_meta.get("__version_id__").cloned();
            obj.metadata = stored_meta
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            obj.internal_metadata = stored_meta;
            Ok((obj, file))
        })?;

        let stream: AsyncReadStream = Box::pin(tokio::fs::File::from_std(file));
        Ok((obj, stream))
    }

    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        len: Option<u64>,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (obj, file) = run_blocking(|| -> StorageResult<(ObjectMeta, std::fs::File)> {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                if self.read_bucket_config_sync(bucket).versioning_status().is_active() {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            use std::io::{Seek, SeekFrom};
            let mut file = std::fs::File::open(&path).map_err(StorageError::Io)?;
            let meta = file.metadata().map_err(StorageError::Io)?;
            if start > meta.len() {
                return Err(StorageError::InvalidRange);
            }
            if start > 0 {
                file.seek(SeekFrom::Start(start)).map_err(StorageError::Io)?;
            }

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
            obj.version_id = stored_meta.get("__version_id__").cloned();
            obj.metadata = stored_meta
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            obj.internal_metadata = stored_meta;
            Ok((obj, file))
        })?;

        let tokio_file = tokio::fs::File::from_std(file);
        let stream: AsyncReadStream = match len {
            Some(n) => {
                use tokio::io::AsyncReadExt;
                Box::pin(tokio_file.take(n))
            }
            None => Box::pin(tokio_file),
        };
        Ok((obj, stream))
    }

    async fn get_object_snapshot(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, tokio::fs::File)> {
        let (obj, file) = run_blocking(|| -> StorageResult<(ObjectMeta, std::fs::File)> {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                if self.read_bucket_config_sync(bucket).versioning_status().is_active() {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            let file = std::fs::File::open(&path).map_err(StorageError::Io)?;
            let meta_fs = file.metadata().map_err(StorageError::Io)?;
            let mtime = meta_fs
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
            let mut obj = ObjectMeta::new(key.to_string(), meta_fs.len(), lm);
            obj.etag = stored_meta.get("__etag__").cloned();
            obj.content_type = stored_meta.get("__content_type__").cloned();
            obj.storage_class = stored_meta
                .get("__storage_class__")
                .cloned()
                .or_else(|| Some("STANDARD".to_string()));
            obj.version_id = stored_meta.get("__version_id__").cloned();
            obj.metadata = stored_meta
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            obj.internal_metadata = stored_meta;
            Ok((obj, file))
        })?;
        Ok((obj, tokio::fs::File::from_std(file)))
    }

    async fn get_object_version_snapshot(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, tokio::fs::File)> {
        let (obj, file) = run_blocking(|| -> StorageResult<(ObjectMeta, std::fs::File)> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            let file = std::fs::File::open(&data_path).map_err(StorageError::Io)?;
            let obj = self.object_meta_from_version_record(key, &record, &data_path)?;
            Ok((obj, file))
        })?;
        Ok((obj, tokio::fs::File::from_std(file)))
    }

    async fn snapshot_object_to_link(
        &self,
        bucket: &str,
        key: &str,
        link_path: &std::path::Path,
    ) -> StorageResult<ObjectMeta> {
        let link_owned = link_path.to_owned();
        run_blocking(|| -> StorageResult<ObjectMeta> {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                if self.read_bucket_config_sync(bucket).versioning_status().is_active() {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            if let Some(parent) = link_owned.parent() {
                std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
            }
            // The hardlink shares the inode of the file *at this moment*.
            // Later renames replace the live path with a different inode,
            // but our hardlink path keeps resolving to the original one
            // until it is explicitly unlinked.
            let _ = std::fs::remove_file(&link_owned);
            std::fs::hard_link(&path, &link_owned).map_err(StorageError::Io)?;

            let meta_fs = std::fs::metadata(&link_owned).map_err(StorageError::Io)?;
            let mtime = meta_fs
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
            let mut obj = ObjectMeta::new(key.to_string(), meta_fs.len(), lm);
            obj.etag = stored_meta.get("__etag__").cloned();
            obj.content_type = stored_meta.get("__content_type__").cloned();
            obj.storage_class = stored_meta
                .get("__storage_class__")
                .cloned()
                .or_else(|| Some("STANDARD".to_string()));
            obj.version_id = stored_meta.get("__version_id__").cloned();
            obj.metadata = stored_meta
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            obj.internal_metadata = stored_meta;
            Ok(obj)
        })
    }

    async fn snapshot_object_version_to_link(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        link_path: &std::path::Path,
    ) -> StorageResult<ObjectMeta> {
        let link_owned = link_path.to_owned();
        run_blocking(|| -> StorageResult<ObjectMeta> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            if let Some(parent) = link_owned.parent() {
                std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
            }
            let _ = std::fs::remove_file(&link_owned);
            std::fs::hard_link(&data_path, &link_owned).map_err(StorageError::Io)?;
            self.object_meta_from_version_record(key, &record, &data_path)
        })
    }

    async fn get_object_path(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        self.require_bucket(bucket)?;
        let path = self.object_path(bucket, key)?;
        if !path.is_file() {
            if self.read_bucket_config_sync(bucket).versioning_enabled {
                if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                    return Err(StorageError::DeleteMarker {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                        version_id: dm_version_id,
                    });
                }
            }
            return Err(StorageError::ObjectNotFound {
                bucket: bucket.to_string(),
                key: key.to_string(),
            });
        }
        Ok(path)
    }

    async fn head_object(&self, bucket: &str, key: &str) -> StorageResult<ObjectMeta> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                if self.read_bucket_config_sync(bucket).versioning_status().is_active() {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
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
            obj.version_id = stored_meta.get("__version_id__").cloned();
            obj.metadata = stored_meta
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            obj.internal_metadata = stored_meta;
            Ok(obj)
        })
    }

    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (obj, file) = run_blocking(|| -> StorageResult<(ObjectMeta, std::fs::File)> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            let file = std::fs::File::open(&data_path).map_err(StorageError::Io)?;
            let obj = self.object_meta_from_version_record(key, &record, &data_path)?;
            Ok((obj, file))
        })?;
        let stream: AsyncReadStream = Box::pin(tokio::fs::File::from_std(file));
        Ok((obj, stream))
    }

    async fn get_object_version_range(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        start: u64,
        len: Option<u64>,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (obj, file) = run_blocking(|| -> StorageResult<(ObjectMeta, std::fs::File)> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            use std::io::{Seek, SeekFrom};
            let mut file = std::fs::File::open(&data_path).map_err(StorageError::Io)?;
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            if start > size {
                return Err(StorageError::InvalidRange);
            }
            if start > 0 {
                file.seek(SeekFrom::Start(start)).map_err(StorageError::Io)?;
            }
            let obj = self.object_meta_from_version_record(key, &record, &data_path)?;
            Ok((obj, file))
        })?;
        let tokio_file = tokio::fs::File::from_std(file);
        let stream: AsyncReadStream = match len {
            Some(n) => {
                use tokio::io::AsyncReadExt;
                Box::pin(tokio_file.take(n))
            }
            None => Box::pin(tokio_file),
        };
        Ok((obj, stream))
    }

    async fn get_object_version_path(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<PathBuf> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            Ok(data_path)
        })
    }

    async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<ObjectMeta> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            self.object_meta_from_version_record(key, &record, &data_path)
        })
    }

    async fn get_object_version_metadata(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<HashMap<String, String>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, _data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            Ok(Self::version_metadata_from_record(&record))
        })
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> StorageResult<DeleteOutcome> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            let bucket_path = self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            let versioning_status = self.read_bucket_config_sync(bucket).versioning_status();

            if versioning_status.is_active() {
                if path.exists() {
                    let existing_meta = self.read_metadata_sync(bucket, key);
                    let existing_vid = existing_meta
                        .get("__version_id__")
                        .map(String::as_str)
                        .unwrap_or("");
                    let should_archive = match versioning_status {
                        VersioningStatus::Enabled => true,
                        VersioningStatus::Suspended => {
                            !existing_vid.is_empty() && existing_vid != "null"
                        }
                        VersioningStatus::Disabled => false,
                    };
                    if should_archive {
                        self.archive_current_version_sync(bucket, key, "delete")
                            .map_err(StorageError::Io)?;
                    }
                    Self::safe_unlink(&path).map_err(StorageError::Io)?;
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    Self::cleanup_empty_parents(&path, &bucket_path);
                }
                let dm_version_id = self
                    .write_delete_marker_sync(bucket, key)
                    .map_err(StorageError::Io)?;
                self.invalidate_bucket_caches(bucket);
                return Ok(DeleteOutcome {
                    version_id: Some(dm_version_id),
                    is_delete_marker: true,
                    existed: true,
                });
            }

            if !path.exists() {
                return Ok(DeleteOutcome::default());
            }

            Self::safe_unlink(&path).map_err(StorageError::Io)?;
            self.delete_metadata_sync(bucket, key)
                .map_err(StorageError::Io)?;

            Self::cleanup_empty_parents(&path, &bucket_path);
            self.invalidate_bucket_caches(bucket);
            Ok(DeleteOutcome {
                version_id: None,
                is_delete_marker: false,
                existed: true,
            })
        })
    }

    async fn delete_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<DeleteOutcome> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            let bucket_path = self.require_bucket(bucket)?;
            self.validate_key(key)?;
            Self::validate_version_id(bucket, key, version_id)?;

            let live_path = self.object_live_path(bucket, key);
            if live_path.is_file() {
                let metadata = self.read_metadata_sync(bucket, key);
                if metadata.get("__version_id__").map(String::as_str) == Some(version_id) {
                    Self::safe_unlink(&live_path).map_err(StorageError::Io)?;
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    Self::cleanup_empty_parents(&live_path, &bucket_path);
                    self.promote_latest_archived_to_live_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    self.invalidate_bucket_caches(bucket);
                    return Ok(DeleteOutcome {
                        version_id: Some(version_id.to_string()),
                        is_delete_marker: false,
                        existed: true,
                    });
                }
            }

            let (manifest_path, data_path) = self.version_record_paths(bucket, key, version_id);
            if !manifest_path.is_file() && !data_path.is_file() {
                return Err(StorageError::VersionNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: version_id.to_string(),
                });
            }

            let is_delete_marker = if manifest_path.is_file() {
                std::fs::read_to_string(&manifest_path)
                    .ok()
                    .and_then(|content| serde_json::from_str::<Value>(&content).ok())
                    .and_then(|record| record.get("is_delete_marker").and_then(Value::as_bool))
                    .unwrap_or(false)
            } else {
                false
            };

            Self::safe_unlink(&data_path).map_err(StorageError::Io)?;
            Self::safe_unlink(&manifest_path).map_err(StorageError::Io)?;
            let versions_root = self.bucket_versions_root(bucket);
            Self::cleanup_empty_parents(&manifest_path, &versions_root);

            let mut was_active_dm = false;
            if is_delete_marker {
                if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                    if dm_version_id == version_id {
                        self.clear_delete_marker_sync(bucket, key);
                        was_active_dm = true;
                    }
                }
            }

            if was_active_dm && !live_path.is_file() {
                self.promote_latest_archived_to_live_sync(bucket, key)
                    .map_err(StorageError::Io)?;
            }

            self.invalidate_bucket_caches(bucket);
            Ok(DeleteOutcome {
                version_id: Some(version_id.to_string()),
                is_delete_marker,
                existed: true,
            })
        })
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(dst_key)?;
        let chunk_size = self.stream_chunk_size;
        let tmp_dir = self.tmp_dir();
        std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        // Copy bytes + hash under the src read lock so the source body and
        // metadata we capture are consistent with one another. The src read
        // guard is released at the end of this block before we take the dst
        // write guard, so even when src == dst (same stripe) there's no
        // upgrade deadlock.
        let copy_res = run_blocking(|| -> StorageResult<(String, u64, HashMap<String, String>)> {
            let _src_guard = self.get_object_lock(src_bucket, src_key).read();
            let src_path = self.object_path(src_bucket, src_key)?;
            if !src_path.is_file() {
                return Err(StorageError::ObjectNotFound {
                    bucket: src_bucket.to_string(),
                    key: src_key.to_string(),
                });
            }

            use std::io::{BufReader, BufWriter, Read, Write};
            let src_file = std::fs::File::open(&src_path).map_err(StorageError::Io)?;
            let mut reader = BufReader::with_capacity(chunk_size, src_file);
            let tmp_file = std::fs::File::create(&tmp_path).map_err(StorageError::Io)?;
            let mut writer = BufWriter::with_capacity(chunk_size * 4, tmp_file);
            let mut hasher = Md5::new();
            let mut buf = vec![0u8; chunk_size];
            let mut total: u64 = 0;
            loop {
                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                writer.write_all(&buf[..n]).map_err(StorageError::Io)?;
                total += n as u64;
            }
            writer.flush().map_err(StorageError::Io)?;

            let src_metadata = self.read_metadata_sync(src_bucket, src_key);
            Ok((format!("{:x}", hasher.finalize()), total, src_metadata))
        });

        let (etag, new_size, src_metadata) = match copy_res {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
        };

        let finalize = run_blocking(|| {
            let _dst_guard = self.get_object_lock(dst_bucket, dst_key).write();
            self.finalize_put_sync(
                dst_bucket,
                dst_key,
                &tmp_path,
                etag,
                new_size,
                Some(src_metadata),
            )
        });

        if finalize.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        finalize
    }

    async fn get_object_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<HashMap<String, String>> {
        Ok(run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.read_metadata_sync(bucket, key)
        }))
    }

    async fn put_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
            let meta_map: serde_json::Map<String, Value> = metadata
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            entry.insert("metadata".to_string(), Value::Object(meta_map));
            self.write_index_entry_sync(bucket, key, &entry)
                .map_err(StorageError::Io)?;
            self.invalidate_bucket_caches(bucket);
            Ok(())
        })
    }

    async fn list_objects(
        &self,
        bucket: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        run_blocking(|| self.list_objects_sync(bucket, params))
    }

    async fn list_objects_shallow(
        &self,
        bucket: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult> {
        run_blocking(|| self.list_objects_shallow_sync(bucket, params))
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
        stream: AsyncReadStream,
    ) -> StorageResult<String> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }

        let part_file = upload_dir.join(format!("part-{:05}.part", part_number));
        let tmp_file = upload_dir.join(format!("part-{:05}.part.tmp", part_number));

        let chunk_size = self.stream_chunk_size;
        let tmp_file_owned = tmp_file.clone();
        let drain_res = tokio::task::spawn_blocking(move || -> StorageResult<(String, u64)> {
            use std::io::{BufWriter, Read, Write};
            let mut reader = tokio_util::io::SyncIoBridge::new(stream);
            let file = std::fs::File::create(&tmp_file_owned).map_err(StorageError::Io)?;
            let mut writer = BufWriter::with_capacity(chunk_size * 4, file);
            let mut hasher = Md5::new();
            let mut part_size: u64 = 0;
            let mut buf = vec![0u8; chunk_size];
            loop {
                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                writer.write_all(&buf[..n]).map_err(StorageError::Io)?;
                part_size += n as u64;
            }
            writer.flush().map_err(StorageError::Io)?;
            Ok((format!("{:x}", hasher.finalize()), part_size))
        })
        .await;

        let (etag, part_size) = match drain_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_file).await;
                return Err(e);
            }
            Err(join) => {
                let _ = tokio::fs::remove_file(&tmp_file).await;
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    join,
                )));
            }
        };

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

        let part_file = upload_dir.join(format!("part-{:05}.part", part_number));
        let tmp_file = upload_dir.join(format!("part-{:05}.part.tmp", part_number));
        let chunk_size = self.stream_chunk_size;

        // Everything that must be consistent with the copied bytes — path
        // check, size/mtime, range validation, open+seek+read — happens under
        // one held read guard. If a concurrent PUT renames the source
        // between our metadata read and our file open, we'd otherwise record
        // the old size/last_modified in the manifest but copy bytes from the
        // new version.
        let copy_res = run_blocking(
            || -> StorageResult<(String, u64, DateTime<Utc>)> {
                let _guard = self.get_object_lock(src_bucket, src_key).read();

                let src_path = self.object_path(src_bucket, src_key)?;
                if !src_path.is_file() {
                    return Err(StorageError::ObjectNotFound {
                        bucket: src_bucket.to_string(),
                        key: src_key.to_string(),
                    });
                }

                use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
                // Open first so subsequent metadata/seek/read are all
                // anchored to the same inode, even if a later rename swaps
                // the path after we release the guard.
                let mut src = std::fs::File::open(&src_path).map_err(StorageError::Io)?;
                let src_meta = src.metadata().map_err(StorageError::Io)?;
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

                if start > 0 {
                    src.seek(SeekFrom::Start(start)).map_err(StorageError::Io)?;
                }
                let mut src = std::io::BufReader::with_capacity(chunk_size, src);
                let dst = std::fs::File::create(&tmp_file).map_err(StorageError::Io)?;
                let mut dst = BufWriter::with_capacity(chunk_size * 4, dst);
                let mut hasher = Md5::new();
                let mut remaining = length;
                let mut buf = vec![0u8; chunk_size];
                while remaining > 0 {
                    let to_read = std::cmp::min(remaining as usize, buf.len());
                    let n = src.read(&mut buf[..to_read]).map_err(StorageError::Io)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    dst.write_all(&buf[..n]).map_err(StorageError::Io)?;
                    remaining -= n as u64;
                }
                dst.flush().map_err(StorageError::Io)?;
                Ok((format!("{:x}", hasher.finalize()), length, last_modified))
            },
        );

        let (etag, length, last_modified) = match copy_res {
            Ok(v) => v,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_file).await;
                return Err(e);
            }
        };

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
        std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let chunk_size = self.stream_chunk_size;
        let part_infos: Vec<PartInfo> = parts.to_vec();
        let upload_dir_owned = upload_dir.clone();
        let tmp_path_owned = tmp_path.clone();

        // Assemble parts on a blocking thread using std::fs, large buffers,
        // and a single writer flush — no per-chunk runtime crossings.
        let assemble_res = tokio::task::spawn_blocking(move || -> StorageResult<(String, u64)> {
            use std::io::{BufReader, BufWriter, Read, Write};
            let out_raw = std::fs::File::create(&tmp_path_owned).map_err(StorageError::Io)?;
            let mut out_file = BufWriter::with_capacity(chunk_size * 4, out_raw);
            let mut md5_digest_concat = Vec::with_capacity(part_infos.len() * 16);
            let mut total_size: u64 = 0;
            let mut buf = vec![0u8; chunk_size];

            for part_info in &part_infos {
                let part_file = upload_dir_owned
                    .join(format!("part-{:05}.part", part_info.part_number));
                if !part_file.exists() {
                    return Err(StorageError::InvalidObjectKey(format!(
                        "Part {} not found",
                        part_info.part_number
                    )));
                }
                let reader = std::fs::File::open(&part_file).map_err(StorageError::Io)?;
                let mut reader = BufReader::with_capacity(chunk_size, reader);
                let mut part_hasher = Md5::new();
                loop {
                    let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                    if n == 0 {
                        break;
                    }
                    part_hasher.update(&buf[..n]);
                    out_file.write_all(&buf[..n]).map_err(StorageError::Io)?;
                    total_size += n as u64;
                }
                md5_digest_concat.extend_from_slice(&part_hasher.finalize());
            }

            out_file.flush().map_err(StorageError::Io)?;
            let mut composite_hasher = Md5::new();
            composite_hasher.update(&md5_digest_concat);
            let etag = format!("{:x}-{}", composite_hasher.finalize(), part_infos.len());
            Ok((etag, total_size))
        })
        .await;

        let (etag, total_size) = match assemble_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
            Err(join) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    join,
                )));
            }
        };

        // Commit to the destination key atomically under its write lock.
        // Lock acquisition happens inside run_blocking so the wait runs under
        // block_in_place rather than parking the async worker.
        let result = run_blocking(|| {
            let _guard = self.get_object_lock(bucket, &object_key).write();
            self.finalize_put_sync(
                bucket,
                &object_key,
                &tmp_path,
                etag,
                total_size,
                Some(metadata),
            )
        });

        match result {
            Ok(obj) => {
                let _ = std::fs::remove_dir_all(&upload_dir);
                Ok(obj)
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                Err(e)
            }
        }
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
        let new_status = if enabled {
            VersioningStatus::Enabled
        } else if config.versioning_enabled || config.versioning_suspended {
            VersioningStatus::Suspended
        } else {
            VersioningStatus::Disabled
        };
        config.set_versioning_status(new_status);
        self.write_bucket_config_sync(bucket, &config)
            .map_err(StorageError::Io)
    }

    async fn get_versioning_status(&self, bucket: &str) -> StorageResult<VersioningStatus> {
        Ok(self.read_bucket_config_sync(bucket).versioning_status())
    }

    async fn set_versioning_status(
        &self,
        bucket: &str,
        status: VersioningStatus,
    ) -> StorageResult<()> {
        self.require_bucket(bucket)?;
        let mut config = self.read_bucket_config_sync(bucket);
        config.set_versioning_status(status);
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
                    .map(|rel| {
                        let s = rel.to_string_lossy().into_owned();
                        #[cfg(windows)]
                        let s = s.replace('\\', "/");
                        fs_decode_key(&s)
                    })
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
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
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
        })
    }

    async fn set_object_tags(&self, bucket: &str, key: &str, tags: &[Tag]) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
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
            self.invalidate_bucket_caches(bucket);
            Ok(())
        })
    }

    async fn delete_object_tags(&self, bucket: &str, key: &str) -> StorageResult<()> {
        self.set_object_tags(bucket, key, &[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::StorageEngine;
    use tokio::io::AsyncReadExt;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_snapshot_to_link_matches_meta() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc as StdArc;

        let (dir, backend) = create_test_backend();
        let root = dir.path().to_path_buf();
        let backend = StdArc::new(backend);
        backend.create_bucket("link-bkt").await.unwrap();

        let tmp_dir = root.join(".myfsio.sys").join("tmp");
        std::fs::create_dir_all(&tmp_dir).unwrap();

        // Seed with known content.
        let data: AsyncReadStream =
            Box::pin(std::io::Cursor::new(vec![b'a'; 4096]));
        backend.put_object("link-bkt", "hot", data, None).await.unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        // Writers swap the object between three distinct fill bytes with
        // distinct known etags; we'll check the snapshot's etag is one of
        // them and matches what we read from link_path.
        for w in 0..2 {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut i: u32 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let fill = b'a' + (((w + i) % 3) as u8);
                    let size = 2048 + ((w + i) % 3) as usize * 1024;
                    let body = vec![fill; size];
                    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                    let _ = b.put_object("link-bkt", "hot", data, None).await;
                    i = i.wrapping_add(1);
                }
            }));
        }

        let reads = StdArc::new(AtomicU64::new(0));
        let mismatches = StdArc::new(AtomicU64::new(0));
        for _ in 0..4 {
            let b = backend.clone();
            let stop = stop.clone();
            let tmp_dir = tmp_dir.clone();
            let reads = reads.clone();
            let mismatches = mismatches.clone();
            handles.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let link = tmp_dir.join(format!("lnk-{}", Uuid::new_v4()));
                    match b.snapshot_object_to_link("link-bkt", "hot", &link).await {
                        Ok(meta) => {
                            let bytes = std::fs::read(&link).unwrap_or_default();
                            let md5 = format!("{:x}", Md5::digest(&bytes));
                            reads.fetch_add(1, Ordering::Relaxed);
                            if meta.etag.as_deref() != Some(md5.as_str())
                                || bytes.len() as u64 != meta.size
                            {
                                mismatches.fetch_add(1, Ordering::Relaxed);
                            }
                            let _ = std::fs::remove_file(&link);
                        }
                        Err(_) => {
                            let _ = std::fs::remove_file(&link);
                        }
                    }
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }

        let r = reads.load(Ordering::Relaxed);
        let m = mismatches.load(Ordering::Relaxed);
        assert!(r > 10, "expected some snapshot reads, got {}", r);
        assert_eq!(
            m, 0,
            "observed {} snapshot_to_link results where meta etag/size didn't match the linked bytes, out of {}",
            m, r
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_get_object_snapshot_size_matches_body() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc as StdArc;
        use tokio::io::AsyncReadExt;

        let (_dir, backend) = create_test_backend();
        let backend = StdArc::new(backend);
        backend.create_bucket("snap-bkt").await.unwrap();

        let data: AsyncReadStream =
            Box::pin(std::io::Cursor::new(vec![b'a'; 1024]));
        backend
            .put_object("snap-bkt", "sz", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        // Writers flip between 1 KiB and 2 KiB bodies so every PUT changes
        // the reported size.
        for w in 0..2 {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut i: u32 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let fill = b'a' + ((w + i) % 20) as u8;
                    let size = if i % 2 == 0 { 1024 } else { 2048 };
                    let body = vec![fill; size];
                    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                    let _ = b.put_object("snap-bkt", "sz", data, None).await;
                    i = i.wrapping_add(1);
                }
            }));
        }

        let reads = StdArc::new(AtomicU64::new(0));
        let mismatches = StdArc::new(AtomicU64::new(0));
        for _ in 0..4 {
            let b = backend.clone();
            let stop = stop.clone();
            let reads = reads.clone();
            let mismatches = mismatches.clone();
            handles.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((meta, mut file)) = b.get_object_snapshot("snap-bkt", "sz").await {
                        let mut buf = Vec::new();
                        if file.read_to_end(&mut buf).await.is_ok() {
                            reads.fetch_add(1, Ordering::Relaxed);
                            if buf.len() as u64 != meta.size {
                                mismatches.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }

        let r = reads.load(Ordering::Relaxed);
        let m = mismatches.load(Ordering::Relaxed);
        assert!(r > 10, "expected some snapshot reads, got {}", r);
        assert_eq!(
            m, 0,
            "observed {} snapshots where meta.size didn't match body length, out of {} reads",
            m, r
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_range_get_snapshot_consistency() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc as StdArc;

        let (_dir, backend) = create_test_backend();
        let backend = StdArc::new(backend);
        backend.create_bucket("range-bkt").await.unwrap();

        // Every version is a 256 KiB run of a single byte, so body bytes
        // alone identify which version any ranged read came from. We pair
        // that with the returned ETag to check they agree.
        const SIZE: u64 = 256 * 1024;
        let seed = vec![b'a'; SIZE as usize];
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
        backend.put_object("range-bkt", "hot", data, None).await.unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        for w in 0..2 {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut i: u8 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let fill = b'a' + ((w as u8 * 7 + i) % 20);
                    let body = vec![fill; SIZE as usize];
                    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                    let _ = b.put_object("range-bkt", "hot", data, None).await;
                    i = i.wrapping_add(1);
                }
            }));
        }

        let reads = StdArc::new(AtomicU64::new(0));
        let mismatches = StdArc::new(AtomicU64::new(0));
        for _ in 0..6 {
            let b = backend.clone();
            let stop = stop.clone();
            let reads = reads.clone();
            let mismatches = mismatches.clone();
            handles.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let start = 1000u64;
                    let len = 4000u64;
                    if let Ok((meta, mut stream)) =
                        b.get_object_range("range-bkt", "hot", start, Some(len)).await
                    {
                        let mut buf = Vec::with_capacity(len as usize);
                        if stream.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
                            // Every byte in the range must be the same — all
                            // writers fill the object uniformly — and the
                            // etag must be the MD5 of a uniform buffer of
                            // that byte at full object size.
                            let fill = buf[0];
                            let all_match = buf.iter().all(|b| *b == fill);
                            let expected_etag = format!(
                                "{:x}",
                                Md5::digest(&vec![fill; SIZE as usize])
                            );
                            let etag_ok = meta.etag.as_deref() == Some(expected_etag.as_str());
                            reads.fetch_add(1, Ordering::Relaxed);
                            if !(all_match && etag_ok) {
                                mismatches.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }

        let r = reads.load(Ordering::Relaxed);
        let m = mismatches.load(Ordering::Relaxed);
        assert!(r > 10, "expected some Range GETs, got {}", r);
        assert_eq!(
            m, 0,
            "observed {} Range GETs where etag and body fill byte disagreed, out of {} reads",
            m, r
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_upload_part_copy_snapshot_consistency() {
        use myfsio_common::types::PartInfo;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc as StdArc;

        let (_dir, backend) = create_test_backend();
        let backend = StdArc::new(backend);
        backend.create_bucket("mp-bkt").await.unwrap();

        // Two fixed-size source versions: all 'a' or all 'b'. Writers flip
        // between them; readers do upload_part_copy and check that the
        // recorded ETag corresponds to exactly one of the two known MD5s
        // (not a cross-pollinated value).
        const SIZE: u64 = 64 * 1024;
        let etag_a = format!("{:x}", Md5::digest(&vec![b'a'; SIZE as usize]));
        let etag_b = format!("{:x}", Md5::digest(&vec![b'b'; SIZE as usize]));

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; SIZE as usize]));
        backend
            .put_object("mp-bkt", "src", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        // Writer flips the source between two fixed contents.
        {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut flip = false;
                while !stop.load(Ordering::Relaxed) {
                    flip = !flip;
                    let fill = if flip { b'a' } else { b'b' };
                    let data: AsyncReadStream =
                        Box::pin(std::io::Cursor::new(vec![fill; SIZE as usize]));
                    let _ = b.put_object("mp-bkt", "src", data, None).await;
                }
            }));
        }

        let ops = StdArc::new(AtomicU64::new(0));
        let bad = StdArc::new(AtomicU64::new(0));
        for _ in 0..4 {
            let b = backend.clone();
            let stop = stop.clone();
            let etag_a = etag_a.clone();
            let etag_b = etag_b.clone();
            let ops = ops.clone();
            let bad = bad.clone();
            handles.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    let upload_id = match b.initiate_multipart("mp-bkt", "dst", None).await {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    let res = b
                        .upload_part_copy(
                            "mp-bkt", &upload_id, 1, "mp-bkt", "src", None,
                        )
                        .await;
                    if let Ok((etag, _lm)) = res {
                        // The part etag is the MD5 of the copied bytes; it
                        // must be one of the two known values, never something
                        // in between (which would signal metadata from one
                        // version and bytes from another).
                        if etag != etag_a && etag != etag_b {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                        ops.fetch_add(1, Ordering::Relaxed);
                    }
                    let _ = b.abort_multipart("mp-bkt", &upload_id).await;
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }

        let o = ops.load(Ordering::Relaxed);
        let x = bad.load(Ordering::Relaxed);
        assert!(o >= 4, "expected at least a few upload_part_copy ops, got {}", o);
        assert_eq!(
            x, 0,
            "observed {} upload_part_copy results with etag unrelated to source content (out of {})",
            x, o
        );
        // Sanity: make sure the test actually exercised both versions.
        let _ = PartInfo {
            part_number: 1,
            etag: etag_a,
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_contention_does_not_stall_other_async_tasks() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc as StdArc;

        let (_dir, backend) = create_test_backend();
        let backend = StdArc::new(backend);
        backend.create_bucket("contend").await.unwrap();

        // Seed a 1 MiB object.
        let seed = vec![b'x'; 1_048_576];
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
        backend
            .put_object("contend", "hot", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        // Hammer the same key with PUTs that each acquire the write lock
        // inside block_in_place. On only 2 worker threads, this is a
        // worst-case pattern for worker starvation.
        for w in 0..4 {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut i: u8 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let fill = b'a' + ((w as u8 + i) % 26);
                    let body = vec![fill; 1_048_576];
                    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                    let _ = b.put_object("contend", "hot", data, None).await;
                    i = i.wrapping_add(1);
                }
            }));
        }

        // Unrelated async tasks (simulating e.g. health checks, metrics
        // emissions) that should keep firing throughout the contention.
        let pings = StdArc::new(AtomicU64::new(0));
        for _ in 0..2 {
            let stop = stop.clone();
            let pings = pings.clone();
            handles.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    tokio::task::yield_now().await;
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    pings.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }

        // If the worker was getting parked on lock.write() outside of
        // block_in_place, the unrelated task's ping counter would stall. We
        // expect ~1 ping per ms when healthy; assert a generous floor.
        let p = pings.load(Ordering::Relaxed);
        assert!(
            p >= 50,
            "unrelated async tasks stalled during PUT contention: only {} pings in 400ms",
            p
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_put_get_atomicity() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc as StdArc;

        let (_dir, backend) = create_test_backend();
        let backend = StdArc::new(backend);
        backend.create_bucket("race-bucket").await.unwrap();

        const SIZE: usize = 256 * 1024;
        // Seed an initial version so GETs can start immediately.
        let seed = vec![b'a'; SIZE];
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
        backend
            .put_object("race-bucket", "hot", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mismatches = StdArc::new(AtomicU64::new(0));
        let reads = StdArc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for w in 0..2 {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut i: u8 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let fill = b'a'.wrapping_add((w * 8 + i) as u8);
                    let body = vec![fill; SIZE];
                    let data: AsyncReadStream = Box::pin(std::io::Cursor::new(body));
                    let _ = b.put_object("race-bucket", "hot", data, None).await;
                    i = i.wrapping_add(1);
                }
            }));
        }
        for _ in 0..6 {
            let b = backend.clone();
            let stop = stop.clone();
            let mismatches = mismatches.clone();
            let reads = reads.clone();
            handles.push(tokio::spawn(async move {
                while !stop.load(Ordering::Relaxed) {
                    if let Ok((obj, mut stream)) = b.get_object("race-bucket", "hot").await {
                        let mut buf = Vec::with_capacity(SIZE);
                        if stream.read_to_end(&mut buf).await.is_ok() {
                            let header_etag = obj.etag.unwrap_or_default();
                            let body_md5 = format!("{:x}", Md5::digest(&buf));
                            reads.fetch_add(1, Ordering::Relaxed);
                            if header_etag != body_md5 {
                                mismatches.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }));
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        stop.store(true, Ordering::Relaxed);
        for h in handles {
            let _ = h.await;
        }

        let r = reads.load(Ordering::Relaxed);
        let m = mismatches.load(Ordering::Relaxed);
        assert!(r > 10, "expected at least a handful of GETs, got {}", r);
        assert_eq!(
            m, 0,
            "observed {} ETag/body mismatches out of {} reads",
            m, r
        );
    }
}
