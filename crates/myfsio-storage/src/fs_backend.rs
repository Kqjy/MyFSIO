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

pub const META_KEY_CORRUPTED: &str = "__corrupted__";
pub const META_KEY_CORRUPTED_AT: &str = "__corrupted_at__";
pub const META_KEY_CORRUPTION_DETAIL: &str = "__corruption_detail__";
pub const META_KEY_QUARANTINE_PATH: &str = "__quarantine_path__";
pub const META_KEY_PART_SIZES: &str = "__part_sizes__";

const STORAGE_MANAGED_METADATA_KEYS: &[&str] = &[
    "__etag__",
    "__size__",
    "__last_modified__",
    "__version_id__",
];

pub enum OpenedObjectContent {
    Single(std::fs::File),
    Segmented {
        files: Vec<(std::fs::File, u64)>,
        total: u64,
    },
}

impl OpenedObjectContent {
    async fn into_range_stream(
        self,
        start: u64,
        len: Option<u64>,
    ) -> std::io::Result<AsyncReadStream> {
        match self {
            OpenedObjectContent::Single(file) => {
                use tokio::io::{AsyncReadExt, AsyncSeekExt};
                let mut file = tokio::fs::File::from_std(file);
                if start > 0 {
                    file.seek(std::io::SeekFrom::Start(start)).await?;
                }
                Ok(match len {
                    Some(n) => Box::pin(file.take(n)),
                    None => Box::pin(file),
                })
            }
            OpenedObjectContent::Segmented { files, total } => {
                let tokio_files: Vec<(tokio::fs::File, u64)> = files
                    .into_iter()
                    .map(|(f, size)| (tokio::fs::File::from_std(f), size))
                    .collect();
                let effective_len = len.unwrap_or_else(|| total.saturating_sub(start));
                let reader = crate::segments::SegmentRangeReader::from_files(
                    tokio_files,
                    start,
                    effective_len,
                )
                .await?;
                Ok(Box::pin(reader))
            }
        }
    }

    fn into_snapshot_source(self, link_path: PathBuf) -> crate::traits::SnapshotSource {
        match self {
            OpenedObjectContent::Single(_) => crate::traits::SnapshotSource::LinkedFile(link_path),
            OpenedObjectContent::Segmented { files, total } => {
                crate::traits::SnapshotSource::Segments { files, total }
            }
        }
    }
}

fn parse_md5_hex(s: &str) -> Option<[u8; 16]> {
    let s = s.trim().trim_matches('"');
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

pub fn encode_part_sizes(sizes: &[u64]) -> String {
    let mut out = String::with_capacity(sizes.len() * 8);
    for (i, s) in sizes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&s.to_string());
    }
    out
}

pub fn parse_part_sizes(raw: &str) -> Option<Vec<u64>> {
    let mut out = Vec::new();
    for tok in raw.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            return None;
        }
        out.push(tok.parse::<u64>().ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn metadata_is_corrupted(meta: &HashMap<String, String>) -> bool {
    meta.get(META_KEY_CORRUPTED)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn metadata_corruption_detail(meta: &HashMap<String, String>) -> String {
    meta.get(META_KEY_CORRUPTION_DETAIL)
        .cloned()
        .unwrap_or_else(|| "data integrity check failed".to_string())
}

pub fn is_multipart_etag(etag: &str) -> bool {
    let Some(dash_idx) = etag.rfind('-') else {
        return false;
    };
    if dash_idx != 32 {
        return false;
    }
    let (head, tail) = etag.split_at(dash_idx);
    let tail = &tail[1..];
    !tail.is_empty()
        && tail.chars().all(|c| c.is_ascii_digit())
        && head.chars().all(|c| c.is_ascii_hexdigit())
}

fn fs_encode_key(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let trailing = key.ends_with('/');
    let body = if trailing { &key[..key.len() - 1] } else { key };
    if body.is_empty() {
        return if trailing {
            "/".to_string()
        } else {
            String::new()
        };
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

type ListCacheEntry = (
    String,
    u64,
    f64,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[derive(Clone, Default)]
struct ShallowCacheEntry {
    files: Vec<ObjectMeta>,
    dirs: Vec<String>,
}

const OBJECT_LOCK_STRIPES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MultipartLayout {
    #[default]
    Segments,
    Concat,
}

impl MultipartLayout {
    pub fn from_env_str(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "concat" => Self::Concat,
            _ => Self::Segments,
        }
    }
}

pub struct FsStorageBackend {
    root: PathBuf,
    object_key_max_length_bytes: usize,
    object_cache_max_size: usize,
    stream_chunk_size: usize,
    multipart_layout: MultipartLayout,
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
    pub multipart_layout: MultipartLayout,
}

impl Default for FsStorageBackendConfig {
    fn default() -> Self {
        Self {
            object_key_max_length_bytes: DEFAULT_OBJECT_KEY_MAX_BYTES,
            object_cache_max_size: 100,
            bucket_config_cache_ttl: std::time::Duration::from_secs(30),
            stream_chunk_size: STREAM_CHUNK_SIZE,
            multipart_layout: MultipartLayout::default(),
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
            multipart_layout: config.multipart_layout,
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

    pub fn system_tmp_dir(&self) -> PathBuf {
        self.root.join(SYSTEM_ROOT).join("tmp")
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

    pub fn segments_bucket_root(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name)
            .join(crate::segments::SEGMENTS_DIR)
    }

    fn segment_set_for(
        &self,
        bucket: &str,
        segment_id: &str,
        sizes: Vec<u64>,
    ) -> crate::segments::SegmentSet {
        crate::segments::SegmentSet::new(
            self.segments_bucket_root(bucket).join(segment_id),
            sizes,
        )
    }

    fn open_object_for_read_sync(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
        let _guard = self.get_object_lock(bucket, key).read();
        self.open_object_for_read_locked_sync(bucket, key)
    }

    fn open_object_for_read_locked_sync(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
        self.require_bucket(bucket)?;
        let path = self.object_path(bucket, key)?;
        if !path.is_file() {
            let stored_meta = self.read_metadata_sync(bucket, key);
            if metadata_is_corrupted(&stored_meta) {
                return Err(StorageError::ObjectCorrupted {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    detail: metadata_corruption_detail(&stored_meta),
                });
            }
            if self
                .read_bucket_config_sync(bucket)
                .versioning_status()
                .is_active()
            {
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
        if metadata_is_corrupted(&stored_meta) {
            return Err(StorageError::ObjectCorrupted {
                bucket: bucket.to_string(),
                key: key.to_string(),
                detail: metadata_corruption_detail(&stored_meta),
            });
        }
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
        let content = self.open_content_for_read_sync(bucket, key, file, &obj.internal_metadata)?;
        Ok((obj, content))
    }

    fn open_version_for_read_sync(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
        let _guard = self.get_object_lock(bucket, key).read();
        self.open_version_for_read_locked_sync(bucket, key, version_id)
    }

    fn open_version_for_read_locked_sync(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
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
        let record_meta = Self::version_metadata_from_record(&record);
        let content = self.open_content_for_read_sync(bucket, key, file, &record_meta)?;
        Ok((obj, content))
    }

    fn open_content_for_read_sync(
        &self,
        bucket: &str,
        key: &str,
        mut file: std::fs::File,
        stored_meta: &HashMap<String, String>,
    ) -> StorageResult<OpenedObjectContent> {
        let Some(seg_id) = stored_meta.get(crate::segments::META_KEY_SEGMENTS) else {
            return Ok(OpenedObjectContent::Single(file));
        };
        let corrupted = |detail: String| StorageError::ObjectCorrupted {
            bucket: bucket.to_string(),
            key: key.to_string(),
            detail,
        };
        let header = crate::segments::read_stub_header_from(&mut file)
            .map_err(StorageError::Io)?
            .ok_or_else(|| {
                corrupted("segmented object data file is missing its stub header".to_string())
            })?;
        if &header.segment_id != seg_id {
            return Err(corrupted(format!(
                "stub references segment set {} but metadata says {}",
                header.segment_id, seg_id
            )));
        }
        let meta_sizes = stored_meta
            .get(META_KEY_PART_SIZES)
            .and_then(|raw| parse_part_sizes(raw));
        if let Some(ref sizes) = meta_sizes {
            if *sizes != header.sizes {
                return Err(corrupted(
                    "part size manifest does not match the segment stub".to_string(),
                ));
            }
        }
        let set = self.segment_set_for(bucket, seg_id, header.sizes.clone());
        let mut files = Vec::with_capacity(set.sizes.len());
        for (i, size) in set.sizes.iter().enumerate() {
            let seg_path = set.seg_path(i);
            let seg_file = std::fs::File::open(&seg_path).map_err(|e| {
                corrupted(format!(
                    "segment file {} is unreadable: {}",
                    seg_path.display(),
                    e
                ))
            })?;
            let seg_len = seg_file.metadata().map_err(StorageError::Io)?.len();
            if seg_len != *size {
                return Err(corrupted(format!(
                    "segment file {} has size {} but manifest says {}",
                    seg_path.display(),
                    seg_len,
                    size
                )));
            }
            files.push((seg_file, *size));
        }
        Ok(OpenedObjectContent::Segmented {
            files,
            total: header.total,
        })
    }

    fn release_segment_dir(&self, bucket: &str, segment_id: &str) {
        if segment_id.is_empty() {
            return;
        }
        let seg_dir = self.segments_bucket_root(bucket).join(segment_id);
        if let Err(e) = std::fs::remove_dir_all(&seg_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    bucket = bucket,
                    segment_id = segment_id,
                    error = %e,
                    "failed to remove segment directory; GC will sweep it"
                );
            }
        }
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
            let direct = self.bucket_path(bucket_name).join(&encoded);
            if direct.is_dir() {
                Ok(direct.join(KEY_DATA_MARKER_FILE))
            } else {
                Ok(direct)
            }
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
            let direct = self.bucket_path(bucket_name).join(&encoded);
            if direct.is_dir() {
                direct.join(KEY_DATA_MARKER_FILE)
            } else {
                direct
            }
        }
    }

    fn ensure_writable_parents_sync(
        &self,
        bucket_root: &Path,
        object_key: &str,
    ) -> std::io::Result<()> {
        let encoded = fs_encode_key(object_key);
        let effective = if object_key.ends_with('/') {
            encoded.trim_end_matches('/').to_string()
        } else {
            encoded
        };
        let segments: Vec<&str> = effective.split('/').filter(|s| !s.is_empty()).collect();
        if segments.len() <= 1 && !object_key.ends_with('/') {
            return Ok(());
        }
        let intermediate_count = if object_key.ends_with('/') {
            segments.len()
        } else {
            segments.len() - 1
        };
        let tmp_dir = self.tmp_dir();
        std::fs::create_dir_all(&tmp_dir)?;
        let mut current = bucket_root.to_path_buf();
        for seg in &segments[..intermediate_count] {
            let next = current.join(seg);
            let meta = match std::fs::symlink_metadata(&next) {
                Ok(m) => Some(m),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(err),
            };
            if let Some(meta) = meta {
                if meta.file_type().is_file() {
                    let temp_path =
                        tmp_dir.join(format!(".tmp_keydata_{}", Uuid::new_v4().simple()));
                    match std::fs::rename(&next, &temp_path) {
                        Ok(()) => {}
                        Err(err) => {
                            if next.is_dir() {
                                current = next;
                                continue;
                            }
                            return Err(err);
                        }
                    }
                    if let Err(err) = std::fs::create_dir_all(&next) {
                        let _ = std::fs::rename(&temp_path, &next);
                        return Err(err);
                    }
                    let target = next.join(KEY_DATA_MARKER_FILE);
                    if let Err(err) = std::fs::rename(&temp_path, &target) {
                        let _ = std::fs::remove_dir(&next);
                        let _ = std::fs::rename(&temp_path, &next);
                        return Err(err);
                    }
                }
            }
            current = next;
        }
        Ok(())
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
        if validation::is_reserved_bucket_name(bucket_name) {
            return Err(StorageError::InvalidBucketName(format!(
                "Bucket name '{}' is reserved",
                bucket_name
            )));
        }
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

    fn load_dir_index_full_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
    ) -> HashMap<String, (Option<String>, Option<String>, Option<String>)> {
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
            let owner = meta
                .and_then(|m| m.get("__acl__"))
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .and_then(|acl| {
                    acl.get("owner")
                        .and_then(|v| v.as_str())
                        .map(ToOwned::to_owned)
                });
            out.insert(name, (etag, version_id, owner));
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

    pub fn lock_object_write(
        &self,
        bucket: &str,
        key: &str,
    ) -> parking_lot::RwLockWriteGuard<'_, ()> {
        self.get_object_lock(bucket, key).write()
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
                .map_err(std::io::Error::other)?;
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
                .map_err(std::io::Error::other)?,
        );

        let json_val = serde_json::to_value(&index_data)
            .map_err(std::io::Error::other)?;
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
                    .map_err(std::io::Error::other)?;
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
            .map_err(std::io::Error::other)?;
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

    pub async fn delete_object_metadata_entry(&self, bucket: &str, key: &str) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.delete_metadata_sync(bucket, key)
                .map_err(StorageError::Io)
        })
    }

    pub async fn put_object_with_etag_override(
        &self,
        bucket: &str,
        key: &str,
        stream: crate::traits::AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
        etag_override: Option<String>,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(key)?;

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let chunk_size = self.stream_chunk_size;
        let drain_tmp = tmp_path.clone();

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
                return Err(StorageError::Io(std::io::Error::other(
                    join_err,
                )));
            }
        };

        let result = run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.finalize_put_sync(
                bucket,
                key,
                &tmp_path,
                etag,
                total_size,
                metadata,
                etag_override,
            )
        });

        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp_path).await;
        }
        result
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
            .map_err(std::io::Error::other)?;
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
        let raw_vid = metadata
            .get("__version_id__")
            .map(String::as_str)
            .unwrap_or("");
        let version_id = if raw_vid.is_empty() {
            "null".to_string()
        } else if raw_vid.contains('/') || raw_vid.contains('\\') || raw_vid.contains("..") {
            Self::new_version_id_sync()
        } else {
            raw_vid.to_string()
        };

        let data_path = version_dir.join(format!("{}.bin", version_id));
        let source_meta = source.metadata()?;

        let stub_header = if metadata.contains_key(crate::segments::META_KEY_SEGMENTS) {
            crate::segments::read_stub_header(&source).unwrap_or(None)
        } else {
            None
        };
        let (source_size, etag, segment_id) = match stub_header {
            Some(header) => {
                crate::segments::write_stub(&data_path, &header)?;
                (header.total, header.etag.clone(), Some(header.segment_id))
            }
            None => {
                std::fs::copy(&source, &data_path)?;
                let etag = metadata
                    .get("__etag__")
                    .cloned()
                    .filter(|e| !e.is_empty())
                    .or_else(|| Self::compute_etag_sync(&source).ok())
                    .unwrap_or_default();
                (source_meta.len(), etag, None)
            }
        };

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

        let live_tags = self
            .read_index_entry_sync(bucket_name, key)
            .and_then(|entry| entry.get("tags").cloned())
            .unwrap_or(Value::Array(Vec::new()));

        let mut record = serde_json::json!({
            "version_id": version_id,
            "key": key,
            "size": source_size,
            "archived_at": now.to_rfc3339(),
            "last_modified": live_last_modified.to_rfc3339(),
            "etag": etag,
            "metadata": metadata,
            "tags": live_tags,
            "reason": reason,
        });
        if let Some(seg_id) = segment_id {
            record["segment_id"] = Value::String(seg_id);
        }

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

    fn write_delete_marker_sync(&self, bucket_name: &str, key: &str) -> std::io::Result<String> {
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

    fn purge_archived_null_version_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<()> {
        let (manifest_path, data_path) = self.version_record_paths(bucket_name, key, "null");
        if manifest_path.is_file() {
            if let Some(seg_id) = std::fs::read_to_string(&manifest_path)
                .ok()
                .and_then(|content| serde_json::from_str::<Value>(&content).ok())
                .and_then(|record| {
                    record
                        .get("segment_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
            {
                self.release_segment_dir(bucket_name, &seg_id);
            }
            Self::safe_unlink(&manifest_path)?;
        }
        if data_path.is_file() {
            Self::safe_unlink(&data_path)?;
        }
        let versions_root = self.bucket_versions_root(bucket_name);
        Self::cleanup_empty_parents(&manifest_path, &versions_root);
        Ok(())
    }


    fn validate_version_id(bucket_name: &str, key: &str, version_id: &str) -> StorageResult<()> {
        const MAX_VERSION_ID_LEN: usize = 128;
        let invalid = version_id.is_empty()
            || version_id.len() > MAX_VERSION_ID_LEN
            || version_id == "."
            || version_id == ".."
            || !version_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
        if invalid {
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

        if let Some(record_and_path) =
            self.try_live_version_record_sync(bucket_name, key, version_id)
        {
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
        let stored_version = metadata.get("__version_id__").map(String::as_str);
        let matches = if version_id == "null" {
            stored_version.is_none_or(|v| v.is_empty() || v == "null")
        } else {
            stored_version == Some(version_id)
        };
        if !matches {
            return None;
        }
        let live_version = stored_version.unwrap_or("null").to_string();
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
        let tags = self
            .read_index_entry_sync(bucket_name, key)
            .and_then(|entry| entry.get("tags").cloned())
            .unwrap_or(Value::Null);
        let record = serde_json::json!({
            "version_id": live_version,
            "key": key,
            "size": file_meta.len(),
            "archived_at": archived_at.to_rfc3339(),
            "etag": etag,
            "metadata": Value::Object(meta_json),
            "tags": tags,
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
        let mut dir_idx_cache: HashMap<
            PathBuf,
            HashMap<String, (Option<String>, Option<String>, Option<String>)>,
        > = HashMap::new();
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
                    let is_keydata_marker = name_str.as_ref() == KEY_DATA_MARKER_FILE;
                    if is_dir_marker {
                        fs_rel = fs_rel
                            .strip_suffix(DIR_MARKER_FILE)
                            .unwrap_or(&fs_rel)
                            .to_string();
                    } else if is_keydata_marker {
                        fs_rel = fs_rel
                            .strip_suffix(KEY_DATA_MARKER_FILE)
                            .unwrap_or(&fs_rel)
                            .trim_end_matches('/')
                            .to_string();
                    }
                    if let Ok(meta) = entry.metadata() {
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);

                        let lookup_path = if is_keydata_marker {
                            Path::new(&fs_rel).to_path_buf()
                        } else {
                            Path::new(&fs_rel)
                                .parent()
                                .map(|p| p.to_path_buf())
                                .unwrap_or_default()
                        };
                        let lookup_name = if is_keydata_marker {
                            Path::new(&fs_rel)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| name_str.to_string())
                        } else {
                            name_str.to_string()
                        };
                        let rel_dir = if is_keydata_marker {
                            Path::new(&fs_rel)
                                .parent()
                                .map(|p| p.to_path_buf())
                                .unwrap_or_default()
                        } else {
                            lookup_path
                        };
                        let idx = dir_idx_cache.entry(rel_dir.clone()).or_insert_with(|| {
                            self.load_dir_index_full_sync(bucket_name, &rel_dir)
                        });
                        let (etag, version_id, owner) = if is_dir_marker {
                            (None, None, None)
                        } else {
                            idx.get(lookup_name.as_str())
                                .cloned()
                                .unwrap_or((None, None, None))
                        };

                        let key = fs_decode_key(&fs_rel);
                        all_keys.push((key, meta.len(), mtime, etag, version_id, owner));
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
        let prefix = params
            .prefix
            .as_deref()
            .map(|p| p.trim_start_matches(['/', '\\']));
        if let Some(prefix) = prefix {
            if !prefix.is_empty() {
                validate_list_prefix(prefix)?;
            }
        }

        let listing = self.get_full_listing_sync(bucket_name)?;

        let (slice_start, slice_end) = match prefix {
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
            .map(|(key, size, mtime, etag, version_id, owner)| {
                let lm = Utc
                    .timestamp_opt(*mtime as i64, ((*mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
                    .unwrap_or_else(Utc::now);
                let mut obj = ObjectMeta::new(key.clone(), *size, lm);
                obj.etag = etag.clone();
                obj.version_id = version_id.clone();
                obj.owner = owner.clone();
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

        let dir_index = self.load_dir_index_full_sync(bucket_name, rel_dir);

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
                dirs.push(format!("{}{}{}", rel_dir_prefix, display_name, delimiter));
                let marker_path = entry.path().join(KEY_DATA_MARKER_FILE);
                if let Ok(marker_meta) = std::fs::metadata(&marker_path) {
                    if marker_meta.is_file() {
                        let mtime = marker_meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);
                        let lm = Utc
                            .timestamp_opt(
                                mtime as i64,
                                ((mtime % 1.0) * 1_000_000_000.0) as u32,
                            )
                            .single()
                            .unwrap_or_else(Utc::now);
                        let rel = format!("{}{}", rel_dir_prefix, display_name);
                        let mut obj = ObjectMeta::new(rel, marker_meta.len(), lm);
                        let (etag, _vid, owner) = dir_index
                            .get(&name_str)
                            .cloned()
                            .unwrap_or((None, None, None));
                        obj.etag = etag;
                        obj.owner = owner;
                        files.push(obj);
                    }
                }
            } else if ft.is_file() {
                if name_str == KEY_DATA_MARKER_FILE {
                    continue;
                }
                if name_str == DIR_MARKER_FILE {
                    if !rel_dir_prefix.is_empty() {
                        if let Ok(meta) = entry.metadata() {
                            let mtime = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(0.0);
                            let lm = Utc
                                .timestamp_opt(
                                    mtime as i64,
                                    ((mtime % 1.0) * 1_000_000_000.0) as u32,
                                )
                                .single()
                                .unwrap_or_else(Utc::now);
                            let mut obj =
                                ObjectMeta::new(rel_dir_prefix.clone(), meta.len(), lm);
                            obj.etag = None;
                            files.push(obj);
                        }
                    }
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
                    let (etag, _vid, owner) = dir_index
                        .get(&name_str)
                        .cloned()
                        .unwrap_or((None, None, None));
                    let mut obj = ObjectMeta::new(rel, meta.len(), lm);
                    obj.etag = etag;
                    obj.owner = owner;
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

        let prefix = params.prefix.trim_start_matches(['/', '\\']);

        let rel_dir: PathBuf = if prefix.is_empty() {
            PathBuf::new()
        } else {
            validate_list_prefix(prefix)?;
            let encoded_prefix = fs_encode_key(prefix);
            let prefix_path = Path::new(&encoded_prefix);
            if prefix.ends_with(&params.delimiter) {
                prefix_path.to_path_buf()
            } else {
                prefix_path.parent().unwrap_or(Path::new("")).to_path_buf()
            }
        };

        let cached = self.get_shallow_sync(bucket_name, &rel_dir, &params.delimiter)?;

        let (file_start, file_end) = slice_range_for_prefix(&cached.files, |o| &o.key, prefix);
        let (dir_start, dir_end) = slice_range_for_prefix(&cached.dirs, |s| s, prefix);
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
        etag_override: Option<String>,
    ) -> StorageResult<ObjectMeta> {
        let etag = etag_override.unwrap_or(etag);
        self.require_bucket(bucket_name)?;
        let bucket_root = self.bucket_path(bucket_name);
        self.ensure_writable_parents_sync(&bucket_root, key)
            .map_err(StorageError::Io)?;
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
        let mut release_old_segments: Option<String> = None;
        if is_overwrite {
            let existing_meta = self.read_metadata_sync(bucket_name, key);
            let old_segments = existing_meta
                .get(crate::segments::META_KEY_SEGMENTS)
                .cloned();
            match versioning_status {
                VersioningStatus::Enabled => {
                    self.archive_current_version_sync(bucket_name, key, "overwrite")
                        .map_err(StorageError::Io)?;
                }
                VersioningStatus::Suspended => {
                    let existing_vid = existing_meta
                        .get("__version_id__")
                        .map(String::as_str)
                        .unwrap_or("");
                    if !existing_vid.is_empty() && existing_vid != "null" {
                        self.archive_current_version_sync(bucket_name, key, "overwrite")
                            .map_err(StorageError::Io)?;
                    } else {
                        release_old_segments = old_segments;
                    }
                }
                VersioningStatus::Disabled => {
                    release_old_segments = old_segments;
                }
            }
        }
        if matches!(versioning_status, VersioningStatus::Suspended) {
            self.purge_archived_null_version_sync(bucket_name, key)
                .map_err(StorageError::Io)?;
        }

        std::fs::rename(tmp_path, &destination).map_err(|e| {
            let _ = std::fs::remove_file(tmp_path);
            StorageError::Io(e)
        })?;

        if let Some(seg_id) = release_old_segments {
            self.release_segment_dir(bucket_name, &seg_id);
        }

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
        if let Some(ref user_meta) = metadata {
            for (k, v) in user_meta {
                if STORAGE_MANAGED_METADATA_KEYS.contains(&k.as_str()) {
                    continue;
                }
                internal_meta.insert(k.clone(), v.clone());
            }
        }
        internal_meta.insert("__etag__".to_string(), etag.clone());
        internal_meta.insert("__size__".to_string(), new_size.to_string());
        internal_meta.insert("__last_modified__".to_string(), mtime.to_string());
        if let Some(ref vid) = new_version_id {
            internal_meta.insert("__version_id__".to_string(), vid.clone());
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
                if validation::is_reserved_bucket_name(&name_str) {
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
        if validation::is_reserved_bucket_name(name) {
            return Err(StorageError::InvalidBucketName(format!(
                "Bucket name '{}' is reserved",
                name
            )));
        }
        if let Some(err) = validation::validate_bucket_name(name) {
            return Err(StorageError::InvalidBucketName(err));
        }
        let bucket_path = self.bucket_path(name);
        if let Some(parent) = bucket_path.parent() {
            std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }
        match std::fs::create_dir(&bucket_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StorageError::BucketAlreadyExists(name.to_string()));
            }
            Err(err) => return Err(StorageError::Io(err)),
        }
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
        if validation::is_reserved_bucket_name(name) {
            return Ok(false);
        }
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
        self.put_object_with_etag_override(bucket, key, stream, metadata, None)
            .await
    }

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (obj, content) = run_blocking(|| self.open_object_for_read_sync(bucket, key))?;
        let stream = content
            .into_range_stream(0, None)
            .await
            .map_err(StorageError::Io)?;
        Ok((obj, stream))
    }

    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        len: Option<u64>,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let (obj, content) = run_blocking(|| self.open_object_for_read_sync(bucket, key))?;
        if start > obj.size {
            return Err(StorageError::InvalidRange);
        }
        let stream = content
            .into_range_stream(start, len)
            .await
            .map_err(StorageError::Io)?;
        Ok((obj, stream))
    }

    async fn get_object_snapshot(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, tokio::fs::File)> {
        let (obj, content) = run_blocking(|| self.open_object_for_read_sync(bucket, key))?;
        match content {
            OpenedObjectContent::Single(file) => Ok((obj, tokio::fs::File::from_std(file))),
            OpenedObjectContent::Segmented { .. } => Err(StorageError::Internal(
                "get_object_snapshot is not supported for segmented objects".to_string(),
            )),
        }
    }

    async fn get_object_version_snapshot(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, tokio::fs::File)> {
        let (obj, content) =
            run_blocking(|| self.open_version_for_read_sync(bucket, key, version_id))?;
        match content {
            OpenedObjectContent::Single(file) => Ok((obj, tokio::fs::File::from_std(file))),
            OpenedObjectContent::Segmented { .. } => Err(StorageError::Internal(
                "get_object_version_snapshot is not supported for segmented objects".to_string(),
            )),
        }
    }

    async fn snapshot_object_to_link(
        &self,
        bucket: &str,
        key: &str,
        link_path: &std::path::Path,
    ) -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
        let link_owned = link_path.to_owned();
        run_blocking(|| -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (obj, content) = self.open_object_for_read_locked_sync(bucket, key)?;
            match content {
                OpenedObjectContent::Single(_) => {
                    let path = self.object_path(bucket, key)?;
                    if let Some(parent) = link_owned.parent() {
                        std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
                    }
                    let _ = std::fs::remove_file(&link_owned);
                    std::fs::hard_link(&path, &link_owned).map_err(StorageError::Io)?;
                    Ok((obj, crate::traits::SnapshotSource::LinkedFile(link_owned)))
                }
                segmented => Ok((obj, segmented.into_snapshot_source(link_owned))),
            }
        })
    }

    async fn snapshot_object_version_to_link(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        link_path: &std::path::Path,
    ) -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
        let link_owned = link_path.to_owned();
        run_blocking(|| -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (obj, content) =
                self.open_version_for_read_locked_sync(bucket, key, version_id)?;
            match content {
                OpenedObjectContent::Single(_) => {
                    let (_, data_path) =
                        self.read_version_record_sync(bucket, key, version_id)?;
                    if let Some(parent) = link_owned.parent() {
                        std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
                    }
                    let _ = std::fs::remove_file(&link_owned);
                    std::fs::hard_link(&data_path, &link_owned).map_err(StorageError::Io)?;
                    Ok((obj, crate::traits::SnapshotSource::LinkedFile(link_owned)))
                }
                segmented => Ok((obj, segmented.into_snapshot_source(link_owned))),
            }
        })
    }

    async fn materialize_object_to_tmp(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        let tmp_dir = self.tmp_dir();
        std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
        let dest = tmp_dir.join(format!("mat-{}", Uuid::new_v4()));
        let dest_owned = dest.clone();
        run_blocking(move || -> StorageResult<()> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (_, content) = self.open_object_for_read_locked_sync(bucket, key)?;
            match content {
                OpenedObjectContent::Single(_) => {
                    let path = self.object_path(bucket, key)?;
                    if std::fs::hard_link(&path, &dest_owned).is_err() {
                        std::fs::copy(&path, &dest_owned).map_err(StorageError::Io)?;
                    }
                    Ok(())
                }
                OpenedObjectContent::Segmented { files, .. } => {
                    let mut out = std::fs::File::create(&dest_owned).map_err(StorageError::Io)?;
                    for (mut file, expected) in files {
                        let copied =
                            std::io::copy(&mut file, &mut out).map_err(StorageError::Io)?;
                        if copied != expected {
                            return Err(StorageError::Internal(
                                "segment changed while materializing object".to_string(),
                            ));
                        }
                    }
                    Ok(())
                }
            }
        })
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&dest);
        })?;
        Ok(dest)
    }

    async fn get_object_path(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        self.require_bucket(bucket)?;
        let path = self.object_path(bucket, key)?;
        if !path.is_file() {
            let stored_meta = self.read_metadata_sync(bucket, key);
            if metadata_is_corrupted(&stored_meta) {
                return Err(StorageError::ObjectCorrupted {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    detail: metadata_corruption_detail(&stored_meta),
                });
            }
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
                let stored_meta = self.read_metadata_sync(bucket, key);
                if metadata_is_corrupted(&stored_meta) {
                    return Err(StorageError::ObjectCorrupted {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                        detail: metadata_corruption_detail(&stored_meta),
                    });
                }
                if self
                    .read_bucket_config_sync(bucket)
                    .versioning_status()
                    .is_active()
                {
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
            if metadata_is_corrupted(&stored_meta) {
                return Err(StorageError::ObjectCorrupted {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    detail: metadata_corruption_detail(&stored_meta),
                });
            }
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
        let (obj, content) =
            run_blocking(|| self.open_version_for_read_sync(bucket, key, version_id))?;
        let stream = content
            .into_range_stream(0, None)
            .await
            .map_err(StorageError::Io)?;
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
        let (obj, content) =
            run_blocking(|| self.open_version_for_read_sync(bucket, key, version_id))?;
        if start > obj.size {
            return Err(StorageError::InvalidRange);
        }
        let stream = content
            .into_range_stream(start, len)
            .await
            .map_err(StorageError::Io)?;
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

    async fn get_archived_null_version_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<Option<HashMap<String, String>>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (manifest_path, _) = self.version_record_paths(bucket, key, "null");
            if !manifest_path.is_file() {
                return Ok(None);
            }
            let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
            let record: Value = serde_json::from_str(&content).map_err(StorageError::Json)?;
            Ok(Some(Self::version_metadata_from_record(&record)))
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
                    } else if let Some(seg_id) =
                        existing_meta.get(crate::segments::META_KEY_SEGMENTS)
                    {
                        self.release_segment_dir(bucket, seg_id);
                    }
                    Self::safe_unlink(&path).map_err(StorageError::Io)?;
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    Self::cleanup_empty_parents(&path, &bucket_path);
                } else {
                    let stored_meta = self.read_metadata_sync(bucket, key);
                    if !stored_meta.is_empty() {
                        self.delete_metadata_sync(bucket, key)
                            .map_err(StorageError::Io)?;
                    }
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
                let stored_meta = self.read_metadata_sync(bucket, key);
                if !stored_meta.is_empty() {
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    self.invalidate_bucket_caches(bucket);
                    return Ok(DeleteOutcome {
                        version_id: None,
                        is_delete_marker: false,
                        existed: true,
                    });
                }
                return Ok(DeleteOutcome::default());
            }

            let stored_meta = self.read_metadata_sync(bucket, key);
            if let Some(seg_id) = stored_meta.get(crate::segments::META_KEY_SEGMENTS) {
                self.release_segment_dir(bucket, seg_id);
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
                let stored_version = metadata.get("__version_id__").map(String::as_str);
                let live_matches = if version_id == "null" {
                    stored_version.is_none_or(|v| v.is_empty() || v == "null")
                } else {
                    stored_version == Some(version_id)
                };
                if live_matches {
                    if let Some(seg_id) = metadata.get(crate::segments::META_KEY_SEGMENTS) {
                        self.release_segment_dir(bucket, seg_id);
                    }
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

            let version_record = if manifest_path.is_file() {
                std::fs::read_to_string(&manifest_path)
                    .ok()
                    .and_then(|content| serde_json::from_str::<Value>(&content).ok())
            } else {
                None
            };
            let is_delete_marker = version_record
                .as_ref()
                .and_then(|record| record.get("is_delete_marker").and_then(Value::as_bool))
                .unwrap_or(false);
            if let Some(seg_id) = version_record
                .as_ref()
                .and_then(|record| record.get("segment_id").and_then(Value::as_str))
            {
                self.release_segment_dir(bucket, seg_id);
            }

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

        let copy_res = run_blocking(
            || -> StorageResult<(String, u64, HashMap<String, String>)> {
                let _src_guard = self.get_object_lock(src_bucket, src_key).read();
                let (obj, content) =
                    self.open_object_for_read_locked_sync(src_bucket, src_key)?;

                use std::io::{BufReader, BufWriter, Read, Write};
                let mut reader: Box<dyn Read> = match content {
                    OpenedObjectContent::Single(file) => {
                        Box::new(BufReader::with_capacity(chunk_size, file))
                    }
                    OpenedObjectContent::Segmented { files, .. } => {
                        Box::new(crate::segments::OpenSegmentsRead::new(files))
                    }
                };
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

                let mut src_metadata = obj.internal_metadata;
                src_metadata.remove(crate::segments::META_KEY_SEGMENTS);
                src_metadata.remove(META_KEY_PART_SIZES);
                Ok((format!("{:x}", hasher.finalize()), total, src_metadata))
            },
        );

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
                None,
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

    async fn put_object_version_metadata(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            self.validate_key(key)?;
            Self::validate_version_id(bucket, key, version_id)?;

            if self
                .try_live_version_record_sync(bucket, key, version_id)
                .is_some()
            {
                let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
                let meta_map: serde_json::Map<String, Value> = metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                entry.insert("metadata".to_string(), Value::Object(meta_map));
                self.write_index_entry_sync(bucket, key, &entry)
                    .map_err(StorageError::Io)?;
                self.invalidate_bucket_caches(bucket);
                return Ok(());
            }

            let (manifest_path, _data_path) =
                self.version_record_paths(bucket, key, version_id);
            if !manifest_path.is_file() {
                return Err(StorageError::VersionNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: version_id.to_string(),
                });
            }
            let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
            let mut record: Value =
                serde_json::from_str(&content).map_err(StorageError::Json)?;
            let meta_map: serde_json::Map<String, Value> = metadata
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            match record {
                Value::Object(ref mut map) => {
                    map.insert("metadata".to_string(), Value::Object(meta_map));
                }
                _ => {
                    return Err(StorageError::Internal(
                        "Invalid version manifest".to_string(),
                    ));
                }
            }
            let new_content = serde_json::to_string_pretty(&record).map_err(StorageError::Json)?;
            let tmp = manifest_path.with_extension("json.tmp");
            std::fs::write(&tmp, new_content.as_bytes()).map_err(StorageError::Io)?;
            std::fs::rename(&tmp, &manifest_path).map_err(StorageError::Io)?;
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
                return Err(StorageError::Io(std::io::Error::other(
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
        src_version_id: Option<&str>,
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
        let src_version_id = src_version_id.map(str::to_string);

        let copy_res = run_blocking(|| -> StorageResult<(String, u64, DateTime<Utc>)> {
            let _guard = self.get_object_lock(src_bucket, src_key).read();

            let (obj, content) = match src_version_id.as_deref() {
                Some(version_id) => {
                    self.open_version_for_read_locked_sync(src_bucket, src_key, version_id)?
                }
                None => self.open_object_for_read_locked_sync(src_bucket, src_key)?,
            };
            let src_size = obj.size;
            let last_modified = obj.last_modified;

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

            use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
            let mut src: Box<dyn Read> = match content {
                OpenedObjectContent::Single(mut file) => {
                    if start > 0 {
                        file.seek(SeekFrom::Start(start)).map_err(StorageError::Io)?;
                    }
                    Box::new(std::io::BufReader::with_capacity(chunk_size, file))
                }
                OpenedObjectContent::Segmented { files, .. } => Box::new(
                    crate::segments::OpenSegmentsRead::with_window(files, start, length)
                        .map_err(StorageError::Io)?,
                ),
            };
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
        });

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
        let manifest_parts = manifest
            .get("parts")
            .and_then(|p| p.as_object())
            .cloned()
            .unwrap_or_default();

        let segments_allowed = self.multipart_layout == MultipartLayout::Segments
            && part_infos.len() >= 2
            && !metadata.contains_key(MULTIPART_PENDING_SSE_ALG)
            && !metadata.contains_key(MULTIPART_PENDING_SSE_KMS_KEY)
            && !metadata.contains_key(MULTIPART_PENDING_SSE_C_KEY)
            && !metadata.contains_key(MPU_SSE_C_MARKER);
        let segment_dir = self.segments_bucket_root(bucket).join(upload_id);
        let segment_id = upload_id.to_string();
        let upload_lock =
            self.get_meta_index_lock(&upload_dir.join(".manifest.lock").to_string_lossy());

        let assemble_res = tokio::task::spawn_blocking(
            move || -> StorageResult<(String, u64, Vec<u64>, Option<String>)> {
                use std::io::Read;
                let mut md5_digest_concat = Vec::with_capacity(part_infos.len() * 16);
                let mut total_size: u64 = 0;
                let mut part_sizes: Vec<u64> = Vec::with_capacity(part_infos.len());

                for part_info in &part_infos {
                    let part_file =
                        upload_dir_owned.join(format!("part-{:05}.part", part_info.part_number));
                    if !part_file.exists() {
                        return Err(StorageError::InvalidObjectKey(format!(
                            "Part {} not found",
                            part_info.part_number
                        )));
                    }
                    let file_size = std::fs::metadata(&part_file)
                        .map_err(StorageError::Io)?
                        .len();
                    let manifest_entry = manifest_parts.get(&part_info.part_number.to_string());
                    let manifest_etag = manifest_entry
                        .and_then(|e| e.get("etag"))
                        .and_then(|v| v.as_str());
                    let manifest_size = manifest_entry
                        .and_then(|e| e.get("size"))
                        .and_then(|v| v.as_u64());
                    match (manifest_etag.and_then(parse_md5_hex), manifest_size) {
                        (Some(digest), Some(size)) if size == file_size => {
                            md5_digest_concat.extend_from_slice(&digest);
                        }
                        _ => {
                            let reader =
                                std::fs::File::open(&part_file).map_err(StorageError::Io)?;
                            let mut reader =
                                std::io::BufReader::with_capacity(chunk_size, reader);
                            let mut part_hasher = Md5::new();
                            let mut buf = vec![0u8; chunk_size];
                            loop {
                                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                                if n == 0 {
                                    break;
                                }
                                part_hasher.update(&buf[..n]);
                            }
                            md5_digest_concat.extend_from_slice(&part_hasher.finalize());
                        }
                    }
                    part_sizes.push(file_size);
                    total_size += file_size;
                }

                let mut composite_hasher = Md5::new();
                composite_hasher.update(&md5_digest_concat);
                let etag = format!("{:x}-{}", composite_hasher.finalize(), part_infos.len());

                if part_infos.len() == 1 {
                    let part_file =
                        upload_dir_owned.join(format!("part-{:05}.part", part_infos[0].part_number));
                    if std::fs::rename(&part_file, &tmp_path_owned).is_err() {
                        std::fs::copy(&part_file, &tmp_path_owned).map_err(StorageError::Io)?;
                    }
                    return Ok((etag, total_size, part_sizes, None));
                }

                if segments_allowed && total_size >= crate::segments::SEGMENT_MIN_TOTAL {
                    let _guard = upload_lock.lock();
                    std::fs::create_dir_all(&segment_dir).map_err(StorageError::Io)?;
                    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(part_infos.len());
                    let mut move_err: Option<std::io::Error> = None;
                    for (ordinal, part_info) in part_infos.iter().enumerate() {
                        let part_file = upload_dir_owned
                            .join(format!("part-{:05}.part", part_info.part_number));
                        let seg_file = segment_dir
                            .join(crate::segments::SegmentSet::seg_file_name(ordinal));
                        match std::fs::rename(&part_file, &seg_file) {
                            Ok(()) => moved.push((seg_file, part_file)),
                            Err(e) => {
                                move_err = Some(e);
                                break;
                            }
                        }
                    }
                    if let Some(e) = move_err {
                        for (seg_file, part_file) in moved.into_iter().rev() {
                            let _ = std::fs::rename(&seg_file, &part_file);
                        }
                        let _ = std::fs::remove_dir(&segment_dir);
                        return Err(StorageError::Io(e));
                    }

                    let header = crate::segments::StubHeader::new(
                        segment_id.clone(),
                        part_sizes.clone(),
                        etag.clone(),
                    );
                    if let Err(e) = crate::segments::write_stub(&tmp_path_owned, &header) {
                        for (seg_file, part_file) in moved.into_iter().rev() {
                            let _ = std::fs::rename(&seg_file, &part_file);
                        }
                        let _ = std::fs::remove_dir(&segment_dir);
                        return Err(StorageError::Io(e));
                    }
                    return Ok((etag, total_size, part_sizes, Some(segment_id)));
                }

                let mut out_file =
                    std::fs::File::create(&tmp_path_owned).map_err(StorageError::Io)?;
                for (part_info, expected) in part_infos.iter().zip(&part_sizes) {
                    let part_file = upload_dir_owned
                        .join(format!("part-{:05}.part", part_info.part_number));
                    let mut src = std::fs::File::open(&part_file).map_err(StorageError::Io)?;
                    let copied =
                        std::io::copy(&mut src, &mut out_file).map_err(StorageError::Io)?;
                    if copied != *expected {
                        return Err(StorageError::Internal(format!(
                            "Part {} changed while completing the multipart upload",
                            part_info.part_number
                        )));
                    }
                }
                Ok((etag, total_size, part_sizes, None))
            },
        )
        .await;

        let (etag, total_size, part_sizes, segmented_as) = match assemble_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
            Err(join) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(StorageError::Io(std::io::Error::other(
                    join,
                )));
            }
        };

        let mut metadata = metadata;
        metadata.insert(META_KEY_PART_SIZES.to_string(), encode_part_sizes(&part_sizes));
        if let Some(ref seg_id) = segmented_as {
            metadata.insert(
                crate::segments::META_KEY_SEGMENTS.to_string(),
                seg_id.clone(),
            );
        }

        let result = run_blocking(|| {
            let _guard = self.get_object_lock(bucket, &object_key).write();
            self.finalize_put_sync(
                bucket,
                &object_key,
                &tmp_path,
                etag,
                total_size,
                Some(metadata),
                None,
            )
        });

        match result {
            Ok(obj) => {
                let _ = std::fs::remove_dir_all(&upload_dir);
                Ok(obj)
            }
            Err(e) => {
                if parts.len() == 1 && tmp_path.exists() {
                    let part_file =
                        upload_dir.join(format!("part-{:05}.part", parts[0].part_number));
                    if std::fs::rename(&tmp_path, &part_file).is_err() {
                        let _ = std::fs::remove_file(&tmp_path);
                    }
                } else {
                    let _ = std::fs::remove_file(&tmp_path);
                    if let Some(ref seg_id) = segmented_as {
                        let seg_dir = self.segments_bucket_root(bucket).join(seg_id);
                        for (ordinal, part_info) in parts.iter().enumerate() {
                            let seg_file =
                                seg_dir.join(crate::segments::SegmentSet::seg_file_name(ordinal));
                            let part_file = upload_dir
                                .join(format!("part-{:05}.part", part_info.part_number));
                            let _ = std::fs::rename(&seg_file, &part_file);
                        }
                        let _ = std::fs::remove_dir(&seg_dir);
                    }
                }
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

    async fn get_multipart_metadata(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> StorageResult<HashMap<String, String>> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }
        let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let manifest: Value = serde_json::from_str(&content).map_err(StorageError::Json)?;
        let metadata = manifest
            .get("metadata")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default();
        Ok(metadata)
    }

    async fn get_multipart_part_path(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
    ) -> StorageResult<PathBuf> {
        let upload_dir = self.multipart_bucket_root(bucket).join(upload_id);
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        if !manifest_path.exists() {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }
        let part_file = upload_dir.join(format!("part-{:05}.part", part_number));
        if !part_file.is_file() {
            return Err(StorageError::InvalidObjectKey(format!(
                "Part {} not found",
                part_number
            )));
        }
        Ok(part_file)
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

    async fn get_object_version_tags(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<Vec<Tag>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, _data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            let tags = record
                .get("tags")
                .and_then(|v| serde_json::from_value::<Vec<Tag>>(v.clone()).ok())
                .unwrap_or_default();
            Ok(tags)
        })
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
    async fn test_create_bucket_rejects_reserved_name() {
        let (_dir, backend) = create_test_backend();
        let err = backend
            .create_bucket("myfsio")
            .await
            .expect_err("creating reserved bucket name must fail");
        assert!(
            matches!(err, crate::error::StorageError::InvalidBucketName(ref msg) if msg.contains("reserved")),
            "expected InvalidBucketName(reserved …), got {:?}",
            err
        );
        assert!(!backend.bucket_exists("myfsio").await.unwrap());
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
    async fn test_put_object_after_prefix_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
        backend
            .put_object("test-bucket", "folder/file", data, None)
            .await
            .unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
        backend
            .put_object("test-bucket", "folder", data, None)
            .await
            .expect("PUT 'folder' after 'folder/file' should succeed");

        let (obj, mut stream) = backend
            .get_object("test-bucket", "folder")
            .await
            .unwrap();
        assert_eq!(obj.size, 5);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"outer");

        let (_, mut stream) = backend
            .get_object("test-bucket", "folder/file")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"inner");
    }

    #[tokio::test]
    async fn test_head_and_delete_collided_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
        backend
            .put_object("test-bucket", "folder/file", data, None)
            .await
            .unwrap();
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
        backend
            .put_object("test-bucket", "folder", data, None)
            .await
            .unwrap();

        let meta = backend
            .head_object("test-bucket", "folder")
            .await
            .expect("head on collided key");
        assert_eq!(meta.size, 5);

        backend
            .delete_object("test-bucket", "folder")
            .await
            .expect("delete collided key");
        assert!(backend.head_object("test-bucket", "folder").await.is_err());
        let inner = backend
            .head_object("test-bucket", "folder/file")
            .await
            .expect("sibling key survives");
        assert_eq!(inner.size, 5);
    }

    #[tokio::test]
    async fn test_put_prefix_object_after_object() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
        backend
            .put_object("test-bucket", "folder", data, None)
            .await
            .unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
        backend
            .put_object("test-bucket", "folder/file", data, None)
            .await
            .expect("PUT 'folder/file' after 'folder' should succeed");

        let (_, mut stream) = backend
            .get_object("test-bucket", "folder")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"outer");

        let (_, mut stream) = backend
            .get_object("test-bucket", "folder/file")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"inner");
    }

    #[tokio::test]
    async fn test_list_carries_per_object_owner() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let acl_alice = serde_json::to_string(&serde_json::json!({
            "owner": "alice",
            "grants": [],
        }))
        .unwrap();
        let acl_bob = serde_json::to_string(&serde_json::json!({
            "owner": "bob",
            "grants": [],
        }))
        .unwrap();

        let mut meta_a: HashMap<String, String> = HashMap::new();
        meta_a.insert("__acl__".to_string(), acl_alice);
        backend
            .put_object(
                "test-bucket",
                "alice-file",
                Box::pin(std::io::Cursor::new(b"a".to_vec())),
                Some(meta_a),
            )
            .await
            .unwrap();

        let mut meta_b: HashMap<String, String> = HashMap::new();
        meta_b.insert("__acl__".to_string(), acl_bob);
        backend
            .put_object(
                "test-bucket",
                "bob-file",
                Box::pin(std::io::Cursor::new(b"b".to_vec())),
                Some(meta_b),
            )
            .await
            .unwrap();

        let result = backend
            .list_objects(
                "test-bucket",
                &myfsio_common::types::ListParams {
                    max_keys: 100,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let by_key: HashMap<_, _> = result
            .objects
            .into_iter()
            .map(|o| (o.key.clone(), o.owner.clone()))
            .collect();
        assert_eq!(
            by_key.get("alice-file").and_then(|o| o.clone()),
            Some("alice".to_string())
        );
        assert_eq!(
            by_key.get("bob-file").and_then(|o| o.clone()),
            Some("bob".to_string())
        );
    }

    #[tokio::test]
    async fn test_list_after_collision_shows_both_keys() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"inner".to_vec()));
        backend
            .put_object("test-bucket", "folder/file", data, None)
            .await
            .unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"outer".to_vec()));
        backend
            .put_object("test-bucket", "folder", data, None)
            .await
            .unwrap();

        let params = myfsio_common::types::ListParams {
            max_keys: 100,
            ..Default::default()
        };
        let result = backend.list_objects("test-bucket", &params).await.unwrap();
        let keys: Vec<&str> = result.objects.iter().map(|o| o.key.as_str()).collect();
        assert!(
            keys.contains(&"folder"),
            "flat list missing 'folder' key: {:?}",
            keys
        );
        assert!(
            keys.contains(&"folder/file"),
            "flat list missing 'folder/file' key: {:?}",
            keys
        );
        for k in &keys {
            assert!(
                !k.contains(KEY_DATA_MARKER_FILE),
                "internal marker leaked into listing: {}",
                k
            );
        }

        let shallow_params = myfsio_common::types::ShallowListParams {
            prefix: String::new(),
            delimiter: "/".to_string(),
            max_keys: 100,
            continuation_token: None,
        };
        let shallow = backend
            .list_objects_shallow("test-bucket", &shallow_params)
            .await
            .unwrap();
        let shallow_keys: Vec<&str> =
            shallow.objects.iter().map(|o| o.key.as_str()).collect();
        assert!(
            shallow_keys.contains(&"folder"),
            "shallow list missing 'folder': {:?}",
            shallow_keys
        );
        assert!(
            shallow.common_prefixes.contains(&"folder/".to_string()),
            "shallow common-prefixes missing 'folder/': {:?}",
            shallow.common_prefixes
        );
        for k in &shallow_keys {
            assert!(
                !k.contains(KEY_DATA_MARKER_FILE),
                "internal marker leaked into shallow listing: {}",
                k
            );
        }
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
    async fn test_poisoned_object_returns_object_corrupted_on_read() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"poisoned bytes".to_vec()));
        backend
            .put_object("test-bucket", "rotted.txt", data, None)
            .await
            .unwrap();

        let mut meta = backend
            .get_object_metadata("test-bucket", "rotted.txt")
            .await
            .unwrap();
        meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
        meta.insert(
            META_KEY_CORRUPTION_DETAIL.to_string(),
            "etag mismatch: stored=abc actual=def".to_string(),
        );
        backend
            .put_object_metadata("test-bucket", "rotted.txt", &meta)
            .await
            .unwrap();

        let res = backend.get_object("test-bucket", "rotted.txt").await;
        match res {
            Err(StorageError::ObjectCorrupted { .. }) => {}
            Err(other) => panic!("expected ObjectCorrupted, got {:?}", other),
            Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
        }

        let res = backend.head_object("test-bucket", "rotted.txt").await;
        match res {
            Err(StorageError::ObjectCorrupted { .. }) => {}
            Err(other) => panic!("expected ObjectCorrupted, got {:?}", other),
            Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_poisoned_object_with_missing_file_still_returns_corrupted() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"will be quarantined".to_vec()));
        backend
            .put_object("test-bucket", "rotted.txt", data, None)
            .await
            .unwrap();

        let mut meta = backend
            .get_object_metadata("test-bucket", "rotted.txt")
            .await
            .unwrap();
        meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
        meta.insert(
            META_KEY_CORRUPTION_DETAIL.to_string(),
            "etag mismatch (no peer)".to_string(),
        );
        backend
            .put_object_metadata("test-bucket", "rotted.txt", &meta)
            .await
            .unwrap();

        let live_path = backend
            .get_object_path("test-bucket", "rotted.txt")
            .await
            .expect("path lookup should succeed before quarantine");
        std::fs::remove_file(&live_path).expect("simulate quarantine: remove live file");

        let res = backend.get_object("test-bucket", "rotted.txt").await;
        match res {
            Err(StorageError::ObjectCorrupted { .. }) => {}
            Err(other) => panic!("expected ObjectCorrupted after quarantine, got {:?}", other),
            Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
        }

        let res = backend.head_object("test-bucket", "rotted.txt").await;
        match res {
            Err(StorageError::ObjectCorrupted { .. }) => {}
            Err(other) => panic!("expected ObjectCorrupted after quarantine, got {:?}", other),
            Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
        }

        let res = backend.get_object_path("test-bucket", "rotted.txt").await;
        match res {
            Err(StorageError::ObjectCorrupted { .. }) => {}
            Err(other) => panic!("expected ObjectCorrupted, got {:?}", other),
            Ok(_) => panic!("expected ObjectCorrupted, got Ok"),
        }
    }

    #[tokio::test]
    async fn test_delete_object_metadata_entry_removes_index_entry() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"x".to_vec()));
        backend
            .put_object("test-bucket", "ghost.txt", data, None)
            .await
            .unwrap();
        let path = backend
            .get_object_path("test-bucket", "ghost.txt")
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();

        backend
            .delete_object_metadata_entry("test-bucket", "ghost.txt")
            .await
            .unwrap();

        let stored = backend
            .get_object_metadata("test-bucket", "ghost.txt")
            .await
            .unwrap();
        assert!(
            stored.is_empty(),
            "metadata entry must be gone, got: {:?}",
            stored
        );
    }

    #[test]
    fn test_part_sizes_roundtrip() {
        let sizes = vec![5_242_880, 5_242_880, 5_242_880, 12_345];
        let encoded = encode_part_sizes(&sizes);
        assert_eq!(encoded, "5242880,5242880,5242880,12345");
        let parsed = parse_part_sizes(&encoded).unwrap();
        assert_eq!(parsed, sizes);
        assert!(parse_part_sizes("").is_none());
        assert!(parse_part_sizes(",,,").is_none());
        assert!(parse_part_sizes("abc").is_none());
        assert!(parse_part_sizes("123,abc").is_none());
        assert!(parse_part_sizes(" ").is_none());
    }

    #[tokio::test]
    async fn test_delete_object_clears_poisoned_metadata() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"will rot".to_vec()));
        backend
            .put_object("test-bucket", "rot.txt", data, None)
            .await
            .unwrap();

        let mut meta = backend
            .get_object_metadata("test-bucket", "rot.txt")
            .await
            .unwrap();
        meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
        backend
            .put_object_metadata("test-bucket", "rot.txt", &meta)
            .await
            .unwrap();

        let live_path = backend
            .get_object_path("test-bucket", "rot.txt")
            .await
            .unwrap();
        std::fs::remove_file(&live_path).unwrap();

        backend
            .delete_object("test-bucket", "rot.txt")
            .await
            .unwrap();

        match backend.head_object("test-bucket", "rot.txt").await {
            Err(StorageError::ObjectNotFound { .. }) => {}
            other => panic!(
                "after DELETE on a poisoned/quarantined object, HEAD should be ObjectNotFound, got {:?}",
                other
            ),
        }

        let leftover = backend
            .get_object_metadata("test-bucket", "rot.txt")
            .await
            .unwrap();
        assert!(
            leftover.is_empty(),
            "metadata sidecar must be cleared after DELETE on poisoned object"
        );
    }

    #[tokio::test]
    async fn test_complete_multipart_persists_part_sizes() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("mp-bucket").await.unwrap();

        let upload_id = backend
            .initiate_multipart("mp-bucket", "obj.bin", None)
            .await
            .unwrap();

        let part1: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'A'; 1024]));
        backend
            .upload_part("mp-bucket", &upload_id, 1, part1)
            .await
            .unwrap();
        let part2: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'B'; 512]));
        backend
            .upload_part("mp-bucket", &upload_id, 2, part2)
            .await
            .unwrap();

        let parts = vec![
            PartInfo {
                part_number: 1,
                etag: String::new(),
            },
            PartInfo {
                part_number: 2,
                etag: String::new(),
            },
        ];
        let obj = backend
            .complete_multipart("mp-bucket", &upload_id, &parts)
            .await
            .unwrap();
        assert_eq!(obj.size, 1536);

        let stored = backend
            .get_object_metadata("mp-bucket", "obj.bin")
            .await
            .unwrap();
        let raw = stored
            .get(META_KEY_PART_SIZES)
            .expect("part sizes must be persisted on completion");
        assert_eq!(parse_part_sizes(raw).unwrap(), vec![1024u64, 512u64]);
    }

    async fn read_stream_to_end(mut stream: AsyncReadStream) -> Vec<u8> {
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    }

    async fn seed_segmented_object(
        backend: &FsStorageBackend,
        bucket: &str,
        key: &str,
        parts_data: &[Vec<u8>],
    ) -> (String, ObjectMeta) {
        let upload_id = backend.initiate_multipart(bucket, key, None).await.unwrap();
        let mut parts = Vec::new();
        for (i, data) in parts_data.iter().enumerate() {
            let stream: AsyncReadStream = Box::pin(std::io::Cursor::new(data.clone()));
            let etag = backend
                .upload_part(bucket, &upload_id, (i + 1) as u32, stream)
                .await
                .unwrap();
            parts.push(PartInfo {
                part_number: (i + 1) as u32,
                etag,
            });
        }
        let obj = backend
            .complete_multipart(bucket, &upload_id, &parts)
            .await
            .unwrap();
        (upload_id, obj)
    }

    fn segmented_parts() -> Vec<Vec<u8>> {
        vec![
            (0..5000u32).map(|i| (i % 251) as u8).collect(),
            (0..4000u32).map(|i| (i % 13) as u8).collect(),
        ]
    }

    fn expected_composite_etag(parts_data: &[Vec<u8>]) -> String {
        let mut concat = Vec::new();
        for p in parts_data {
            concat.extend_from_slice(&Md5::digest(p));
        }
        format!("{:x}-{}", Md5::digest(&concat), parts_data.len())
    }

    #[tokio::test]
    async fn test_segmented_complete_roundtrip() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("seg-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let full: Vec<u8> = parts_data.concat();

        let (upload_id, obj) = seed_segmented_object(&backend, "seg-bkt", "v.bin", &parts_data).await;
        assert_eq!(obj.size, full.len() as u64);
        assert_eq!(obj.etag.as_deref(), Some(expected_composite_etag(&parts_data).as_str()));

        let stored = backend
            .get_object_metadata("seg-bkt", "v.bin")
            .await
            .unwrap();
        assert_eq!(
            stored.get(crate::segments::META_KEY_SEGMENTS),
            Some(&upload_id)
        );

        let live_path = backend.object_path("seg-bkt", "v.bin").unwrap();
        let header = crate::segments::read_stub_header(&live_path)
            .unwrap()
            .expect("live file must be a segment stub");
        assert_eq!(header.total, full.len() as u64);
        assert_eq!(
            std::fs::metadata(&live_path).unwrap().len(),
            full.len() as u64
        );
        let seg_dir = backend.segments_bucket_root("seg-bkt").join(&upload_id);
        assert!(seg_dir.is_dir());

        let (meta, stream) = backend.get_object("seg-bkt", "v.bin").await.unwrap();
        assert_eq!(meta.size, full.len() as u64);
        assert_eq!(read_stream_to_end(stream).await, full);

        let (_, stream) = backend
            .get_object_range("seg-bkt", "v.bin", 4990, Some(30))
            .await
            .unwrap();
        assert_eq!(read_stream_to_end(stream).await, &full[4990..5020]);

        let head = backend.head_object("seg-bkt", "v.bin").await.unwrap();
        assert_eq!(head.size, full.len() as u64);

        let listing = backend
            .list_objects("seg-bkt", &ListParams::default())
            .await
            .unwrap();
        let entry = listing
            .objects
            .iter()
            .find(|o| o.key == "v.bin")
            .expect("listed");
        assert_eq!(entry.size, full.len() as u64);
    }

    #[tokio::test]
    async fn test_segmented_and_concat_layouts_agree() {
        let dir = tempfile::tempdir().unwrap();
        let concat_backend = FsStorageBackend::new_with_config(
            dir.path().to_path_buf(),
            FsStorageBackendConfig {
                multipart_layout: MultipartLayout::Concat,
                ..FsStorageBackendConfig::default()
            },
        );
        concat_backend.create_bucket("cmp-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let (_, concat_obj) =
            seed_segmented_object(&concat_backend, "cmp-bkt", "c.bin", &parts_data).await;

        let (_dir2, seg_backend) = create_test_backend();
        seg_backend.create_bucket("cmp-bkt").await.unwrap();
        let (_, seg_obj) =
            seed_segmented_object(&seg_backend, "cmp-bkt", "c.bin", &parts_data).await;

        assert_eq!(concat_obj.etag, seg_obj.etag);
        assert_eq!(concat_obj.size, seg_obj.size);

        let concat_meta = concat_backend
            .get_object_metadata("cmp-bkt", "c.bin")
            .await
            .unwrap();
        assert!(!concat_meta.contains_key(crate::segments::META_KEY_SEGMENTS));

        let (_, s1) = concat_backend.get_object("cmp-bkt", "c.bin").await.unwrap();
        let (_, s2) = seg_backend.get_object("cmp-bkt", "c.bin").await.unwrap();
        assert_eq!(read_stream_to_end(s1).await, read_stream_to_end(s2).await);
    }

    #[tokio::test]
    async fn test_segmented_delete_releases_segment_dir() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segdel-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let (upload_id, _) =
            seed_segmented_object(&backend, "segdel-bkt", "d.bin", &parts_data).await;
        let seg_dir = backend.segments_bucket_root("segdel-bkt").join(&upload_id);
        assert!(seg_dir.is_dir());
        backend.delete_object("segdel-bkt", "d.bin").await.unwrap();
        assert!(!seg_dir.exists());
    }

    #[tokio::test]
    async fn test_segmented_overwrite_releases_old_segment_dir() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segow-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let (upload_id, _) =
            seed_segmented_object(&backend, "segow-bkt", "o.bin", &parts_data).await;
        let seg_dir = backend.segments_bucket_root("segow-bkt").join(&upload_id);
        assert!(seg_dir.is_dir());

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"tiny".to_vec()));
        backend
            .put_object("segow-bkt", "o.bin", data, None)
            .await
            .unwrap();
        assert!(!seg_dir.exists());
        let (_, stream) = backend.get_object("segow-bkt", "o.bin").await.unwrap();
        assert_eq!(read_stream_to_end(stream).await, b"tiny");
    }

    #[tokio::test]
    async fn test_segmented_versioned_overwrite_and_restore() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segver-bkt").await.unwrap();
        backend.set_versioning("segver-bkt", true).await.unwrap();
        let parts_data = segmented_parts();
        let full: Vec<u8> = parts_data.concat();
        let (upload_id, obj) =
            seed_segmented_object(&backend, "segver-bkt", "vv.bin", &parts_data).await;
        let v1 = obj.version_id.clone().expect("versioned complete");
        let seg_dir = backend.segments_bucket_root("segver-bkt").join(&upload_id);

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"second".to_vec()));
        backend
            .put_object("segver-bkt", "vv.bin", data, None)
            .await
            .unwrap();
        assert!(
            seg_dir.is_dir(),
            "versioned overwrite must transfer segment ownership, not delete"
        );

        let (_, data_path) = backend.version_record_paths("segver-bkt", "vv.bin", &v1);
        let header = crate::segments::read_stub_header(&data_path)
            .unwrap()
            .expect("archived version must be a stub");
        assert_eq!(header.total, full.len() as u64);
        assert_eq!(
            std::fs::metadata(&data_path).unwrap().len(),
            full.len() as u64
        );

        let (vmeta, vstream) = backend
            .get_object_version("segver-bkt", "vv.bin", &v1)
            .await
            .unwrap();
        assert_eq!(vmeta.size, full.len() as u64);
        assert_eq!(read_stream_to_end(vstream).await, full);

        let (_, vrange) = backend
            .get_object_version_range("segver-bkt", "vv.bin", &v1, 4999, Some(2))
            .await
            .unwrap();
        assert_eq!(read_stream_to_end(vrange).await, &full[4999..5001]);

        let live_meta = backend
            .get_object_metadata("segver-bkt", "vv.bin")
            .await
            .unwrap();
        let v2 = live_meta.get("__version_id__").cloned().unwrap();
        backend
            .delete_object_version("segver-bkt", "vv.bin", &v2)
            .await
            .unwrap();
        let (_, stream) = backend.get_object("segver-bkt", "vv.bin").await.unwrap();
        assert_eq!(
            read_stream_to_end(stream).await,
            full,
            "promoted segmented version must serve original bytes"
        );
        assert!(seg_dir.is_dir());

        backend
            .delete_object_version("segver-bkt", "vv.bin", &v1)
            .await
            .unwrap();
        assert!(!seg_dir.exists(), "deleting the last owner must release segments");
    }

    #[tokio::test]
    async fn test_segmented_copy_object_produces_single_file() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segcp-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let full: Vec<u8> = parts_data.concat();
        seed_segmented_object(&backend, "segcp-bkt", "src.bin", &parts_data).await;

        let copied = backend
            .copy_object("segcp-bkt", "src.bin", "segcp-bkt", "dst.bin")
            .await
            .unwrap();
        assert_eq!(copied.size, full.len() as u64);

        let dst_meta = backend
            .get_object_metadata("segcp-bkt", "dst.bin")
            .await
            .unwrap();
        assert!(!dst_meta.contains_key(crate::segments::META_KEY_SEGMENTS));
        assert!(!dst_meta.contains_key(META_KEY_PART_SIZES));

        let (_, stream) = backend.get_object("segcp-bkt", "dst.bin").await.unwrap();
        assert_eq!(read_stream_to_end(stream).await, full);

        let dst_path = backend.object_path("segcp-bkt", "dst.bin").unwrap();
        assert!(crate::segments::read_stub_header(&dst_path)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_segmented_upload_part_copy_across_boundary() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segpc-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let full: Vec<u8> = parts_data.concat();
        seed_segmented_object(&backend, "segpc-bkt", "src.bin", &parts_data).await;

        let upload_id = backend
            .initiate_multipart("segpc-bkt", "dst.bin", None)
            .await
            .unwrap();
        backend
            .upload_part_copy(
                "segpc-bkt",
                &upload_id,
                1,
                "segpc-bkt",
                "src.bin",
                None,
                Some((4000, 6999)),
            )
            .await
            .unwrap();
        let part_path = backend
            .get_multipart_part_path("segpc-bkt", &upload_id, 1)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&part_path).unwrap(), &full[4000..7000]);
        backend
            .abort_multipart("segpc-bkt", &upload_id)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_segmented_materialize_to_tmp() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segmat-bkt").await.unwrap();
        let parts_data = segmented_parts();
        let full: Vec<u8> = parts_data.concat();
        seed_segmented_object(&backend, "segmat-bkt", "m.bin", &parts_data).await;

        let tmp = backend
            .materialize_object_to_tmp("segmat-bkt", "m.bin")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&tmp).unwrap(), full);
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn test_small_multipart_falls_back_to_concat() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("segsm-bkt").await.unwrap();
        let parts_data = vec![vec![b'A'; 1024], vec![b'B'; 512]];
        seed_segmented_object(&backend, "segsm-bkt", "s.bin", &parts_data).await;
        let stored = backend
            .get_object_metadata("segsm-bkt", "s.bin")
            .await
            .unwrap();
        assert!(!stored.contains_key(crate::segments::META_KEY_SEGMENTS));
        let (_, stream) = backend.get_object("segsm-bkt", "s.bin").await.unwrap();
        assert_eq!(read_stream_to_end(stream).await, parts_data.concat());
    }

    #[tokio::test]
    async fn test_put_clears_poison_flag() {
        let (_dir, backend) = create_test_backend();
        backend.create_bucket("test-bucket").await.unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"first".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, None)
            .await
            .unwrap();

        let mut meta = backend
            .get_object_metadata("test-bucket", "file.txt")
            .await
            .unwrap();
        meta.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
        backend
            .put_object_metadata("test-bucket", "file.txt", &meta)
            .await
            .unwrap();

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(b"replacement".to_vec()));
        backend
            .put_object("test-bucket", "file.txt", data, None)
            .await
            .unwrap();

        match backend.get_object("test-bucket", "file.txt").await {
            Ok(_) => {}
            Err(e) => panic!("get must succeed after PUT clears poison, got {:?}", e),
        }
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

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; 4096]));
        backend
            .put_object("link-bkt", "hot", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

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
                        Ok((meta, _source)) => {
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

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; 1024]));
        backend
            .put_object("snap-bkt", "sz", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

        for w in 0..2 {
            let b = backend.clone();
            let stop = stop.clone();
            handles.push(tokio::spawn(async move {
                let mut i: u32 = 0;
                while !stop.load(Ordering::Relaxed) {
                    let fill = b'a' + ((w + i) % 20) as u8;
                    let size = if i.is_multiple_of(2) { 1024 } else { 2048 };
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

        const SIZE: u64 = 256 * 1024;
        let seed = vec![b'a'; SIZE as usize];
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
        backend
            .put_object("range-bkt", "hot", data, None)
            .await
            .unwrap();

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
                    if let Ok((meta, mut stream)) = b
                        .get_object_range("range-bkt", "hot", start, Some(len))
                        .await
                    {
                        let mut buf = Vec::with_capacity(len as usize);
                        if stream.read_to_end(&mut buf).await.is_ok() && !buf.is_empty() {
                            let fill = buf[0];
                            let all_match = buf.iter().all(|b| *b == fill);
                            let expected_etag =
                                format!("{:x}", Md5::digest(vec![fill; SIZE as usize]));
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

        const SIZE: u64 = 64 * 1024;
        let etag_a = format!("{:x}", Md5::digest(vec![b'a'; SIZE as usize]));
        let etag_b = format!("{:x}", Md5::digest(vec![b'b'; SIZE as usize]));

        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(vec![b'a'; SIZE as usize]));
        backend
            .put_object("mp-bkt", "src", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

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
                        .upload_part_copy("mp-bkt", &upload_id, 1, "mp-bkt", "src", None, None)
                        .await;
                    if let Ok((etag, _lm)) = res {
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
        assert!(
            o >= 4,
            "expected at least a few upload_part_copy ops, got {}",
            o
        );
        assert_eq!(
            x, 0,
            "observed {} upload_part_copy results with etag unrelated to source content (out of {})",
            x, o
        );
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

        let seed = vec![b'x'; 1_048_576];
        let data: AsyncReadStream = Box::pin(std::io::Cursor::new(seed));
        backend
            .put_object("contend", "hot", data, None)
            .await
            .unwrap();

        let stop = StdArc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();

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
                    let fill = b'a'.wrapping_add(w * 8 + i  );
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
