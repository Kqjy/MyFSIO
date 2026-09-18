use crate::error::StorageError;
use crate::listing_index::{
    BucketListingIndex, ListingCounters, ListingRecord, VersionMutation, VersionMutationKind,
};
use crate::traits::{AsyncReadStream, StorageResult};
use crate::validation;
use myfsio_common::constants::*;
use myfsio_common::types::*;

use chrono::{DateTime, TimeZone, Utc};
use dashmap::DashMap;
use lru::LruCache;
use md5::{Digest, Md5};
#[cfg(test)]
use parking_lot::Condvar;
use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::{Component, Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::time::Instant;
use uuid::Uuid;

mod bucket_config;
mod casing;
mod engine;
mod integrity;
mod listing;
mod listing_compactor;
mod metadata;
mod migration;
mod multipart;
mod object_io;
mod recovery;
mod stats;
mod versioning;

#[cfg(test)]
use casing::DiskCasingVerdict;
use listing_compactor::wait_for_listing_compaction_install;
use listing_compactor::ListingCompactor;
use multipart::MultipartManifest;
pub use multipart::PreparedMultipartUpload;

const EMPTY_SEGMENT_SENTINEL: &str = ".__myfsio_empty__";

pub const META_KEY_CORRUPTED: &str = "__corrupted__";
pub const META_KEY_CORRUPTED_AT: &str = "__corrupted_at__";
pub const META_KEY_CORRUPTION_DETAIL: &str = "__corruption_detail__";
pub const META_KEY_QUARANTINE_PATH: &str = "__quarantine_path__";
pub const META_KEY_CORRUPTION_RETRY_COUNT: &str = "__corruption_retry_count__";
pub const META_KEY_CORRUPTION_LAST_RETRY_AT: &str = "__corruption_last_retry_at__";
pub const META_KEY_PART_SIZES: &str = "__part_sizes__";

pub const SIDECAR_FILE_PREFIX: &str = ".__myfsio_meta__";
pub const SIDECAR_FILE_EXT: &str = ".json";
pub const SIDECAR_ENTRY_NAME_FIELD: &str = "__entry_name__";
pub const SIDECAR_COMMIT_BUCKET_FIELD: &str = "__commit_bucket__";
pub const SIDECAR_COMMIT_KEY_FIELD: &str = "__commit_key__";
pub const META_KEY_COMMIT_MTIME_NS: &str = "__commit_mtime_ns__";
pub const META_KEY_UNREADABLE: &str = "__meta_unreadable__";
const SIDECAR_MAX_FILE_NAME_BYTES: usize = 255;

#[derive(Debug, Default, Clone)]
pub struct StagedCommitRecovery {
    pub published: Vec<RecoveredCommit>,
    pub discarded: usize,
    pub poisoned: usize,
}

#[derive(Debug, Clone)]
pub struct RecoveredCommit {
    pub bucket: String,
    pub key: String,
    pub staged_path: PathBuf,
}

const STORAGE_MANAGED_METADATA_KEYS: &[&str] = &[
    "__etag__",
    "__size__",
    "__last_modified__",
    "__version_id__",
    META_KEY_COMMIT_MTIME_NS,
    META_KEY_CORRUPTED,
    META_KEY_CORRUPTED_AT,
    META_KEY_CORRUPTION_DETAIL,
    META_KEY_QUARANTINE_PATH,
    META_KEY_CORRUPTION_RETRY_COUNT,
    META_KEY_CORRUPTION_LAST_RETRY_AT,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityQuarantineOutcome {
    Quarantined,
    Healthy,
    Skipped,
}

pub enum OpenedObjectContent {
    Single(std::fs::File),
    Segmented {
        source: crate::segments::LazySegmentSource,
        total: u64,
        base_offset: u64,
    },
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

pub fn metadata_has_pending_sse(meta: &HashMap<String, String>) -> bool {
    meta.contains_key(MULTIPART_PENDING_SSE_ALG)
        || meta.contains_key(MULTIPART_PENDING_SSE_KMS_KEY)
        || meta.contains_key(MULTIPART_PENDING_SSE_C_KEY)
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

const DIRECTORY_PUBLISH_STRIPES: usize = 512;

const DISK_CASING_RESOLVE_ATTEMPTS: usize = 8;

const DIRECTORY_PUBLISH_ATTEMPTS: usize = 16;

const DIRECTORY_PUBLISH_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

#[derive(Debug, Default)]
pub struct MetaMigrationPreflight {
    pub index_files: usize,
    pub entries: usize,
    pub corrupt: Vec<String>,
    pub collisions: Vec<String>,
}

#[derive(Debug, Default)]
pub struct MetaMigrationReport {
    pub index_files_migrated: usize,
    pub index_files_failed: usize,
    pub entries_written: usize,
    pub entries_skipped: usize,
    pub failures: Vec<String>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetadataLayout {
    #[default]
    Sidecar,
    Index,
}

impl MetadataLayout {
    pub fn from_env_str(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "index" => Self::Index,
            _ => Self::Sidecar,
        }
    }
}

pub struct FsStorageBackend {
    root: PathBuf,
    canonical_root: Option<PathBuf>,
    case_insensitive_fs: bool,
    object_key_max_length_bytes: usize,
    object_cache_max_size: usize,
    stream_chunk_size: usize,
    multipart_layout: MultipartLayout,
    metadata_layout: MetadataLayout,
    listing_index_enabled: bool,
    listing_index_compact_min_ops: usize,
    bucket_config_cache: DashMap<String, (BucketConfig, Instant)>,
    bucket_config_cache_ttl: std::time::Duration,
    meta_read_cache: Mutex<LruCache<(String, String), Option<HashMap<String, Value>>>>,
    meta_index_locks: DashMap<String, Arc<Mutex<()>>>,
    directory_publish_stripes: Box<[RwLock<()>]>,
    bucket_config_locks: DashMap<String, Arc<Mutex<()>>>,
    quota_locks: DashMap<String, Arc<Mutex<()>>>,
    object_lock_stripes: Box<[RwLock<()>]>,
    stats_cache: DashMap<String, (BucketStats, Instant)>,
    stats_cache_ttl: std::time::Duration,
    list_cache: DashMap<String, (Arc<Vec<ListCacheEntry>>, Instant)>,
    listing_indexes: DashMap<String, Arc<Mutex<BucketListingIndex>>>,
    listing_compactor: Option<ListingCompactor>,
    shallow_cache: DashMap<(String, PathBuf, String), (Arc<ShallowCacheEntry>, Instant)>,
    list_rebuild_locks: DashMap<String, Arc<Mutex<()>>>,
    shallow_rebuild_locks: DashMap<(String, PathBuf, String), Arc<Mutex<()>>>,
    list_cache_ttl: std::time::Duration,
    tmp_dir_durable: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    listing_full_builds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    stats_full_walks: std::sync::atomic::AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct FsStorageBackendConfig {
    pub object_key_max_length_bytes: usize,
    pub object_cache_max_size: usize,
    pub bucket_config_cache_ttl: std::time::Duration,
    pub stream_chunk_size: usize,
    pub multipart_layout: MultipartLayout,
    pub metadata_layout: MetadataLayout,
    pub listing_index_enabled: bool,
    pub listing_index_compact_min_ops: usize,
}

impl Default for FsStorageBackendConfig {
    fn default() -> Self {
        Self {
            object_key_max_length_bytes: DEFAULT_OBJECT_KEY_MAX_BYTES,
            object_cache_max_size: 1024,
            bucket_config_cache_ttl: std::time::Duration::from_secs(30),
            stream_chunk_size: STREAM_CHUNK_SIZE,
            multipart_layout: MultipartLayout::default(),
            metadata_layout: MetadataLayout::default(),
            listing_index_enabled: true,
            listing_index_compact_min_ops: 4096,
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
        let listing_compactor = config.listing_index_enabled.then(ListingCompactor::new);
        let object_lock_stripes = (0..OBJECT_LOCK_STRIPES)
            .map(|_| RwLock::new(()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let directory_publish_stripes = (0..DIRECTORY_PUBLISH_STRIPES)
            .map(|_| RwLock::new(()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let mut backend = Self {
            root,
            canonical_root: None,
            case_insensitive_fs: false,
            object_key_max_length_bytes: config.object_key_max_length_bytes,
            object_cache_max_size: config.object_cache_max_size,
            stream_chunk_size,
            multipart_layout: config.multipart_layout,
            metadata_layout: config.metadata_layout,
            listing_index_enabled: config.listing_index_enabled,
            listing_index_compact_min_ops: config.listing_index_compact_min_ops,
            bucket_config_cache: DashMap::new(),
            bucket_config_cache_ttl: config.bucket_config_cache_ttl,
            meta_read_cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(config.object_cache_max_size.max(1)).unwrap(),
            )),
            meta_index_locks: DashMap::new(),
            bucket_config_locks: DashMap::new(),
            quota_locks: DashMap::new(),
            object_lock_stripes,
            directory_publish_stripes,
            stats_cache: DashMap::new(),
            stats_cache_ttl: std::time::Duration::from_secs(60),
            list_cache: DashMap::new(),
            listing_indexes: DashMap::new(),
            listing_compactor,
            shallow_cache: DashMap::new(),
            list_rebuild_locks: DashMap::new(),
            shallow_rebuild_locks: DashMap::new(),
            list_cache_ttl: std::time::Duration::from_secs(5),
            tmp_dir_durable: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            listing_full_builds: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            stats_full_walks: std::sync::atomic::AtomicUsize::new(0),
        };
        backend.ensure_system_roots();
        backend.canonical_root = std::fs::canonicalize(&backend.root).ok();
        backend.case_insensitive_fs = backend.probe_case_insensitive_fs();
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

    fn bucket_listing_dir(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name).join("listing")
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

    fn multipart_upload_dir(&self, bucket_name: &str, upload_id: &str) -> StorageResult<PathBuf> {
        Self::guard_bucket_name(bucket_name)?;
        if !validation::is_valid_multipart_id(upload_id) {
            return Err(StorageError::UploadNotFound(upload_id.to_string()));
        }
        Ok(self.multipart_bucket_root(bucket_name).join(upload_id))
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
        crate::segments::SegmentSet::new(self.segments_bucket_root(bucket).join(segment_id), sizes)
    }

    fn object_path(&self, bucket_name: &str, object_key: &str) -> StorageResult<PathBuf> {
        self.validate_key(object_key)?;
        let encoded = fs_encode_key(object_key);
        let path = if object_key.ends_with('/') {
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
        };
        if !self.verify_disk_casing(&path)? {
            return Err(StorageError::ObjectNotFound {
                bucket: bucket_name.to_string(),
                key: object_key.to_string(),
            });
        }
        Ok(path)
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
            let meta = Self::stat_settled_entry_sync(&next)?;
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

    fn guard_bucket_name(bucket_name: &str) -> StorageResult<()> {
        match validation::bucket_name_rejection(bucket_name) {
            Some(err) => Err(StorageError::InvalidBucketName(err)),
            None => Ok(()),
        }
    }

    fn guard_contained(&self, path: &Path, bucket_name: &str) -> StorageResult<()> {
        if !path.starts_with(&self.root) {
            tracing::error!(
                bucket = bucket_name,
                path = %path.display(),
                root = %self.root.display(),
                "resolved bucket path escapes the storage root; refusing the operation"
            );
            return Err(StorageError::InvalidBucketName(format!(
                "Bucket name '{}' resolves outside the storage root",
                bucket_name
            )));
        }
        Ok(())
    }

    fn require_bucket(&self, bucket_name: &str) -> StorageResult<PathBuf> {
        Self::guard_bucket_name(bucket_name)?;
        let path = self.bucket_path(bucket_name);
        self.guard_contained(&path, bucket_name)?;
        if !path.exists() {
            return Err(StorageError::BucketNotFound(bucket_name.to_string()));
        }
        Ok(path)
    }

    fn fsync_dir(dir: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::fs::File::open(dir)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = dir;
            Ok(())
        }
    }

    fn fsync_dir_best_effort(dir: &Path) {
        let _ = Self::fsync_dir(dir);
    }

    fn get_meta_index_lock(&self, index_path: &str) -> Arc<Mutex<()>> {
        self.meta_index_locks
            .entry(index_path.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn quota_lock_if_configured(&self, bucket: &str) -> Option<Arc<Mutex<()>>> {
        self.read_bucket_config_sync(bucket)
            .quota
            .as_ref()
            .map(|_| {
                self.quota_locks
                    .entry(bucket.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone()
            })
    }

    fn etag_condition_matches(condition: &str, etag: Option<&str>) -> bool {
        let trimmed = condition.trim();
        if trimmed == "*" {
            return true;
        }
        let current = match etag {
            Some(e) => e.trim_matches('"'),
            None => return false,
        };
        trimmed
            .split(',')
            .map(|v| v.trim().trim_matches('"'))
            .any(|candidate| candidate == current || candidate == "*")
    }

    fn precondition_failed() -> StorageError {
        StorageError::PreconditionFailed(
            "At least one of the pre-conditions you specified did not hold".to_string(),
        )
    }

    fn evaluate_put_conditions_sync(
        conditions: &crate::traits::PutConditions,
        existing: Option<&HashMap<String, String>>,
    ) -> StorageResult<()> {
        let Some(meta) = existing else {
            if conditions.if_match.is_some() || conditions.if_unmodified_since.is_some() {
                return Err(Self::precondition_failed());
            }
            return Ok(());
        };
        let etag = meta
            .get("__etag__")
            .map(String::as_str)
            .filter(|e| !e.is_empty());
        let last_modified = meta
            .get("__last_modified__")
            .and_then(|value| value.parse::<f64>().ok())
            .and_then(|mtime| {
                Utc.timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
            });
        if let Some(ref value) = conditions.if_match {
            if !Self::etag_condition_matches(value, etag) {
                return Err(Self::precondition_failed());
            }
        } else if let (Some(t), Some(lm)) = (conditions.if_unmodified_since, last_modified) {
            if lm > t {
                return Err(Self::precondition_failed());
            }
        }
        if let Some(ref value) = conditions.if_none_match {
            if Self::etag_condition_matches(value, etag) {
                return Err(Self::precondition_failed());
            }
        } else if let (Some(t), Some(lm)) = (conditions.if_modified_since, last_modified) {
            if lm <= t {
                return Err(Self::precondition_failed());
            }
        }
        Ok(())
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
            Self::create_publish_dir_sync(parent)?;
        }
        let tmp_path = path.with_extension("tmp");
        let result = (|| {
            let file = std::fs::File::create(&tmp_path)?;
            let mut writer = std::io::BufWriter::new(file);
            serde_json::to_writer(&mut writer, data).map_err(std::io::Error::other)?;
            let file = writer.into_inner()?;
            if sync {
                file.sync_all()?;
            }
            drop(file);
            std::fs::rename(&tmp_path, path)?;
            if sync {
                if let Some(parent) = path.parent() {
                    Self::fsync_dir(parent)?;
                }
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    fn compute_etag_sync(path: &Path) -> std::io::Result<String> {
        myfsio_crypto::hashing::md5_file(path)
    }

    fn check_bucket_contents_sync(
        &self,
        bucket_path: &Path,
    ) -> std::io::Result<(bool, bool, bool)> {
        let bucket_name = bucket_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        let has_objects = Self::dir_has_files(bucket_path, Some(INTERNAL_FOLDERS))?;
        let has_versions = Self::dir_has_files(&self.bucket_versions_root(&bucket_name), None)?
            || Self::dir_has_files(&self.legacy_versions_root(&bucket_name), None)?;
        let has_multipart = Self::dir_has_files(&self.multipart_bucket_root(&bucket_name), None)?
            || Self::dir_has_files(&self.legacy_multipart_root(&bucket_name), None)?;

        Ok((has_objects, has_versions, has_multipart))
    }

    fn dir_has_files(dir: &Path, skip_dirs: Option<&[&str]>) -> std::io::Result<bool> {
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for entry in entries {
                let entry = entry?;
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
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e),
                };
                if ft.is_file() {
                    return Ok(true);
                }
                if ft.is_dir() {
                    stack.push(entry.path());
                }
            }
        }
        Ok(false)
    }

    fn remove_tree(path: &Path) -> std::io::Result<()> {
        match std::fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
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

    fn directory_publish_stripe(&self, directory: &Path) -> &RwLock<()> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        directory.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.directory_publish_stripes.len();
        &self.directory_publish_stripes[index]
    }

    fn directory_publish_guard(&self, directory: &Path) -> RwLockReadGuard<'_, ()> {
        self.directory_publish_stripe(directory).read()
    }

    fn try_lock_directory_for_prune(&self, directory: &Path) -> Option<RwLockWriteGuard<'_, ()>> {
        self.directory_publish_stripe(directory).try_write()
    }

    fn directory_may_be_vanishing(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::AlreadyExists
        )
    }

    fn stat_settled_entry_sync(path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
        let mut attempt = 0;
        loop {
            let err = match std::fs::symlink_metadata(path) {
                Ok(metadata) => return Ok(Some(metadata)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(err) => err,
            };
            attempt += 1;
            if attempt >= DIRECTORY_PUBLISH_ATTEMPTS || !Self::directory_may_be_vanishing(&err) {
                return Err(err);
            }
            std::thread::sleep(DIRECTORY_PUBLISH_RETRY_DELAY);
        }
    }

    fn create_publish_dir_sync(directory: &Path) -> std::io::Result<()> {
        let mut attempt = 0;
        loop {
            let err = match std::fs::create_dir_all(directory) {
                Ok(()) => return Ok(()),
                Err(err) => err,
            };
            attempt += 1;
            if attempt >= DIRECTORY_PUBLISH_ATTEMPTS || !Self::directory_may_be_vanishing(&err) {
                return Err(err);
            }
            std::thread::sleep(DIRECTORY_PUBLISH_RETRY_DELAY);
        }
    }

    fn publish_by_rename_sync(&self, source: &Path, destination: &Path) -> std::io::Result<()> {
        let Some(parent) = destination.parent() else {
            return std::fs::rename(source, destination);
        };
        let _guard = self.directory_publish_guard(parent);
        let mut attempt = 0;
        loop {
            let err = match std::fs::rename(source, destination) {
                Ok(()) => return Ok(()),
                Err(err) => err,
            };
            attempt += 1;
            if attempt >= DIRECTORY_PUBLISH_ATTEMPTS
                || !Self::directory_may_be_vanishing(&err)
                || Self::disk_entry_is_gone(source)
            {
                return Err(err);
            }
            let _ = std::fs::create_dir_all(parent);
            std::thread::sleep(DIRECTORY_PUBLISH_RETRY_DELAY);
        }
    }

    fn cleanup_empty_parents(&self, path: &Path, stop_at: &Path) {
        let mut parent = path.parent();
        while let Some(p) = parent {
            if p == stop_at {
                break;
            }
            let Some(_guard) = self.try_lock_directory_for_prune(p) else {
                break;
            };
            if std::fs::remove_dir(p).is_err() {
                break;
            }
            parent = p.parent();
        }
    }
}

impl Drop for FsStorageBackend {
    fn drop(&mut self) {
        if let Some(compactor) = &self.listing_compactor {
            compactor.shutdown();
        }
    }
}

#[cfg(test)]
mod tests;
