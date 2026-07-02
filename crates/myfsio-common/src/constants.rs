pub const SYSTEM_ROOT: &str = ".myfsio.sys";
pub const SYSTEM_BUCKETS_DIR: &str = "buckets";
pub const SYSTEM_MULTIPART_DIR: &str = "multipart";
pub const BUCKET_META_DIR: &str = "meta";
pub const BUCKET_VERSIONS_DIR: &str = "versions";
pub const BUCKET_CONFIG_FILE: &str = ".bucket.json";
pub const STATS_FILE: &str = "stats.json";
pub const ETAG_INDEX_FILE: &str = "etag_index.json";
pub const INDEX_FILE: &str = "_index.json";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const DIR_MARKER_FILE: &str = ".__myfsio_dirobj__";
pub const KEY_DATA_MARKER_FILE: &str = ".__myfsio_keydata__";

pub const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];

pub const MULTIPART_PENDING_SSE_ALG: &str = "__pending_sse_algorithm__";
pub const MULTIPART_PENDING_SSE_KMS_KEY: &str = "__pending_sse_kms_key_id__";
pub const MULTIPART_PENDING_SSE_C_KEY: &str = "__pending_sse_c_customer_key__";
pub const MPU_SSE_C_MARKER: &str = "__mpu_sse_c__";

pub const DEFAULT_REGION: &str = "us-east-1";
pub const AWS_SERVICE: &str = "s3";

pub const DEFAULT_MAX_KEYS: usize = 1000;
pub const DEFAULT_OBJECT_KEY_MAX_BYTES: usize = 1024;
pub const DEFAULT_CHUNK_SIZE: usize = 65536;
pub const STREAM_CHUNK_SIZE: usize = 1_048_576;
