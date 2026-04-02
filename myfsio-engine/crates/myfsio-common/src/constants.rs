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

pub const INTERNAL_FOLDERS: &[&str] = &[".meta", ".versions", ".multipart"];

pub const DEFAULT_REGION: &str = "us-east-1";
pub const AWS_SERVICE: &str = "s3";

pub const DEFAULT_MAX_KEYS: usize = 1000;
pub const DEFAULT_OBJECT_KEY_MAX_BYTES: usize = 1024;
pub const DEFAULT_CHUNK_SIZE: usize = 65536;
pub const STREAM_CHUNK_SIZE: usize = 1_048_576;
