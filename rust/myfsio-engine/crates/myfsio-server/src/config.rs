use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub storage_root: PathBuf,
    pub region: String,
    pub iam_config_path: PathBuf,
    pub sigv4_timestamp_tolerance_secs: u64,
    pub presigned_url_min_expiry: u64,
    pub presigned_url_max_expiry: u64,
    pub secret_key: Option<String>,
    pub encryption_enabled: bool,
    pub kms_enabled: bool,
    pub gc_enabled: bool,
    pub integrity_enabled: bool,
    pub metrics_enabled: bool,
    pub lifecycle_enabled: bool,
    pub website_hosting_enabled: bool,
    pub replication_connect_timeout_secs: u64,
    pub replication_read_timeout_secs: u64,
    pub replication_max_retries: u32,
    pub replication_streaming_threshold_bytes: u64,
    pub replication_max_failures_per_bucket: usize,
    pub site_sync_enabled: bool,
    pub site_sync_interval_secs: u64,
    pub site_sync_batch_size: usize,
    pub site_sync_connect_timeout_secs: u64,
    pub site_sync_read_timeout_secs: u64,
    pub site_sync_max_retries: u32,
    pub site_sync_clock_skew_tolerance: f64,
    pub ui_enabled: bool,
    pub templates_dir: PathBuf,
    pub static_dir: PathBuf,
}

impl ServerConfig {
    pub fn from_env() -> Self {
        let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port: u16 = std::env::var("PORT")
            .unwrap_or_else(|_| "5000".to_string())
            .parse()
            .unwrap_or(5000);
        let storage_root = std::env::var("STORAGE_ROOT")
            .unwrap_or_else(|_| "./data".to_string());
        let region = std::env::var("AWS_REGION")
            .unwrap_or_else(|_| "us-east-1".to_string());

        let storage_path = PathBuf::from(&storage_root);
        let iam_config_path = std::env::var("IAM_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                storage_path.join(".myfsio.sys").join("config").join("iam.json")
            });

        let sigv4_timestamp_tolerance_secs: u64 = std::env::var("SIGV4_TIMESTAMP_TOLERANCE_SECONDS")
            .unwrap_or_else(|_| "900".to_string())
            .parse()
            .unwrap_or(900);

        let presigned_url_min_expiry: u64 = std::env::var("PRESIGNED_URL_MIN_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()
            .unwrap_or(1);

        let presigned_url_max_expiry: u64 = std::env::var("PRESIGNED_URL_MAX_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "604800".to_string())
            .parse()
            .unwrap_or(604800);

        let secret_key = {
            let env_key = std::env::var("SECRET_KEY").ok();
            match env_key {
                Some(k) if !k.is_empty() && k != "dev-secret-key" => Some(k),
                _ => {
                    let secret_file = storage_path
                        .join(".myfsio.sys")
                        .join("config")
                        .join(".secret");
                    std::fs::read_to_string(&secret_file).ok().map(|s| s.trim().to_string())
                }
            }
        };

        let encryption_enabled = std::env::var("ENCRYPTION_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let kms_enabled = std::env::var("KMS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let gc_enabled = std::env::var("GC_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let integrity_enabled = std::env::var("INTEGRITY_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let metrics_enabled = std::env::var("OPERATION_METRICS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let lifecycle_enabled = std::env::var("LIFECYCLE_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let website_hosting_enabled = std::env::var("WEBSITE_HOSTING_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

        let replication_connect_timeout_secs = parse_u64_env("REPLICATION_CONNECT_TIMEOUT_SECONDS", 5);
        let replication_read_timeout_secs = parse_u64_env("REPLICATION_READ_TIMEOUT_SECONDS", 30);
        let replication_max_retries = parse_u64_env("REPLICATION_MAX_RETRIES", 2) as u32;
        let replication_streaming_threshold_bytes =
            parse_u64_env("REPLICATION_STREAMING_THRESHOLD_BYTES", 10_485_760);
        let replication_max_failures_per_bucket =
            parse_u64_env("REPLICATION_MAX_FAILURES_PER_BUCKET", 50) as usize;

        let site_sync_enabled = std::env::var("SITE_SYNC_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";
        let site_sync_interval_secs = parse_u64_env("SITE_SYNC_INTERVAL_SECONDS", 60);
        let site_sync_batch_size = parse_u64_env("SITE_SYNC_BATCH_SIZE", 100) as usize;
        let site_sync_connect_timeout_secs = parse_u64_env("SITE_SYNC_CONNECT_TIMEOUT_SECONDS", 10);
        let site_sync_read_timeout_secs = parse_u64_env("SITE_SYNC_READ_TIMEOUT_SECONDS", 120);
        let site_sync_max_retries = parse_u64_env("SITE_SYNC_MAX_RETRIES", 2) as u32;
        let site_sync_clock_skew_tolerance: f64 = std::env::var("SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1.0);

        let ui_enabled = std::env::var("UI_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .to_lowercase() == "true";
        let templates_dir = std::env::var("TEMPLATES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_templates_dir());
        let static_dir = std::env::var("STATIC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_static_dir());

        Self {
            bind_addr: SocketAddr::new(host.parse().unwrap(), port),
            storage_root: storage_path,
            region,
            iam_config_path,
            sigv4_timestamp_tolerance_secs,
            presigned_url_min_expiry,
            presigned_url_max_expiry,
            secret_key,
            encryption_enabled,
            kms_enabled,
            gc_enabled,
            integrity_enabled,
            metrics_enabled,
            lifecycle_enabled,
            website_hosting_enabled,
            replication_connect_timeout_secs,
            replication_read_timeout_secs,
            replication_max_retries,
            replication_streaming_threshold_bytes,
            replication_max_failures_per_bucket,
            site_sync_enabled,
            site_sync_interval_secs,
            site_sync_batch_size,
            site_sync_connect_timeout_secs,
            site_sync_read_timeout_secs,
            site_sync_max_retries,
            site_sync_clock_skew_tolerance,
            ui_enabled,
            templates_dir,
            static_dir,
        }
    }
}

fn default_templates_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("templates")
}

fn default_static_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for candidate in [
        manifest_dir.join("static"),
        manifest_dir.join("..").join("..").join("..").join("static"),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    manifest_dir.join("static")
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}
