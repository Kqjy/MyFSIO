use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitSetting {
    pub max_requests: u32,
    pub window_seconds: u64,
}

impl RateLimitSetting {
    pub const fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub ui_bind_addr: SocketAddr,
    pub storage_root: PathBuf,
    pub region: String,
    pub iam_config_path: PathBuf,
    pub sigv4_timestamp_tolerance_secs: u64,
    pub presigned_url_min_expiry: u64,
    pub presigned_url_max_expiry: u64,
    pub secret_key: Option<String>,
    pub encryption_enabled: bool,
    pub encryption_chunk_size_bytes: usize,
    pub kms_enabled: bool,
    pub kms_generate_data_key_min_bytes: usize,
    pub kms_generate_data_key_max_bytes: usize,
    pub gc_enabled: bool,
    pub gc_interval_hours: f64,
    pub gc_temp_file_max_age_hours: f64,
    pub gc_multipart_max_age_days: u64,
    pub gc_lock_file_max_age_hours: f64,
    pub gc_dry_run: bool,
    pub integrity_enabled: bool,
    pub integrity_interval_hours: f64,
    pub integrity_batch_size: usize,
    pub integrity_auto_heal: bool,
    pub integrity_dry_run: bool,
    pub integrity_heal_concurrency: usize,
    pub integrity_quarantine_retention_days: u64,
    pub metrics_enabled: bool,
    pub metrics_history_enabled: bool,
    pub metrics_interval_minutes: u64,
    pub metrics_retention_hours: u64,
    pub metrics_history_interval_minutes: u64,
    pub metrics_history_retention_hours: u64,
    pub lifecycle_enabled: bool,
    pub lifecycle_max_history_per_bucket: usize,
    pub website_hosting_enabled: bool,
    pub object_key_max_length_bytes: usize,
    pub object_tag_limit: usize,
    pub object_cache_max_size: usize,
    pub bucket_config_cache_ttl_seconds: f64,
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
    pub site_id: Option<String>,
    pub site_endpoint: Option<String>,
    pub site_region: String,
    pub site_priority: i32,
    pub api_base_url: String,
    pub num_trusted_proxies: usize,
    pub allowed_redirect_hosts: Vec<String>,
    pub allow_internal_endpoints: bool,
    pub cors_origins: Vec<String>,
    pub cors_methods: Vec<String>,
    pub cors_allow_headers: Vec<String>,
    pub cors_expose_headers: Vec<String>,
    pub session_lifetime_days: u64,
    pub log_level: String,
    pub multipart_min_part_size: u64,
    pub bulk_delete_max_keys: usize,
    pub stream_chunk_size: usize,
    pub request_body_timeout_secs: u64,
    pub ratelimit_default: RateLimitSetting,
    pub ratelimit_list_buckets: RateLimitSetting,
    pub ratelimit_bucket_ops: RateLimitSetting,
    pub ratelimit_object_ops: RateLimitSetting,
    pub ratelimit_head_ops: RateLimitSetting,
    pub ratelimit_admin: RateLimitSetting,
    pub ratelimit_storage_uri: String,
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
        let host_ip: std::net::IpAddr = host.parse().unwrap();
        let bind_addr = SocketAddr::new(host_ip, port);
        let ui_port: u16 = std::env::var("UI_PORT")
            .unwrap_or_else(|_| "5100".to_string())
            .parse()
            .unwrap_or(5100);
        let storage_root = std::env::var("STORAGE_ROOT").unwrap_or_else(|_| "./data".to_string());
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let storage_path = PathBuf::from(&storage_root);
        let iam_config_path = std::env::var("IAM_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                storage_path
                    .join(".myfsio.sys")
                    .join("config")
                    .join("iam.json")
            });

        let sigv4_timestamp_tolerance_secs: u64 =
            std::env::var("SIGV4_TIMESTAMP_TOLERANCE_SECONDS")
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
                    std::fs::read_to_string(&secret_file)
                        .ok()
                        .map(|s| s.trim().to_string())
                }
            }
        };

        let encryption_enabled = parse_bool_env("ENCRYPTION_ENABLED", false);
        let encryption_chunk_size_bytes = parse_usize_env("ENCRYPTION_CHUNK_SIZE_BYTES", 65_536);

        let kms_enabled = parse_bool_env("KMS_ENABLED", false);
        let kms_generate_data_key_min_bytes = parse_usize_env("KMS_GENERATE_DATA_KEY_MIN_BYTES", 1);
        let kms_generate_data_key_max_bytes =
            parse_usize_env("KMS_GENERATE_DATA_KEY_MAX_BYTES", 1024);

        let gc_enabled = parse_bool_env("GC_ENABLED", false);
        let gc_interval_hours = parse_f64_env("GC_INTERVAL_HOURS", 6.0);
        let gc_temp_file_max_age_hours = parse_f64_env("GC_TEMP_FILE_MAX_AGE_HOURS", 24.0);
        let gc_multipart_max_age_days = parse_u64_env("GC_MULTIPART_MAX_AGE_DAYS", 7);
        let gc_lock_file_max_age_hours = parse_f64_env("GC_LOCK_FILE_MAX_AGE_HOURS", 1.0);
        let gc_dry_run = parse_bool_env("GC_DRY_RUN", false);

        let integrity_enabled = parse_bool_env("INTEGRITY_ENABLED", false);
        let integrity_interval_hours = parse_f64_env("INTEGRITY_INTERVAL_HOURS", 24.0);
        let integrity_batch_size = parse_usize_env("INTEGRITY_BATCH_SIZE", 10_000);
        let integrity_auto_heal = parse_bool_env("INTEGRITY_AUTO_HEAL", false);
        let integrity_dry_run = parse_bool_env("INTEGRITY_DRY_RUN", false);
        let integrity_heal_concurrency = parse_usize_env("INTEGRITY_HEAL_CONCURRENCY", 4);
        let integrity_quarantine_retention_days =
            parse_u64_env("INTEGRITY_QUARANTINE_RETENTION_DAYS", 7);

        let metrics_enabled = parse_bool_env("OPERATION_METRICS_ENABLED", false);

        let metrics_history_enabled = parse_bool_env("METRICS_HISTORY_ENABLED", false);

        let metrics_interval_minutes = parse_u64_env("OPERATION_METRICS_INTERVAL_MINUTES", 5);
        let metrics_retention_hours = parse_u64_env("OPERATION_METRICS_RETENTION_HOURS", 24);
        let metrics_history_interval_minutes = parse_u64_env("METRICS_HISTORY_INTERVAL_MINUTES", 5);
        let metrics_history_retention_hours = parse_u64_env("METRICS_HISTORY_RETENTION_HOURS", 24);

        let lifecycle_enabled = parse_bool_env("LIFECYCLE_ENABLED", false);
        let lifecycle_max_history_per_bucket =
            parse_usize_env("LIFECYCLE_MAX_HISTORY_PER_BUCKET", 50);

        let website_hosting_enabled = parse_bool_env("WEBSITE_HOSTING_ENABLED", false);
        let object_key_max_length_bytes = parse_usize_env("OBJECT_KEY_MAX_LENGTH_BYTES", 1024);
        let object_tag_limit = parse_usize_env("OBJECT_TAG_LIMIT", 50);
        let object_cache_max_size = parse_usize_env("OBJECT_CACHE_MAX_SIZE", 100);
        let bucket_config_cache_ttl_seconds =
            parse_f64_env("BUCKET_CONFIG_CACHE_TTL_SECONDS", 30.0);

        let replication_connect_timeout_secs =
            parse_u64_env("REPLICATION_CONNECT_TIMEOUT_SECONDS", 5);
        let replication_read_timeout_secs = parse_u64_env("REPLICATION_READ_TIMEOUT_SECONDS", 30);
        let replication_max_retries = parse_u64_env("REPLICATION_MAX_RETRIES", 2) as u32;
        let replication_streaming_threshold_bytes =
            parse_u64_env("REPLICATION_STREAMING_THRESHOLD_BYTES", 10_485_760);
        let replication_max_failures_per_bucket =
            parse_u64_env("REPLICATION_MAX_FAILURES_PER_BUCKET", 50) as usize;

        let site_sync_enabled = parse_bool_env("SITE_SYNC_ENABLED", false);
        let site_sync_interval_secs = parse_u64_env("SITE_SYNC_INTERVAL_SECONDS", 60);
        let site_sync_batch_size = parse_u64_env("SITE_SYNC_BATCH_SIZE", 100) as usize;
        let site_sync_connect_timeout_secs = parse_u64_env("SITE_SYNC_CONNECT_TIMEOUT_SECONDS", 10);
        let site_sync_read_timeout_secs = parse_u64_env("SITE_SYNC_READ_TIMEOUT_SECONDS", 120);
        let site_sync_max_retries = parse_u64_env("SITE_SYNC_MAX_RETRIES", 2) as u32;
        let site_sync_clock_skew_tolerance: f64 =
            std::env::var("SITE_SYNC_CLOCK_SKEW_TOLERANCE_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1.0);

        let site_id = parse_optional_string_env("SITE_ID");
        let site_endpoint = parse_optional_string_env("SITE_ENDPOINT");
        let site_region = std::env::var("SITE_REGION").unwrap_or_else(|_| region.clone());
        let site_priority = parse_i32_env("SITE_PRIORITY", 100);
        let api_base_url = std::env::var("API_BASE_URL")
            .unwrap_or_else(|_| format!("http://{}", bind_addr))
            .trim_end_matches('/')
            .to_string();
        let num_trusted_proxies = parse_usize_env("NUM_TRUSTED_PROXIES", 0);
        let allowed_redirect_hosts = parse_list_env("ALLOWED_REDIRECT_HOSTS", "");
        let allow_internal_endpoints = parse_bool_env("ALLOW_INTERNAL_ENDPOINTS", false);
        let cors_origins = parse_list_env("CORS_ORIGINS", "*");
        let cors_methods = parse_list_env("CORS_METHODS", "GET,PUT,POST,DELETE,OPTIONS,HEAD");
        let cors_allow_headers = parse_list_env("CORS_ALLOW_HEADERS", "*");
        let cors_expose_headers = parse_list_env("CORS_EXPOSE_HEADERS", "*");
        let session_lifetime_days = parse_u64_env("SESSION_LIFETIME_DAYS", 1);
        let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string());
        let multipart_min_part_size = parse_u64_env("MULTIPART_MIN_PART_SIZE", 5_242_880);
        let bulk_delete_max_keys = parse_usize_env("BULK_DELETE_MAX_KEYS", 1000);
        let stream_chunk_size = parse_usize_env("STREAM_CHUNK_SIZE", 1_048_576);
        let request_body_timeout_secs = parse_u64_env("REQUEST_BODY_TIMEOUT_SECONDS", 60);
        let ratelimit_default =
            parse_rate_limit_env("RATE_LIMIT_DEFAULT", RateLimitSetting::new(5000, 60));
        let ratelimit_list_buckets =
            parse_rate_limit_env("RATE_LIMIT_LIST_BUCKETS", ratelimit_default);
        let ratelimit_bucket_ops = parse_rate_limit_env("RATE_LIMIT_BUCKET_OPS", ratelimit_default);
        let ratelimit_object_ops = parse_rate_limit_env("RATE_LIMIT_OBJECT_OPS", ratelimit_default);
        let ratelimit_head_ops = parse_rate_limit_env("RATE_LIMIT_HEAD_OPS", ratelimit_default);
        let ratelimit_admin =
            parse_rate_limit_env("RATE_LIMIT_ADMIN", RateLimitSetting::new(60, 60));
        let ratelimit_storage_uri =
            std::env::var("RATE_LIMIT_STORAGE_URI").unwrap_or_else(|_| "memory://".to_string());

        let ui_enabled = parse_bool_env("UI_ENABLED", true);
        let templates_dir = std::env::var("TEMPLATES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_templates_dir());
        let static_dir = std::env::var("STATIC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_static_dir());

        Self {
            bind_addr,
            ui_bind_addr: SocketAddr::new(host_ip, ui_port),
            storage_root: storage_path,
            region,
            iam_config_path,
            sigv4_timestamp_tolerance_secs,
            presigned_url_min_expiry,
            presigned_url_max_expiry,
            secret_key,
            encryption_enabled,
            encryption_chunk_size_bytes,
            kms_enabled,
            kms_generate_data_key_min_bytes,
            kms_generate_data_key_max_bytes,
            gc_enabled,
            gc_interval_hours,
            gc_temp_file_max_age_hours,
            gc_multipart_max_age_days,
            gc_lock_file_max_age_hours,
            gc_dry_run,
            integrity_enabled,
            integrity_interval_hours,
            integrity_batch_size,
            integrity_auto_heal,
            integrity_dry_run,
            integrity_heal_concurrency,
            integrity_quarantine_retention_days,
            metrics_enabled,
            metrics_history_enabled,
            metrics_interval_minutes,
            metrics_retention_hours,
            metrics_history_interval_minutes,
            metrics_history_retention_hours,
            lifecycle_enabled,
            lifecycle_max_history_per_bucket,
            website_hosting_enabled,
            object_key_max_length_bytes,
            object_tag_limit,
            object_cache_max_size,
            bucket_config_cache_ttl_seconds,
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
            site_id,
            site_endpoint,
            site_region,
            site_priority,
            api_base_url,
            num_trusted_proxies,
            allowed_redirect_hosts,
            allow_internal_endpoints,
            cors_origins,
            cors_methods,
            cors_allow_headers,
            cors_expose_headers,
            session_lifetime_days,
            log_level,
            multipart_min_part_size,
            bulk_delete_max_keys,
            stream_chunk_size,
            request_body_timeout_secs,
            ratelimit_default,
            ratelimit_list_buckets,
            ratelimit_bucket_ops,
            ratelimit_object_ops,
            ratelimit_head_ops,
            ratelimit_admin,
            ratelimit_storage_uri,
            ui_enabled,
            templates_dir,
            static_dir,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:5000".parse().unwrap(),
            ui_bind_addr: "127.0.0.1:5100".parse().unwrap(),
            storage_root: PathBuf::from("./data"),
            region: "us-east-1".to_string(),
            iam_config_path: PathBuf::from("./data/.myfsio.sys/config/iam.json"),
            sigv4_timestamp_tolerance_secs: 900,
            presigned_url_min_expiry: 1,
            presigned_url_max_expiry: 604_800,
            secret_key: None,
            encryption_enabled: false,
            encryption_chunk_size_bytes: 65_536,
            kms_enabled: false,
            kms_generate_data_key_min_bytes: 1,
            kms_generate_data_key_max_bytes: 1024,
            gc_enabled: false,
            gc_interval_hours: 6.0,
            gc_temp_file_max_age_hours: 24.0,
            gc_multipart_max_age_days: 7,
            gc_lock_file_max_age_hours: 1.0,
            gc_dry_run: false,
            integrity_enabled: false,
            integrity_interval_hours: 24.0,
            integrity_batch_size: 10_000,
            integrity_auto_heal: false,
            integrity_dry_run: false,
            integrity_heal_concurrency: 4,
            integrity_quarantine_retention_days: 7,
            metrics_enabled: false,
            metrics_history_enabled: false,
            metrics_interval_minutes: 5,
            metrics_retention_hours: 24,
            metrics_history_interval_minutes: 5,
            metrics_history_retention_hours: 24,
            lifecycle_enabled: false,
            lifecycle_max_history_per_bucket: 50,
            website_hosting_enabled: false,
            object_key_max_length_bytes: 1024,
            object_tag_limit: 50,
            object_cache_max_size: 100,
            bucket_config_cache_ttl_seconds: 30.0,
            replication_connect_timeout_secs: 5,
            replication_read_timeout_secs: 30,
            replication_max_retries: 2,
            replication_streaming_threshold_bytes: 10_485_760,
            replication_max_failures_per_bucket: 50,
            site_sync_enabled: false,
            site_sync_interval_secs: 60,
            site_sync_batch_size: 100,
            site_sync_connect_timeout_secs: 10,
            site_sync_read_timeout_secs: 120,
            site_sync_max_retries: 2,
            site_sync_clock_skew_tolerance: 1.0,
            site_id: None,
            site_endpoint: None,
            site_region: "us-east-1".to_string(),
            site_priority: 100,
            api_base_url: "http://127.0.0.1:5000".to_string(),
            num_trusted_proxies: 0,
            allowed_redirect_hosts: Vec::new(),
            allow_internal_endpoints: false,
            cors_origins: vec!["*".to_string()],
            cors_methods: vec![
                "GET".to_string(),
                "PUT".to_string(),
                "POST".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
                "HEAD".to_string(),
            ],
            cors_allow_headers: vec!["*".to_string()],
            cors_expose_headers: vec!["*".to_string()],
            session_lifetime_days: 1,
            log_level: "INFO".to_string(),
            multipart_min_part_size: 5_242_880,
            bulk_delete_max_keys: 1000,
            stream_chunk_size: 1_048_576,
            request_body_timeout_secs: 60,
            ratelimit_default: RateLimitSetting::new(5000, 60),
            ratelimit_list_buckets: RateLimitSetting::new(5000, 60),
            ratelimit_bucket_ops: RateLimitSetting::new(5000, 60),
            ratelimit_object_ops: RateLimitSetting::new(5000, 60),
            ratelimit_head_ops: RateLimitSetting::new(5000, 60),
            ratelimit_admin: RateLimitSetting::new(60, 60),
            ratelimit_storage_uri: "memory://".to_string(),
            ui_enabled: true,
            templates_dir: default_templates_dir(),
            static_dir: default_static_dir(),
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

fn parse_usize_env(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn parse_i32_env(key: &str, default: i32) -> i32 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn parse_f64_env(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

fn parse_optional_string_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_list_env(key: &str, default: &str) -> Vec<String> {
    std::env::var(key)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

pub fn parse_rate_limit(value: &str) -> Option<RateLimitSetting> {
    let trimmed = value.trim();
    if let Some((requests, window)) = trimmed.split_once('/') {
        let max_requests = requests.trim().parse::<u32>().ok()?;
        if max_requests == 0 {
            return None;
        }
        let window_str = window.trim().to_ascii_lowercase();
        let window_seconds = if let Ok(n) = window_str.parse::<u64>() {
            if n == 0 {
                return None;
            }
            n
        } else {
            match window_str.as_str() {
                "s" | "sec" | "second" | "seconds" => 1,
                "m" | "min" | "minute" | "minutes" => 60,
                "h" | "hr" | "hour" | "hours" => 3600,
                "d" | "day" | "days" => 86_400,
                _ => return None,
            }
        };
        return Some(RateLimitSetting::new(max_requests, window_seconds));
    }

    let parts = trimmed.split_whitespace().collect::<Vec<_>>();
    if parts.len() != 3 || !parts[1].eq_ignore_ascii_case("per") {
        return None;
    }
    let max_requests = parts[0].parse::<u32>().ok()?;
    if max_requests == 0 {
        return None;
    }
    let window_seconds = match parts[2].to_ascii_lowercase().as_str() {
        "second" | "seconds" => 1,
        "minute" | "minutes" => 60,
        "hour" | "hours" => 3600,
        "day" | "days" => 86_400,
        _ => return None,
    };
    Some(RateLimitSetting::new(max_requests, window_seconds))
}

fn parse_rate_limit_env(key: &str, default: RateLimitSetting) -> RateLimitSetting {
    std::env::var(key)
        .ok()
        .and_then(|value| parse_rate_limit(&value))
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn parses_rate_limit_text() {
        assert_eq!(
            parse_rate_limit("200 per minute"),
            Some(RateLimitSetting::new(200, 60))
        );
        assert_eq!(
            parse_rate_limit("3 per hours"),
            Some(RateLimitSetting::new(3, 3600))
        );
        assert_eq!(
            parse_rate_limit("50000/60"),
            Some(RateLimitSetting::new(50000, 60))
        );
        assert_eq!(
            parse_rate_limit("100/minute"),
            Some(RateLimitSetting::new(100, 60))
        );
        assert_eq!(parse_rate_limit("0/60"), None);
        assert_eq!(parse_rate_limit("0 per minute"), None);
        assert_eq!(parse_rate_limit("bad"), None);
    }

    #[test]
    fn env_defaults_and_invalid_values_fall_back() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("OBJECT_KEY_MAX_LENGTH_BYTES");
        std::env::set_var("OBJECT_TAG_LIMIT", "not-a-number");
        std::env::set_var("RATE_LIMIT_DEFAULT", "invalid");

        let config = ServerConfig::from_env();

        assert_eq!(config.object_key_max_length_bytes, 1024);
        assert_eq!(config.object_tag_limit, 50);
        assert_eq!(config.ratelimit_default, RateLimitSetting::new(5000, 60));

        std::env::remove_var("OBJECT_TAG_LIMIT");
        std::env::remove_var("RATE_LIMIT_DEFAULT");
    }

    #[test]
    fn env_overrides_new_values() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("OBJECT_KEY_MAX_LENGTH_BYTES", "2048");
        std::env::set_var("GC_DRY_RUN", "true");
        std::env::set_var("RATE_LIMIT_ADMIN", "7 per second");
        std::env::set_var("HOST", "127.0.0.1");
        std::env::set_var("PORT", "5501");
        std::env::remove_var("API_BASE_URL");

        let config = ServerConfig::from_env();

        assert_eq!(config.object_key_max_length_bytes, 2048);
        assert!(config.gc_dry_run);
        assert_eq!(config.ratelimit_admin, RateLimitSetting::new(7, 1));
        assert_eq!(config.api_base_url, "http://127.0.0.1:5501");

        std::env::remove_var("OBJECT_KEY_MAX_LENGTH_BYTES");
        std::env::remove_var("GC_DRY_RUN");
        std::env::remove_var("RATE_LIMIT_ADMIN");
        std::env::remove_var("HOST");
        std::env::remove_var("PORT");
    }
}
