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
        }
    }
}
