use std::sync::Arc;

use crate::config::ServerConfig;
use crate::services::gc::GcService;
use crate::services::integrity::IntegrityService;
use crate::services::metrics::MetricsService;
use crate::services::site_registry::SiteRegistry;
use crate::services::website_domains::WebsiteDomainStore;
use myfsio_auth::iam::IamService;
use myfsio_crypto::encryption::EncryptionService;
use myfsio_crypto::kms::KmsService;
use myfsio_storage::fs_backend::FsStorageBackend;

#[derive(Clone)]
pub struct AppState {
    pub config: ServerConfig,
    pub storage: Arc<FsStorageBackend>,
    pub iam: Arc<IamService>,
    pub encryption: Option<Arc<EncryptionService>>,
    pub kms: Option<Arc<KmsService>>,
    pub gc: Option<Arc<GcService>>,
    pub integrity: Option<Arc<IntegrityService>>,
    pub metrics: Option<Arc<MetricsService>>,
    pub site_registry: Option<Arc<SiteRegistry>>,
    pub website_domains: Option<Arc<WebsiteDomainStore>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        let storage = Arc::new(FsStorageBackend::new(config.storage_root.clone()));
        let iam = Arc::new(IamService::new_with_secret(
            config.iam_config_path.clone(),
            config.secret_key.clone(),
        ));

        let gc = if config.gc_enabled {
            Some(Arc::new(GcService::new(
                config.storage_root.clone(),
                crate::services::gc::GcConfig::default(),
            )))
        } else {
            None
        };

        let integrity = if config.integrity_enabled {
            Some(Arc::new(IntegrityService::new(
                storage.clone(),
                &config.storage_root,
                crate::services::integrity::IntegrityConfig::default(),
            )))
        } else {
            None
        };

        let metrics = if config.metrics_enabled {
            Some(Arc::new(MetricsService::new(
                &config.storage_root,
                crate::services::metrics::MetricsConfig::default(),
            )))
        } else {
            None
        };

        let site_registry = Some(Arc::new(SiteRegistry::new(&config.storage_root)));

        let website_domains = if config.website_hosting_enabled {
            Some(Arc::new(WebsiteDomainStore::new(&config.storage_root)))
        } else {
            None
        };

        Self {
            config,
            storage,
            iam,
            encryption: None,
            kms: None,
            gc,
            integrity,
            metrics,
            site_registry,
            website_domains,
        }
    }

    pub async fn new_with_encryption(config: ServerConfig) -> Self {
        let mut state = Self::new(config.clone());

        let keys_dir = config.storage_root.join(".myfsio.sys").join("keys");

        let kms = if config.kms_enabled {
            match KmsService::new(&keys_dir).await {
                Ok(k) => Some(Arc::new(k)),
                Err(e) => {
                    tracing::error!("Failed to initialize KMS: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let encryption = if config.encryption_enabled {
            match myfsio_crypto::kms::load_or_create_master_key(&keys_dir).await {
                Ok(master_key) => {
                    Some(Arc::new(EncryptionService::new(master_key, kms.clone())))
                }
                Err(e) => {
                    tracing::error!("Failed to initialize encryption: {}", e);
                    None
                }
            }
        } else {
            None
        };

        state.encryption = encryption;
        state.kms = kms;
        state
    }
}
