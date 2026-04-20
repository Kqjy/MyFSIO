use std::sync::Arc;
use std::time::Duration;

use crate::config::ServerConfig;
use crate::services::access_logging::AccessLoggingService;
use crate::services::gc::GcService;
use crate::services::integrity::IntegrityService;
use crate::services::metrics::MetricsService;
use crate::services::replication::ReplicationManager;
use crate::services::site_registry::SiteRegistry;
use crate::services::site_sync::SiteSyncWorker;
use crate::services::system_metrics::SystemMetricsService;
use crate::services::website_domains::WebsiteDomainStore;
use crate::session::SessionStore;
use crate::stores::connections::ConnectionStore;
use crate::templates::TemplateEngine;
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
    pub system_metrics: Option<Arc<SystemMetricsService>>,
    pub site_registry: Option<Arc<SiteRegistry>>,
    pub website_domains: Option<Arc<WebsiteDomainStore>>,
    pub connections: Arc<ConnectionStore>,
    pub replication: Arc<ReplicationManager>,
    pub site_sync: Option<Arc<SiteSyncWorker>>,
    pub templates: Option<Arc<TemplateEngine>>,
    pub sessions: Arc<SessionStore>,
    pub access_logging: Arc<AccessLoggingService>,
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
                crate::services::metrics::MetricsConfig {
                    interval_minutes: config.metrics_interval_minutes,
                    retention_hours: config.metrics_retention_hours,
                },
            )))
        } else {
            None
        };

        let system_metrics = if config.metrics_history_enabled {
            Some(Arc::new(SystemMetricsService::new(
                &config.storage_root,
                storage.clone(),
                crate::services::system_metrics::SystemMetricsConfig {
                    interval_minutes: config.metrics_history_interval_minutes,
                    retention_hours: config.metrics_history_retention_hours,
                },
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

        let connections = Arc::new(ConnectionStore::new(&config.storage_root));

        let replication = Arc::new(ReplicationManager::new(
            storage.clone(),
            connections.clone(),
            &config.storage_root,
            Duration::from_secs(config.replication_connect_timeout_secs),
            Duration::from_secs(config.replication_read_timeout_secs),
            config.replication_max_retries,
            config.replication_streaming_threshold_bytes,
            config.replication_max_failures_per_bucket,
        ));

        let site_sync = if config.site_sync_enabled {
            Some(Arc::new(SiteSyncWorker::new(
                storage.clone(),
                connections.clone(),
                replication.clone(),
                config.storage_root.clone(),
                config.site_sync_interval_secs,
                config.site_sync_batch_size,
                Duration::from_secs(config.site_sync_connect_timeout_secs),
                Duration::from_secs(config.site_sync_read_timeout_secs),
                config.site_sync_max_retries,
                config.site_sync_clock_skew_tolerance,
            )))
        } else {
            None
        };

        let templates = init_templates(&config.templates_dir);
        let access_logging = Arc::new(AccessLoggingService::new(&config.storage_root));
        Self {
            config,
            storage,
            iam,
            encryption: None,
            kms: None,
            gc,
            integrity,
            metrics,
            system_metrics,
            site_registry,
            website_domains,
            connections,
            replication,
            site_sync,
            templates,
            sessions: Arc::new(SessionStore::new(Duration::from_secs(60 * 60 * 12))),
            access_logging,
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
                Ok(master_key) => Some(Arc::new(EncryptionService::new(master_key, kms.clone()))),
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

fn init_templates(templates_dir: &std::path::Path) -> Option<Arc<TemplateEngine>> {
    let glob = format!("{}/*.html", templates_dir.display()).replace('\\', "/");
    match TemplateEngine::new(&glob) {
        Ok(engine) => {
            crate::handlers::ui_pages::register_ui_endpoints(&engine);
            Some(Arc::new(engine))
        }
        Err(e) => {
            tracing::error!("Template engine init failed: {}", e);
            None
        }
    }
}
