use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::Value;

use crate::config::ServerConfig;
use crate::services::access_logging::AccessLoggingService;
use crate::services::gc::GcService;
use crate::services::integrity::IntegrityService;
use crate::services::metrics::MetricsService;
use crate::services::peer_fetch::PeerFetcher;
use crate::services::replication::ReplicationManager;
use crate::services::s3_client::ClientOptions;
use crate::services::site_registry::SiteRegistry;
use crate::services::site_sync::SiteSyncWorker;
use crate::services::system_metrics::SystemMetricsService;
use crate::services::website_domains::WebsiteDomainStore;
use crate::session::SessionStore;
use crate::stores::connections::ConnectionStore;
use crate::templates::TemplateEngine;
use myfsio_auth::iam::IamService;
use myfsio_crypto::encryption::{EncryptionConfig, EncryptionService};
use myfsio_crypto::kms::KmsService;
use myfsio_storage::fs_backend::{FsStorageBackend, FsStorageBackendConfig};

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
    pub cluster_overview_cache: Arc<Mutex<Option<(Instant, Value)>>>,
    pub cluster_aggregate_cache: Arc<Mutex<Option<(Instant, Value)>>>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Self {
        let storage = Arc::new(FsStorageBackend::new_with_config(
            config.storage_root.clone(),
            FsStorageBackendConfig {
                object_key_max_length_bytes: config.object_key_max_length_bytes,
                object_cache_max_size: config.object_cache_max_size,
                bucket_config_cache_ttl: Duration::from_secs_f64(
                    config.bucket_config_cache_ttl_seconds,
                ),
                stream_chunk_size: config.stream_chunk_size,
            },
        ));
        let iam = Arc::new(IamService::new_with_secret(
            config.iam_config_path.clone(),
            config.secret_key.clone(),
        ));

        let gc = if config.gc_enabled {
            Some(Arc::new(GcService::new(
                config.storage_root.clone(),
                crate::services::gc::GcConfig {
                    interval_hours: config.gc_interval_hours,
                    temp_file_max_age_hours: config.gc_temp_file_max_age_hours,
                    multipart_max_age_days: config.gc_multipart_max_age_days,
                    lock_file_max_age_hours: config.gc_lock_file_max_age_hours,
                    quarantine_max_age_days: config.integrity_quarantine_retention_days,
                    dry_run: config.gc_dry_run,
                },
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

        let site_registry = {
            let registry = SiteRegistry::new(&config.storage_root);
            if let (Some(site_id), Some(endpoint)) =
                (config.site_id.as_deref(), config.site_endpoint.as_deref())
            {
                registry.set_local_site(crate::services::site_registry::SiteInfo {
                    site_id: site_id.to_string(),
                    endpoint: endpoint.to_string(),
                    region: config.site_region.clone(),
                    priority: config.site_priority,
                    display_name: site_id.to_string(),
                    created_at: Some(chrono::Utc::now().to_rfc3339()),
                });
            }
            Some(Arc::new(registry))
        };

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

        let integrity_peer_fetcher: Option<Arc<PeerFetcher>> = if let Some(ref ss) = site_sync {
            Some(ss.peer_fetcher())
        } else {
            Some(Arc::new(PeerFetcher::new(
                storage.clone(),
                connections.clone(),
                replication.clone(),
                ClientOptions {
                    connect_timeout: Duration::from_secs(config.site_sync_connect_timeout_secs),
                    read_timeout: Duration::from_secs(config.site_sync_read_timeout_secs),
                    max_attempts: config.site_sync_max_retries,
                },
            )))
        };

        let integrity = if config.integrity_enabled {
            Some(Arc::new(IntegrityService::new(
                storage.clone(),
                &config.storage_root,
                crate::services::integrity::IntegrityConfig {
                    interval_hours: config.integrity_interval_hours,
                    batch_size: config.integrity_batch_size,
                    auto_heal: config.integrity_auto_heal,
                    dry_run: config.integrity_dry_run,
                    heal_concurrency: config.integrity_heal_concurrency,
                    quarantine_retention_days: config.integrity_quarantine_retention_days,
                },
                integrity_peer_fetcher,
            )))
        } else {
            None
        };

        let templates = init_templates(&config.templates_dir);
        let access_logging = Arc::new(AccessLoggingService::new(&config.storage_root));
        let session_ttl = Duration::from_secs(config.session_lifetime_days.saturating_mul(86_400));
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
            sessions: Arc::new(SessionStore::new(session_ttl)),
            access_logging,
            cluster_overview_cache: Arc::new(Mutex::new(None)),
            cluster_aggregate_cache: Arc::new(Mutex::new(None)),
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
                Ok(master_key) => Some(Arc::new(EncryptionService::with_config(
                    master_key,
                    kms.clone(),
                    EncryptionConfig {
                        chunk_size: config.encryption_chunk_size_bytes,
                    },
                ))),
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
    let use_disk = std::env::var("TEMPLATES_DIR").is_ok() && templates_dir.is_dir();
    let result = if use_disk {
        let glob = format!("{}/*.html", templates_dir.display()).replace('\\', "/");
        tracing::info!("Loading templates from disk: {}", templates_dir.display());
        TemplateEngine::new(&glob)
    } else {
        tracing::info!("Loading templates from embedded assets");
        TemplateEngine::from_embedded()
    };
    match result {
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
