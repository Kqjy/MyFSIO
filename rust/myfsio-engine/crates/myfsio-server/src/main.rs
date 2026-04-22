use clap::{Parser, Subcommand};
use myfsio_server::config::ServerConfig;
use myfsio_server::state::AppState;

#[derive(Parser)]
#[command(
    name = "myfsio",
    version,
    about = "MyFSIO S3-compatible storage engine"
)]
struct Cli {
    #[arg(long, help = "Validate configuration and exit")]
    check_config: bool,
    #[arg(long, help = "Show configuration summary and exit")]
    show_config: bool,
    #[arg(long, help = "Reset admin credentials and exit")]
    reset_cred: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Version,
}

#[tokio::main]
async fn main() {
    load_env_files();
    init_tracing();

    let cli = Cli::parse();
    let config = ServerConfig::from_env();
    if !config
        .ratelimit_storage_uri
        .eq_ignore_ascii_case("memory://")
    {
        tracing::warn!(
            "RATE_LIMIT_STORAGE_URI={} is not supported yet; using in-memory rate limits",
            config.ratelimit_storage_uri
        );
    }

    if cli.reset_cred {
        reset_admin_credentials(&config);
        return;
    }
    if cli.check_config || cli.show_config {
        print_config_summary(&config);
        if cli.check_config {
            let issues = validate_config(&config);
            for issue in &issues {
                println!("{issue}");
            }
            if issues.iter().any(|issue| issue.starts_with("CRITICAL:")) {
                std::process::exit(1);
            }
        }
        return;
    }

    match cli.command.unwrap_or(Command::Serve) {
        Command::Version => {
            println!("myfsio {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Command::Serve => {}
    }

    ensure_iam_bootstrap(&config);
    let bind_addr = config.bind_addr;
    let ui_bind_addr = config.ui_bind_addr;

    tracing::info!("MyFSIO Rust Engine starting — API on {}", bind_addr);
    if config.ui_enabled {
        tracing::info!("UI will bind on {}", ui_bind_addr);
    }
    tracing::info!("Storage root: {}", config.storage_root.display());
    tracing::info!("Region: {}", config.region);
    tracing::info!(
        "Encryption: {}, KMS: {}, GC: {}, Lifecycle: {}, Integrity: {}, Metrics History: {}, Operation Metrics: {}, UI: {}",
        config.encryption_enabled,
        config.kms_enabled,
        config.gc_enabled,
        config.lifecycle_enabled,
        config.integrity_enabled,
        config.metrics_history_enabled,
        config.metrics_enabled,
        config.ui_enabled
    );

    let state = if config.encryption_enabled || config.kms_enabled {
        AppState::new_with_encryption(config.clone()).await
    } else {
        AppState::new(config.clone())
    };

    let mut bg_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    if let Some(ref gc) = state.gc {
        bg_handles.push(gc.clone().start_background());
        tracing::info!("GC background service started");
    }

    if let Some(ref integrity) = state.integrity {
        bg_handles.push(integrity.clone().start_background());
        tracing::info!("Integrity checker background service started");
    }

    if let Some(ref metrics) = state.metrics {
        bg_handles.push(metrics.clone().start_background());
        tracing::info!("Metrics collector background service started");
    }

    if let Some(ref system_metrics) = state.system_metrics {
        bg_handles.push(system_metrics.clone().start_background());
        tracing::info!("System metrics history collector started");
    }

    if config.lifecycle_enabled {
        let lifecycle =
            std::sync::Arc::new(myfsio_server::services::lifecycle::LifecycleService::new(
                state.storage.clone(),
                config.storage_root.clone(),
                myfsio_server::services::lifecycle::LifecycleConfig {
                    interval_seconds: 3600,
                    max_history_per_bucket: config.lifecycle_max_history_per_bucket,
                },
            ));
        bg_handles.push(lifecycle.start_background());
        tracing::info!("Lifecycle manager background service started");
    }

    if let Some(ref site_sync) = state.site_sync {
        let worker = site_sync.clone();
        bg_handles.push(tokio::spawn(async move {
            worker.run().await;
        }));
        tracing::info!("Site sync worker started");
    }

    let ui_enabled = config.ui_enabled;
    let api_app = myfsio_server::create_router(state.clone());
    let ui_app = if ui_enabled {
        Some(myfsio_server::create_ui_router(state.clone()))
    } else {
        None
    };

    let api_listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!("API port already in use: {}", bind_addr);
            } else {
                tracing::error!("Failed to bind API {}: {}", bind_addr, err);
            }
            for handle in bg_handles {
                handle.abort();
            }
            std::process::exit(1);
        }
    };
    tracing::info!("API listening on {}", bind_addr);

    let ui_listener = if let Some(ref app) = ui_app {
        let _ = app;
        match tokio::net::TcpListener::bind(ui_bind_addr).await {
            Ok(listener) => {
                tracing::info!("UI listening on {}", ui_bind_addr);
                Some(listener)
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::AddrInUse {
                    tracing::error!("UI port already in use: {}", ui_bind_addr);
                } else {
                    tracing::error!("Failed to bind UI {}: {}", ui_bind_addr, err);
                }
                for handle in bg_handles {
                    handle.abort();
                }
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let shutdown = shutdown_signal_shared();
    let api_shutdown = shutdown.clone();
    let api_task = tokio::spawn(async move {
        axum::serve(
            api_listener,
            api_app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            api_shutdown.notified().await;
        })
        .await
    });

    let ui_task = if let (Some(listener), Some(app)) = (ui_listener, ui_app) {
        let ui_shutdown = shutdown.clone();
        Some(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    ui_shutdown.notified().await;
                })
                .await
        }))
    } else {
        None
    };

    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");
    tracing::info!("Shutdown signal received");
    shutdown.notify_waiters();

    if let Err(err) = api_task.await.unwrap_or(Ok(())) {
        tracing::error!("API server exited with error: {}", err);
    }
    if let Some(task) = ui_task {
        if let Err(err) = task.await.unwrap_or(Ok(())) {
            tracing::error!("UI server exited with error: {}", err);
        }
    }

    for handle in bg_handles {
        handle.abort();
    }
}

fn print_config_summary(config: &ServerConfig) {
    println!("MyFSIO Rust Configuration");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!("API bind: {}", config.bind_addr);
    println!("UI bind: {}", config.ui_bind_addr);
    println!("UI enabled: {}", config.ui_enabled);
    println!("Storage root: {}", config.storage_root.display());
    println!("IAM config: {}", config.iam_config_path.display());
    println!("Region: {}", config.region);
    println!("Encryption enabled: {}", config.encryption_enabled);
    println!(
        "Encryption chunk size: {} bytes",
        config.encryption_chunk_size_bytes
    );
    println!("KMS enabled: {}", config.kms_enabled);
    println!(
        "KMS data key bounds: {}-{} bytes",
        config.kms_generate_data_key_min_bytes, config.kms_generate_data_key_max_bytes
    );
    println!("GC enabled: {}", config.gc_enabled);
    println!(
        "GC interval: {} hours, dry run: {}",
        config.gc_interval_hours, config.gc_dry_run
    );
    println!("Integrity enabled: {}", config.integrity_enabled);
    println!("Lifecycle enabled: {}", config.lifecycle_enabled);
    println!(
        "Lifecycle history limit: {}",
        config.lifecycle_max_history_per_bucket
    );
    println!(
        "Website hosting enabled: {}",
        config.website_hosting_enabled
    );
    println!("Site sync enabled: {}", config.site_sync_enabled);
    println!("API base URL: {}", config.api_base_url);
    println!(
        "Object key max: {} bytes, tag limit: {}",
        config.object_key_max_length_bytes, config.object_tag_limit
    );
    println!(
        "Rate limits: default {} per {}s, admin {} per {}s",
        config.ratelimit_default.max_requests,
        config.ratelimit_default.window_seconds,
        config.ratelimit_admin.max_requests,
        config.ratelimit_admin.window_seconds
    );
    println!(
        "Metrics history enabled: {}",
        config.metrics_history_enabled
    );
    println!("Operation metrics enabled: {}", config.metrics_enabled);
}

fn validate_config(config: &ServerConfig) -> Vec<String> {
    let mut issues = Vec::new();

    if config.ui_enabled && config.bind_addr == config.ui_bind_addr {
        issues.push(
            "CRITICAL: API and UI bind addresses cannot be identical when UI is enabled."
                .to_string(),
        );
    }
    if config.presigned_url_min_expiry > config.presigned_url_max_expiry {
        issues.push("CRITICAL: PRESIGNED_URL_MIN_EXPIRY_SECONDS cannot exceed PRESIGNED_URL_MAX_EXPIRY_SECONDS.".to_string());
    }
    if config.encryption_chunk_size_bytes == 0 {
        issues.push("CRITICAL: ENCRYPTION_CHUNK_SIZE_BYTES must be greater than zero.".to_string());
    }
    if config.kms_generate_data_key_min_bytes == 0 {
        issues.push(
            "CRITICAL: KMS_GENERATE_DATA_KEY_MIN_BYTES must be greater than zero.".to_string(),
        );
    }
    if config.kms_generate_data_key_min_bytes > config.kms_generate_data_key_max_bytes {
        issues.push("CRITICAL: KMS_GENERATE_DATA_KEY_MIN_BYTES cannot exceed KMS_GENERATE_DATA_KEY_MAX_BYTES.".to_string());
    }
    if config.gc_interval_hours <= 0.0 {
        issues.push("CRITICAL: GC_INTERVAL_HOURS must be greater than zero.".to_string());
    }
    if config.bucket_config_cache_ttl_seconds < 0.0 {
        issues.push("CRITICAL: BUCKET_CONFIG_CACHE_TTL_SECONDS cannot be negative.".to_string());
    }
    if !config
        .ratelimit_storage_uri
        .eq_ignore_ascii_case("memory://")
    {
        issues.push(format!(
            "WARNING: RATE_LIMIT_STORAGE_URI={} is not supported yet; using in-memory limits.",
            config.ratelimit_storage_uri
        ));
    }
    if let Err(err) = std::fs::create_dir_all(&config.storage_root) {
        issues.push(format!(
            "CRITICAL: Cannot create storage root {}: {}",
            config.storage_root.display(),
            err
        ));
    }
    if let Some(parent) = config.iam_config_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            issues.push(format!(
                "CRITICAL: Cannot create IAM config directory {}: {}",
                parent.display(),
                err
            ));
        }
    }
    if config.encryption_enabled && config.secret_key.is_none() {
        issues.push(
            "WARNING: ENCRYPTION_ENABLED=true but SECRET_KEY is not configured; secure-at-rest config encryption is unavailable.".to_string(),
        );
    }
    if config.site_sync_enabled && !config.website_hosting_enabled {
        issues.push(
            "INFO: SITE_SYNC_ENABLED=true without WEBSITE_HOSTING_ENABLED; this is valid but unrelated.".to_string(),
        );
    }

    issues
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_env("RUST_LOG")
        .or_else(|_| {
            EnvFilter::try_new(std::env::var("LOG_LEVEL").unwrap_or_else(|_| "INFO".to_string()))
        })
        .unwrap_or_else(|_| EnvFilter::new("INFO"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn shutdown_signal_shared() -> std::sync::Arc<tokio::sync::Notify> {
    std::sync::Arc::new(tokio::sync::Notify::new())
}

fn load_env_files() {
    let cwd = std::env::current_dir().ok();
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    candidates.push(std::path::PathBuf::from("/opt/myfsio/myfsio.env"));
    if let Some(ref dir) = cwd {
        candidates.push(dir.join(".env"));
        candidates.push(dir.join("myfsio.env"));
        for ancestor in dir.ancestors().skip(1).take(4) {
            candidates.push(ancestor.join(".env"));
            candidates.push(ancestor.join("myfsio.env"));
        }
    }

    let mut seen = std::collections::HashSet::new();
    for path in candidates {
        if !seen.insert(path.clone()) {
            continue;
        }
        if path.is_file() {
            match dotenvy::from_path_override(&path) {
                Ok(()) => eprintln!("Loaded env file: {}", path.display()),
                Err(e) => eprintln!("Failed to load env file {}: {}", path.display(), e),
            }
        }
    }
}

fn ensure_iam_bootstrap(config: &ServerConfig) {
    let iam_path = &config.iam_config_path;
    if iam_path.exists() {
        return;
    }

    let access_key = std::env::var("ADMIN_ACCESS_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("AK{}", uuid::Uuid::new_v4().simple()));
    let secret_key = std::env::var("ADMIN_SECRET_KEY")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("SK{}", uuid::Uuid::new_v4().simple()));

    let user_id = format!("u-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
    let created_at = chrono::Utc::now().to_rfc3339();

    let body = serde_json::json!({
        "version": 2,
        "users": [{
            "user_id": user_id,
            "display_name": "Local Admin",
            "enabled": true,
            "access_keys": [{
                "access_key": access_key,
                "secret_key": secret_key,
                "status": "active",
                "created_at": created_at,
            }],
            "policies": [{
                "bucket": "*",
                "actions": ["*"],
                "prefix": "*",
            }]
        }]
    });

    let json = match serde_json::to_string_pretty(&body) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to serialize IAM bootstrap config: {}", e);
            return;
        }
    };

    if let Some(parent) = iam_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::error!(
                "Failed to create IAM config dir {}: {}",
                parent.display(),
                e
            );
            return;
        }
    }

    if let Err(e) = std::fs::write(iam_path, json) {
        tracing::error!(
            "Failed to write IAM bootstrap config {}: {}",
            iam_path.display(),
            e
        );
        return;
    }

    tracing::info!("============================================================");
    tracing::info!("MYFSIO - ADMIN CREDENTIALS INITIALIZED");
    tracing::info!("============================================================");
    tracing::info!("Access Key: {}", access_key);
    tracing::info!("Secret Key: {}", secret_key);
    tracing::info!("Saved to: {}", iam_path.display());
    tracing::info!("============================================================");
}

fn reset_admin_credentials(config: &ServerConfig) {
    if let Some(parent) = config.iam_config_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            eprintln!(
                "Failed to create IAM config directory {}: {}",
                parent.display(),
                err
            );
            std::process::exit(1);
        }
    }

    if config.iam_config_path.exists() {
        let backup = config
            .iam_config_path
            .with_extension(format!("bak-{}", chrono::Utc::now().timestamp()));
        if let Err(err) = std::fs::rename(&config.iam_config_path, &backup) {
            eprintln!(
                "Failed to back up existing IAM config {}: {}",
                config.iam_config_path.display(),
                err
            );
            std::process::exit(1);
        }
        println!("Backed up existing IAM config to {}", backup.display());
        prune_iam_backups(&config.iam_config_path, 5);
    }

    ensure_iam_bootstrap(config);
    println!("Admin credentials reset.");
}

fn prune_iam_backups(iam_path: &std::path::Path, keep: usize) {
    let parent = match iam_path.parent() {
        Some(p) => p,
        None => return,
    };
    let stem = match iam_path.file_stem().and_then(|s| s.to_str()) {
        Some(s) => s,
        None => return,
    };
    let prefix = format!("{}.bak-", stem);

    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let mut backups: Vec<(i64, std::path::PathBuf)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let path = e.path();
            let name = path.file_name()?.to_str()?;
            let rest = name.strip_prefix(&prefix)?;
            let ts: i64 = rest.parse().ok()?;
            Some((ts, path))
        })
        .collect();
    backups.sort_by(|a, b| b.0.cmp(&a.0));

    for (_, path) in backups.into_iter().skip(keep) {
        if let Err(err) = std::fs::remove_file(&path) {
            eprintln!(
                "Failed to remove old IAM backup {}: {}",
                path.display(),
                err
            );
        } else {
            println!("Pruned old IAM backup {}", path.display());
        }
    }
}
