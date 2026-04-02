use myfsio_server::config::ServerConfig;
use myfsio_server::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = ServerConfig::from_env();
    let bind_addr = config.bind_addr;

    tracing::info!("MyFSIO Rust Engine starting on {}", bind_addr);
    tracing::info!("Storage root: {}", config.storage_root.display());
    tracing::info!("Region: {}", config.region);
    tracing::info!(
        "Encryption: {}, KMS: {}, GC: {}, Lifecycle: {}, Integrity: {}, Metrics: {}",
        config.encryption_enabled,
        config.kms_enabled,
        config.gc_enabled,
        config.lifecycle_enabled,
        config.integrity_enabled,
        config.metrics_enabled
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

    if config.lifecycle_enabled {
        let lifecycle = std::sync::Arc::new(
            myfsio_server::services::lifecycle::LifecycleService::new(
                state.storage.clone(),
                myfsio_server::services::lifecycle::LifecycleConfig::default(),
            ),
        );
        bg_handles.push(lifecycle.start_background());
        tracing::info!("Lifecycle manager background service started");
    }

    let app = myfsio_server::create_router(state);

    let listener = match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!("Port already in use: {}", bind_addr);
            } else {
                tracing::error!("Failed to bind {}: {}", bind_addr, err);
            }
            for handle in bg_handles {
                handle.abort();
            }
            std::process::exit(1);
        }
    };
    tracing::info!("Listening on {}", bind_addr);

    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        tracing::error!("Server exited with error: {}", err);
        for handle in bg_handles {
            handle.abort();
        }
        std::process::exit(1);
    }

    for handle in bg_handles {
        handle.abort();
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for Ctrl+C");
    tracing::info!("Shutdown signal received");
}
