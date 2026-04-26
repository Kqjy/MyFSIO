pub mod config;
pub mod handlers;
pub mod middleware;
pub mod services;
pub mod session;
pub mod state;
pub mod stores;
pub mod templates;

use axum::Router;

pub const SERVER_HEADER: &str = concat!("MyFSIO-Rust/", env!("CARGO_PKG_VERSION"));

pub fn create_ui_router(state: state::AppState) -> Router {
    use axum::routing::{delete, get, post, put};
    use handlers::ui;
    use handlers::ui_api;
    use handlers::ui_pages;

    let protected = Router::new()
        .route("/", get(ui::root_redirect))
        .route("/ui", get(ui::root_redirect))
        .route("/ui/", get(ui::root_redirect))
        .route(
            "/ui/buckets",
            get(ui_pages::buckets_overview).post(ui_pages::create_bucket),
        )
        .route("/ui/buckets/create", post(ui_pages::create_bucket))
        .route("/ui/buckets/{bucket_name}", get(ui_pages::bucket_detail))
        .route(
            "/ui/buckets/{bucket_name}/delete",
            post(ui_pages::delete_bucket),
        )
        .route(
            "/ui/buckets/{bucket_name}/versioning",
            post(ui_pages::update_bucket_versioning),
        )
        .route(
            "/ui/buckets/{bucket_name}/quota",
            post(ui_pages::update_bucket_quota),
        )
        .route(
            "/ui/buckets/{bucket_name}/encryption",
            post(ui_pages::update_bucket_encryption),
        )
        .route(
            "/ui/buckets/{bucket_name}/policy",
            post(ui_pages::update_bucket_policy),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication",
            post(ui_pages::update_bucket_replication),
        )
        .route(
            "/ui/buckets/{bucket_name}/website",
            post(ui_pages::update_bucket_website),
        )
        .route(
            "/ui/buckets/{bucket_name}/upload",
            post(ui_api::upload_object),
        )
        .route(
            "/ui/buckets/{bucket_name}/multipart/initiate",
            post(ui_api::initiate_multipart_upload),
        )
        .route(
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/part",
            put(ui_api::upload_multipart_part),
        )
        .route(
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/parts",
            put(ui_api::upload_multipart_part),
        )
        .route(
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/complete",
            post(ui_api::complete_multipart_upload),
        )
        .route(
            "/ui/buckets/{bucket_name}/multipart/{upload_id}/abort",
            delete(ui_api::abort_multipart_upload),
        )
        .route(
            "/ui/buckets/{bucket_name}/multipart/{upload_id}",
            delete(ui_api::abort_multipart_upload),
        )
        .route(
            "/ui/buckets/{bucket_name}/objects",
            get(ui_api::list_bucket_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/objects/stream",
            get(ui_api::stream_bucket_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/objects/search",
            get(ui_api::search_bucket_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/stats",
            get(ui_api::bucket_stats_json),
        )
        .route(
            "/ui/buckets/{bucket_name}/folders",
            get(ui_api::list_bucket_folders),
        )
        .route(
            "/ui/buckets/{bucket_name}/copy-targets",
            get(ui_api::list_copy_targets),
        )
        .route(
            "/ui/buckets/{bucket_name}/list-for-copy",
            get(ui_api::list_copy_targets),
        )
        .route(
            "/ui/buckets/{bucket_name}/objects/bulk-delete",
            post(ui_api::bulk_delete_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/objects/bulk-download",
            post(ui_api::bulk_download_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/objects/{*rest}",
            get(ui_api::object_get_dispatch).post(ui_api::object_post_dispatch),
        )
        .route(
            "/ui/buckets/{bucket_name}/acl",
            get(ui_api::bucket_acl).post(ui_api::update_bucket_acl),
        )
        .route(
            "/ui/buckets/{bucket_name}/cors",
            get(ui_api::bucket_cors).post(ui_api::update_bucket_cors),
        )
        .route(
            "/ui/buckets/{bucket_name}/lifecycle",
            get(ui_api::bucket_lifecycle).post(ui_api::update_bucket_lifecycle),
        )
        .route(
            "/ui/buckets/{bucket_name}/lifecycle/history",
            get(ui_api::lifecycle_history),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/status",
            get(ui_api::replication_status),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/failures",
            get(ui_api::replication_failures).delete(ui_api::clear_replication_failures),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/failures/retry",
            post(ui_api::retry_replication_failure),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/failures/retry-all",
            post(ui_api::retry_all_replication_failures),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/failures/dismiss",
            delete(ui_api::dismiss_replication_failure),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/failures/clear",
            delete(ui_api::clear_replication_failures),
        )
        .route(
            "/ui/buckets/{bucket_name}/replication/failures/{*rest}",
            post(ui_api::retry_replication_failure_path)
                .delete(ui_api::dismiss_replication_failure_path),
        )
        .route(
            "/ui/buckets/{bucket_name}/bulk-delete",
            post(ui_api::bulk_delete_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/bulk-download",
            post(ui_api::bulk_download_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/archived",
            get(ui_api::archived_objects),
        )
        .route(
            "/ui/buckets/{bucket_name}/archived/{*rest}",
            post(ui_api::archived_post_dispatch),
        )
        .route("/ui/iam", get(ui_pages::iam_dashboard))
        .route("/ui/iam/users", post(ui_pages::create_iam_user))
        .route("/ui/iam/users/{user_id}", post(ui_pages::update_iam_user))
        .route(
            "/ui/iam/users/{user_id}/delete",
            post(ui_pages::delete_iam_user),
        )
        .route(
            "/ui/iam/users/{user_id}/update",
            post(ui_pages::update_iam_user),
        )
        .route(
            "/ui/iam/users/{user_id}/policies",
            post(ui_pages::update_iam_policies),
        )
        .route(
            "/ui/iam/users/{user_id}/expiry",
            post(ui_pages::update_iam_expiry),
        )
        .route(
            "/ui/iam/users/{user_id}/rotate-secret",
            post(ui_pages::rotate_iam_secret),
        )
        .route(
            "/ui/iam/users/{user_id}/rotate",
            post(ui_pages::rotate_iam_secret),
        )
        .route("/ui/connections/create", post(ui_pages::create_connection))
        .route("/ui/connections/test", post(ui_api::test_connection))
        .route(
            "/ui/connections/{connection_id}",
            post(ui_pages::update_connection),
        )
        .route(
            "/ui/connections/{connection_id}/update",
            post(ui_pages::update_connection),
        )
        .route(
            "/ui/connections/{connection_id}/delete",
            post(ui_pages::delete_connection),
        )
        .route(
            "/ui/connections/{connection_id}/health",
            get(ui_api::connection_health),
        )
        .route("/ui/sites", get(ui_pages::sites_dashboard))
        .route("/ui/cluster", get(ui_pages::cluster_dashboard))
        .route("/ui/cluster/data", get(ui_pages::cluster_data_json))
        .route("/ui/sites/local", post(ui_pages::update_local_site))
        .route("/ui/sites/peers", post(ui_pages::add_peer_site))
        .route(
            "/ui/sites/peers/{site_id}/update",
            post(ui_pages::update_peer_site),
        )
        .route(
            "/ui/sites/peers/{site_id}/delete",
            post(ui_pages::delete_peer_site),
        )
        .route("/ui/sites/peers/{site_id}/health", get(ui_api::peer_health))
        .route(
            "/ui/sites/peers/{site_id}/sync-stats",
            get(ui_api::peer_sync_stats),
        )
        .route(
            "/ui/sites/peers/{site_id}/bidirectional-status",
            get(ui_api::peer_bidirectional_status),
        )
        .route(
            "/ui/connections",
            get(ui_pages::connections_dashboard).post(ui_pages::create_connection),
        )
        .route("/ui/metrics", get(ui_pages::metrics_dashboard))
        .route(
            "/ui/metrics/settings",
            get(ui_api::metrics_settings).put(ui_api::update_metrics_settings),
        )
        .route("/ui/metrics/api", get(ui_api::metrics_api))
        .route("/ui/metrics/history", get(ui_api::metrics_history))
        .route("/ui/metrics/operations", get(ui_api::metrics_operations))
        .route(
            "/ui/metrics/operations/history",
            get(ui_api::metrics_operations_history),
        )
        .route("/ui/system", get(ui_pages::system_dashboard))
        .route("/ui/system/gc/status", get(ui_api::gc_status_ui))
        .route("/ui/system/gc/run", post(ui_api::gc_run_ui))
        .route("/ui/system/gc/history", get(ui_api::gc_history_ui))
        .route(
            "/ui/system/integrity/status",
            get(ui_api::integrity_status_ui),
        )
        .route("/ui/system/integrity/run", post(ui_api::integrity_run_ui))
        .route(
            "/ui/system/integrity/history",
            get(ui_api::integrity_history_ui),
        )
        .route(
            "/ui/website-domains",
            get(ui_pages::website_domains_dashboard),
        )
        .route(
            "/ui/website-domains/create",
            post(ui_pages::create_website_domain),
        )
        .route(
            "/ui/website-domains/{domain}",
            post(ui_pages::update_website_domain),
        )
        .route(
            "/ui/website-domains/{domain}/update",
            post(ui_pages::update_website_domain),
        )
        .route(
            "/ui/website-domains/{domain}/delete",
            post(ui_pages::delete_website_domain),
        )
        .route("/ui/replication/new", get(ui_pages::replication_wizard))
        .route(
            "/ui/replication/create",
            post(ui_pages::create_peer_replication_rules_from_query),
        )
        .route(
            "/ui/sites/peers/{site_id}/replication-rules",
            post(ui_pages::create_peer_replication_rules),
        )
        .route("/ui/docs", get(ui_pages::docs_page))
        .layer(axum::middleware::from_fn(ui::require_login));

    let public = Router::new()
        .route("/login", get(ui::login_page).post(ui::login_submit))
        .route("/logout", post(ui::logout).get(ui::logout));

    let session_state = middleware::SessionLayerState {
        store: state.sessions.clone(),
        secure: false,
    };

    let static_service = tower::ServiceBuilder::new()
        .layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache"),
        ))
        .service(tower_http::services::ServeDir::new(
            &state.config.static_dir,
        ));

    protected
        .merge(public)
        .fallback(ui::not_found_page)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::csrf_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            session_state,
            middleware::session_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::ui_metrics_layer,
        ))
        .with_state(state)
        .nest_service("/static", static_service)
        .layer(axum::middleware::from_fn(middleware::server_header))
        .layer(tower_http::compression::CompressionLayer::new())
}

pub fn create_router(state: state::AppState) -> Router {
    let default_rate_limit = middleware::RateLimitLayerState::with_per_op(
        state.config.ratelimit_default,
        state.config.ratelimit_list_buckets,
        state.config.ratelimit_bucket_ops,
        state.config.ratelimit_object_ops,
        state.config.ratelimit_head_ops,
        state.config.num_trusted_proxies,
    );
    let admin_rate_limit = middleware::RateLimitLayerState::new(
        state.config.ratelimit_admin,
        state.config.num_trusted_proxies,
    );

    let mut api_router = Router::new()
        .route("/myfsio/health", axum::routing::get(handlers::health_check))
        .route("/", axum::routing::get(handlers::list_buckets))
        .route(
            "/{bucket}",
            axum::routing::put(handlers::create_bucket)
                .get(handlers::get_bucket)
                .delete(handlers::delete_bucket)
                .head(handlers::head_bucket)
                .post(handlers::post_bucket),
        )
        .route(
            "/{bucket}/",
            axum::routing::put(handlers::create_bucket)
                .get(handlers::get_bucket)
                .delete(handlers::delete_bucket)
                .head(handlers::head_bucket)
                .post(handlers::post_bucket),
        )
        .route(
            "/{bucket}/{*key}",
            axum::routing::put(handlers::put_object)
                .get(handlers::get_object)
                .delete(handlers::delete_object)
                .head(handlers::head_object)
                .post(handlers::post_object),
        );

    if state.config.kms_enabled {
        api_router = api_router
            .route(
                "/kms/keys",
                axum::routing::get(handlers::kms::list_keys).post(handlers::kms::create_key),
            )
            .route(
                "/kms/keys/{key_id}",
                axum::routing::get(handlers::kms::get_key).delete(handlers::kms::delete_key),
            )
            .route(
                "/kms/keys/{key_id}/enable",
                axum::routing::post(handlers::kms::enable_key),
            )
            .route(
                "/kms/keys/{key_id}/disable",
                axum::routing::post(handlers::kms::disable_key),
            )
            .route("/kms/encrypt", axum::routing::post(handlers::kms::encrypt))
            .route("/kms/decrypt", axum::routing::post(handlers::kms::decrypt))
            .route(
                "/kms/generate-data-key",
                axum::routing::post(handlers::kms::generate_data_key),
            )
            .route(
                "/kms/generate-data-key-without-plaintext",
                axum::routing::post(handlers::kms::generate_data_key_without_plaintext),
            )
            .route(
                "/kms/re-encrypt",
                axum::routing::post(handlers::kms::re_encrypt),
            )
            .route(
                "/kms/generate-random",
                axum::routing::post(handlers::kms::generate_random),
            )
            .route(
                "/kms/client/generate-key",
                axum::routing::post(handlers::kms::client_generate_key),
            )
            .route(
                "/kms/client/encrypt",
                axum::routing::post(handlers::kms::client_encrypt),
            )
            .route(
                "/kms/client/decrypt",
                axum::routing::post(handlers::kms::client_decrypt),
            )
            .route(
                "/kms/materials/{key_id}",
                axum::routing::post(handlers::kms::materials),
            );
    }

    api_router = api_router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            default_rate_limit,
            middleware::rate_limit_layer,
        ));

    let admin_router = Router::new()
        .route(
            "/admin/site",
            axum::routing::get(handlers::admin::get_local_site)
                .put(handlers::admin::update_local_site),
        )
        .route(
            "/admin/sites",
            axum::routing::get(handlers::admin::list_all_sites)
                .post(handlers::admin::register_peer_site),
        )
        .route(
            "/admin/sites/{site_id}",
            axum::routing::get(handlers::admin::get_peer_site)
                .put(handlers::admin::update_peer_site)
                .delete(handlers::admin::delete_peer_site),
        )
        .route(
            "/admin/sites/{site_id}/health",
            axum::routing::get(handlers::admin::check_peer_health)
                .post(handlers::admin::check_peer_health),
        )
        .route(
            "/admin/sites/{site_id}/bidirectional-status",
            axum::routing::get(handlers::admin::check_bidirectional_status),
        )
        .route(
            "/admin/sync/stats",
            axum::routing::get(handlers::admin::get_sync_stats),
        )
        .route(
            "/admin/cluster/overview",
            axum::routing::get(handlers::admin::get_cluster_overview),
        )
        .route(
            "/admin/topology",
            axum::routing::get(handlers::admin::get_topology),
        )
        .route(
            "/admin/site/local",
            axum::routing::get(handlers::admin::get_local_site)
                .put(handlers::admin::update_local_site),
        )
        .route(
            "/admin/site/all",
            axum::routing::get(handlers::admin::list_all_sites),
        )
        .route(
            "/admin/site/peers",
            axum::routing::post(handlers::admin::register_peer_site),
        )
        .route(
            "/admin/site/peers/{site_id}",
            axum::routing::get(handlers::admin::get_peer_site)
                .put(handlers::admin::update_peer_site)
                .delete(handlers::admin::delete_peer_site),
        )
        .route(
            "/admin/site/peers/{site_id}/health",
            axum::routing::post(handlers::admin::check_peer_health),
        )
        .route(
            "/admin/site/topology",
            axum::routing::get(handlers::admin::get_topology),
        )
        .route(
            "/admin/site/peers/{site_id}/bidirectional-status",
            axum::routing::get(handlers::admin::check_bidirectional_status),
        )
        .route(
            "/admin/iam/users",
            axum::routing::get(handlers::admin::iam_list_users),
        )
        .route(
            "/admin/iam/users/{identifier}",
            axum::routing::get(handlers::admin::iam_get_user),
        )
        .route(
            "/admin/iam/users/{identifier}/policies",
            axum::routing::get(handlers::admin::iam_get_user_policies),
        )
        .route(
            "/admin/iam/users/{identifier}/access-keys",
            axum::routing::post(handlers::admin::iam_create_access_key),
        )
        .route(
            "/admin/iam/users/{identifier}/keys",
            axum::routing::post(handlers::admin::iam_create_access_key),
        )
        .route(
            "/admin/iam/users/{identifier}/access-keys/{access_key}",
            axum::routing::delete(handlers::admin::iam_delete_access_key),
        )
        .route(
            "/admin/iam/users/{identifier}/keys/{access_key}",
            axum::routing::delete(handlers::admin::iam_delete_access_key),
        )
        .route(
            "/admin/iam/users/{identifier}/disable",
            axum::routing::post(handlers::admin::iam_disable_user),
        )
        .route(
            "/admin/iam/users/{identifier}/enable",
            axum::routing::post(handlers::admin::iam_enable_user),
        )
        .route(
            "/admin/website-domains",
            axum::routing::get(handlers::admin::list_website_domains)
                .post(handlers::admin::create_website_domain),
        )
        .route(
            "/admin/website-domains/{domain}",
            axum::routing::get(handlers::admin::get_website_domain)
                .put(handlers::admin::update_website_domain)
                .delete(handlers::admin::delete_website_domain),
        )
        .route(
            "/admin/gc/status",
            axum::routing::get(handlers::admin::gc_status),
        )
        .route(
            "/admin/gc/run",
            axum::routing::post(handlers::admin::gc_run),
        )
        .route(
            "/admin/gc/history",
            axum::routing::get(handlers::admin::gc_history),
        )
        .route(
            "/admin/integrity/status",
            axum::routing::get(handlers::admin::integrity_status),
        )
        .route(
            "/admin/integrity/run",
            axum::routing::post(handlers::admin::integrity_run),
        )
        .route(
            "/admin/integrity/history",
            axum::routing::get(handlers::admin::integrity_history),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            admin_rate_limit,
            middleware::rate_limit_layer,
        ));

    let request_body_timeout =
        std::time::Duration::from_secs(state.config.request_body_timeout_secs);

    api_router
        .merge(admin_router)
        .layer(axum::middleware::from_fn(middleware::server_header))
        .layer(cors_layer(&state.config))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::bucket_cors_layer,
        ))
        .layer(axum::middleware::from_fn(middleware::request_log_layer))
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(tower_http::timeout::RequestBodyTimeoutLayer::new(
            request_body_timeout,
        ))
        .with_state(state)
}

fn cors_layer(config: &config::ServerConfig) -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};
    use tower_http::cors::{Any, CorsLayer};

    let mut layer = CorsLayer::new();

    if config.cors_origins.iter().any(|origin| origin == "*") {
        layer = layer.allow_origin(Any);
    } else {
        let origins = config
            .cors_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect::<Vec<_>>();
        if !origins.is_empty() {
            layer = layer.allow_origin(origins);
        }
    }

    let methods = config
        .cors_methods
        .iter()
        .filter_map(|method| method.parse::<Method>().ok())
        .collect::<Vec<_>>();
    if !methods.is_empty() {
        layer = layer.allow_methods(methods);
    }

    if config.cors_allow_headers.iter().any(|header| header == "*") {
        layer = layer.allow_headers(Any);
    } else {
        let headers = config
            .cors_allow_headers
            .iter()
            .filter_map(|header| header.parse::<HeaderName>().ok())
            .collect::<Vec<_>>();
        if !headers.is_empty() {
            layer = layer.allow_headers(headers);
        }
    }

    if config
        .cors_expose_headers
        .iter()
        .any(|header| header == "*")
    {
        layer = layer.expose_headers(Any);
    } else {
        let headers = config
            .cors_expose_headers
            .iter()
            .filter_map(|header| header.parse::<HeaderName>().ok())
            .collect::<Vec<_>>();
        if !headers.is_empty() {
            layer = layer.expose_headers(headers);
        }
    }

    layer
}
