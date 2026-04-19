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
    use axum::routing::{get, post};
    use handlers::ui;
    use handlers::ui_pages;

    let protected = Router::new()
        .route("/ui/buckets", get(ui_pages::buckets_overview))
        .route("/ui/buckets/create", post(ui_pages::create_bucket))
        .route("/ui/buckets/{bucket_name}", get(ui_pages::bucket_detail))
        .route("/ui/iam", get(ui_pages::iam_dashboard))
        .route("/ui/sites", get(ui_pages::sites_dashboard))
        .route("/ui/connections", get(ui_pages::connections_dashboard))
        .route("/ui/metrics", get(ui_pages::metrics_dashboard))
        .route("/ui/system", get(ui_pages::system_dashboard))
        .route("/ui/website-domains", get(ui_pages::website_domains_dashboard))
        .route("/ui/replication/new", get(ui_pages::replication_wizard))
        .route("/ui/docs", get(ui_pages::docs_page))
        .layer(axum::middleware::from_fn(ui::require_login));

    let public = Router::new()
        .route("/login", get(ui::login_page).post(ui::login_submit))
        .route("/logout", post(ui::logout).get(ui::logout))
        .route("/csrf-error", get(ui::csrf_error_page));

    let session_state = middleware::SessionLayerState {
        store: state.sessions.clone(),
        secure: false,
    };

    protected
        .merge(public)
        .layer(axum::middleware::from_fn(middleware::csrf_layer))
        .layer(axum::middleware::from_fn_with_state(
            session_state,
            middleware::session_layer,
        ))
        .with_state(state)
}

pub fn create_router(state: state::AppState) -> Router {
    let mut router = Router::new()
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
            "/{bucket}/{*key}",
            axum::routing::put(handlers::put_object)
                .get(handlers::get_object)
                .delete(handlers::delete_object)
                .head(handlers::head_object)
                .post(handlers::post_object),
        );

    if state.config.kms_enabled {
        router = router
            .route("/kms/keys", axum::routing::get(handlers::kms::list_keys).post(handlers::kms::create_key))
            .route("/kms/keys/{key_id}", axum::routing::get(handlers::kms::get_key).delete(handlers::kms::delete_key))
            .route("/kms/keys/{key_id}/enable", axum::routing::post(handlers::kms::enable_key))
            .route("/kms/keys/{key_id}/disable", axum::routing::post(handlers::kms::disable_key))
            .route("/kms/encrypt", axum::routing::post(handlers::kms::encrypt))
            .route("/kms/decrypt", axum::routing::post(handlers::kms::decrypt))
            .route("/kms/generate-data-key", axum::routing::post(handlers::kms::generate_data_key));
    }

    router = router
        .route("/admin/site/local", axum::routing::get(handlers::admin::get_local_site).put(handlers::admin::update_local_site))
        .route("/admin/site/all", axum::routing::get(handlers::admin::list_all_sites))
        .route("/admin/site/peers", axum::routing::post(handlers::admin::register_peer_site))
        .route("/admin/site/peers/{site_id}", axum::routing::get(handlers::admin::get_peer_site).put(handlers::admin::update_peer_site).delete(handlers::admin::delete_peer_site))
        .route("/admin/site/peers/{site_id}/health", axum::routing::post(handlers::admin::check_peer_health))
        .route("/admin/site/topology", axum::routing::get(handlers::admin::get_topology))
        .route("/admin/site/peers/{site_id}/bidirectional-status", axum::routing::get(handlers::admin::check_bidirectional_status))
        .route("/admin/iam/users", axum::routing::get(handlers::admin::iam_list_users))
        .route("/admin/iam/users/{identifier}", axum::routing::get(handlers::admin::iam_get_user))
        .route("/admin/iam/users/{identifier}/policies", axum::routing::get(handlers::admin::iam_get_user_policies))
        .route("/admin/iam/users/{identifier}/access-keys", axum::routing::post(handlers::admin::iam_create_access_key))
        .route("/admin/iam/users/{identifier}/access-keys/{access_key}", axum::routing::delete(handlers::admin::iam_delete_access_key))
        .route("/admin/iam/users/{identifier}/disable", axum::routing::post(handlers::admin::iam_disable_user))
        .route("/admin/iam/users/{identifier}/enable", axum::routing::post(handlers::admin::iam_enable_user))
        .route("/admin/website-domains", axum::routing::get(handlers::admin::list_website_domains).post(handlers::admin::create_website_domain))
        .route("/admin/website-domains/{domain}", axum::routing::get(handlers::admin::get_website_domain).put(handlers::admin::update_website_domain).delete(handlers::admin::delete_website_domain))
        .route("/admin/gc/status", axum::routing::get(handlers::admin::gc_status))
        .route("/admin/gc/run", axum::routing::post(handlers::admin::gc_run))
        .route("/admin/gc/history", axum::routing::get(handlers::admin::gc_history))
        .route("/admin/integrity/status", axum::routing::get(handlers::admin::integrity_status))
        .route("/admin/integrity/run", axum::routing::post(handlers::admin::integrity_run))
        .route("/admin/integrity/history", axum::routing::get(handlers::admin::integrity_history));

    let mut router = router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_layer,
        ))
        .layer(axum::middleware::from_fn(middleware::server_header))
        .with_state(state.clone());

    if state.config.ui_enabled {
        let static_service = tower_http::services::ServeDir::new(&state.config.static_dir);
        router = router
            .nest_service("/static", static_service)
            .merge(create_ui_router(state));
    }

    router
}
