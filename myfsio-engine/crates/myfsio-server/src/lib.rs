pub mod config;
pub mod handlers;
pub mod middleware;
pub mod services;
pub mod state;

use axum::Router;

pub const SERVER_HEADER: &str = concat!("MyFSIO-Rust/", env!("CARGO_PKG_VERSION"));

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

    router
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_layer,
        ))
        .layer(axum::middleware::from_fn(middleware::server_header))
        .with_state(state)
}
