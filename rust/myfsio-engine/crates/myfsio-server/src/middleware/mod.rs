mod auth;
pub mod session;

pub use auth::auth_layer;
pub use session::{csrf_layer, session_layer, SessionHandle, SessionLayerState};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

use crate::state::AppState;

pub async fn server_header(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut()
        .insert("server", crate::SERVER_HEADER.parse().unwrap());
    resp
}

pub async fn ui_metrics_layer(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let metrics = match state.metrics.clone() {
        Some(m) => m,
        None => return next.run(req).await,
    };
    let start = Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let endpoint_type = classify_ui_endpoint(&path);
    let bytes_in = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let response = next.run(req).await;

    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();
    let bytes_out = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let error_code = if status >= 400 { Some("UIError") } else { None };
    metrics.record_request(
        method.as_str(),
        endpoint_type,
        status,
        latency_ms,
        bytes_in,
        bytes_out,
        error_code,
    );

    response
}

fn classify_ui_endpoint(path: &str) -> &'static str {
    if path.contains("/upload") {
        "ui_upload"
    } else if path.starts_with("/ui/buckets/") {
        "ui_bucket"
    } else if path.starts_with("/ui/iam") {
        "ui_iam"
    } else if path.starts_with("/ui/sites") {
        "ui_sites"
    } else if path.starts_with("/ui/connections") {
        "ui_connections"
    } else if path.starts_with("/ui/metrics") {
        "ui_metrics"
    } else if path.starts_with("/ui/system") {
        "ui_system"
    } else if path.starts_with("/ui/website-domains") {
        "ui_website_domains"
    } else if path.starts_with("/ui/replication") {
        "ui_replication"
    } else if path.starts_with("/login") || path.starts_with("/logout") {
        "ui_auth"
    } else {
        "ui_other"
    }
}
