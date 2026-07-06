mod auth;
mod bucket_cors;
pub mod ratelimit;
pub mod session;
pub(crate) mod sha_body;

pub use auth::{auth_layer, ui_authorize, ui_authorize_list, ui_can_see_bucket};
pub use bucket_cors::bucket_cors_layer;
pub use ratelimit::{rate_limit_layer, RateLimitLayerState};
pub use session::{csrf_layer, session_layer, SessionHandle, SessionLayerState};

#[derive(Clone, Copy, Debug)]
pub struct ReplicationPeerRequest;

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

pub async fn request_log_layer(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();
    let remote = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "-".to_string());

    let response = next.run(req).await;

    let status = response.status().as_u16();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let bytes_out = response
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());

    tracing::info!(
        target: "myfsio::access",
        remote = %remote,
        method = %method,
        uri = %uri,
        version = ?version,
        status,
        bytes_out = bytes_out.unwrap_or(0),
        elapsed_ms = format!("{:.3}", elapsed_ms),
        "request"
    );

    response
}

pub async fn admin_audit_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let should_audit = matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    );
    let path = req.uri().path().to_string();
    let admin_user = req
        .extensions()
        .get::<myfsio_common::types::Principal>()
        .map(|p| p.user_id.clone());

    let response = next.run(req).await;

    if should_audit && state.audit_log.enabled() {
        let status_code = response.status().as_u16();
        let result = if (200..400).contains(&status_code) {
            "ok".to_string()
        } else {
            "error".to_string()
        };
        state
            .audit_log
            .record(crate::services::audit_log::AuditEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                correlation_id: uuid::Uuid::new_v4().to_string(),
                origin_site_id: None,
                admin_user_id: admin_user,
                action: format!("admin:{} {}", method, path),
                method: method.to_string(),
                path,
                target: crate::services::audit_log::AuditTarget::Local,
                result,
                status_code,
                peer_ip: None,
                idempotency_key: None,
                error: None,
                attribution: Some(crate::services::audit_log::ATTRIBUTION_VERIFIED.to_string()),
            });
    }
    response
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
    metrics.record_request(
        method.as_str(),
        endpoint_type,
        status,
        latency_ms,
        bytes_in,
        bytes_out,
        None,
        None,
        None,
        None,
        "ui",
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
