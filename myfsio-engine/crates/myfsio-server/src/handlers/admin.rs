use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use myfsio_common::types::Principal;
use myfsio_storage::traits::StorageEngine;

use crate::services::site_registry::{PeerSite, SiteInfo};
use crate::services::website_domains::{is_valid_domain, normalize_domain};
use crate::state::AppState;

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        value.to_string(),
    )
        .into_response()
}

fn json_error(code: &str, message: &str, status: StatusCode) -> Response {
    json_response(
        status,
        serde_json::json!({"error": {"code": code, "message": message}}),
    )
}

fn require_admin(principal: &Principal) -> Option<Response> {
    if !principal.is_admin {
        return Some(json_error("AccessDenied", "Admin access required", StatusCode::FORBIDDEN));
    }
    None
}

async fn read_json_body(body: Body) -> Option<serde_json::Value> {
    let bytes = http_body_util::BodyExt::collect(body).await.ok()?.to_bytes();
    serde_json::from_slice(&bytes).ok()
}

fn validate_site_id(site_id: &str) -> Option<String> {
    if site_id.is_empty() || site_id.len() > 63 {
        return Some("site_id must be 1-63 characters".to_string());
    }
    let first = site_id.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Some("site_id must start with alphanumeric".to_string());
    }
    if !site_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Some("site_id must contain only alphanumeric, hyphens, underscores".to_string());
    }
    None
}

fn validate_endpoint(endpoint: &str) -> Option<String> {
    if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
        return Some("Endpoint must be http or https URL".to_string());
    }
    None
}

fn validate_region(region: &str) -> Option<String> {
    let re = regex::Regex::new(r"^[a-z]{2,}-[a-z]+-\d+$").unwrap();
    if !re.is_match(region) {
        return Some("Region must match format like us-east-1".to_string());
    }
    None
}

fn validate_priority(priority: i64) -> Option<String> {
    if priority < 0 || priority > 1000 {
        return Some("Priority must be between 0 and 1000".to_string());
    }
    None
}

pub async fn get_local_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }

    if let Some(ref registry) = state.site_registry {
        if let Some(local) = registry.get_local_site() {
            return json_response(StatusCode::OK, serde_json::to_value(&local).unwrap());
        }
    }

    json_error("NotFound", "Local site not configured", StatusCode::NOT_FOUND)
}

pub async fn update_local_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("InvalidRequest", "Site registry not available", StatusCode::BAD_REQUEST),
    };

    let payload = match read_json_body(body).await {
        Some(v) => v,
        None => return json_error("MalformedJSON", "Invalid JSON body", StatusCode::BAD_REQUEST),
    };

    let site_id = match payload.get("site_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return json_error("ValidationError", "site_id is required", StatusCode::BAD_REQUEST),
    };

    if let Some(err) = validate_site_id(&site_id) {
        return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
    }

    let endpoint = payload.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !endpoint.is_empty() {
        if let Some(err) = validate_endpoint(&endpoint) {
            return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
        }
    }

    if let Some(p) = payload.get("priority").and_then(|v| v.as_i64()) {
        if let Some(err) = validate_priority(p) {
            return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
        }
    }

    if let Some(r) = payload.get("region").and_then(|v| v.as_str()) {
        if let Some(err) = validate_region(r) {
            return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
        }
    }

    let existing = registry.get_local_site();
    let site = SiteInfo {
        site_id: site_id.clone(),
        endpoint,
        region: payload.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1").to_string(),
        priority: payload.get("priority").and_then(|v| v.as_i64()).unwrap_or(100) as i32,
        display_name: payload.get("display_name").and_then(|v| v.as_str()).unwrap_or(&site_id).to_string(),
        created_at: existing.and_then(|e| e.created_at),
    };

    registry.set_local_site(site.clone());
    json_response(StatusCode::OK, serde_json::to_value(&site).unwrap())
}

pub async fn list_all_sites(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_response(StatusCode::OK, serde_json::json!({"local": null, "peers": [], "total_peers": 0})),
    };

    let local = registry.get_local_site();
    let peers = registry.list_peers();

    json_response(StatusCode::OK, serde_json::json!({
        "local": local,
        "peers": peers,
        "total_peers": peers.len(),
    }))
}

pub async fn register_peer_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("InvalidRequest", "Site registry not available", StatusCode::BAD_REQUEST),
    };

    let payload = match read_json_body(body).await {
        Some(v) => v,
        None => return json_error("MalformedJSON", "Invalid JSON body", StatusCode::BAD_REQUEST),
    };

    let site_id = match payload.get("site_id").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return json_error("ValidationError", "site_id is required", StatusCode::BAD_REQUEST),
    };
    if let Some(err) = validate_site_id(&site_id) {
        return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
    }

    let endpoint = match payload.get("endpoint").and_then(|v| v.as_str()) {
        Some(e) => e.to_string(),
        None => return json_error("ValidationError", "endpoint is required", StatusCode::BAD_REQUEST),
    };
    if let Some(err) = validate_endpoint(&endpoint) {
        return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
    }

    let region = payload.get("region").and_then(|v| v.as_str()).unwrap_or("us-east-1").to_string();
    if let Some(err) = validate_region(&region) {
        return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
    }

    let priority = payload.get("priority").and_then(|v| v.as_i64()).unwrap_or(100);
    if let Some(err) = validate_priority(priority) {
        return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
    }

    if registry.get_peer(&site_id).is_some() {
        return json_error("AlreadyExists", &format!("Peer site '{}' already exists", site_id), StatusCode::CONFLICT);
    }

    let peer = PeerSite {
        site_id: site_id.clone(),
        endpoint,
        region,
        priority: priority as i32,
        display_name: payload.get("display_name").and_then(|v| v.as_str()).unwrap_or(&site_id).to_string(),
        connection_id: payload.get("connection_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
        created_at: Some(chrono::Utc::now().to_rfc3339()),
        is_healthy: false,
        last_health_check: None,
    };

    registry.add_peer(peer.clone());
    json_response(StatusCode::CREATED, serde_json::to_value(&peer).unwrap())
}

pub async fn get_peer_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(site_id): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("NotFound", "Site registry not available", StatusCode::NOT_FOUND),
    };

    match registry.get_peer(&site_id) {
        Some(peer) => json_response(StatusCode::OK, serde_json::to_value(&peer).unwrap()),
        None => json_error("NotFound", &format!("Peer site '{}' not found", site_id), StatusCode::NOT_FOUND),
    }
}

pub async fn update_peer_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(site_id): Path<String>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("NotFound", "Site registry not available", StatusCode::NOT_FOUND),
    };

    let existing = match registry.get_peer(&site_id) {
        Some(p) => p,
        None => return json_error("NotFound", &format!("Peer site '{}' not found", site_id), StatusCode::NOT_FOUND),
    };

    let payload = match read_json_body(body).await {
        Some(v) => v,
        None => return json_error("MalformedJSON", "Invalid JSON body", StatusCode::BAD_REQUEST),
    };

    if let Some(ep) = payload.get("endpoint").and_then(|v| v.as_str()) {
        if let Some(err) = validate_endpoint(ep) {
            return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
        }
    }
    if let Some(p) = payload.get("priority").and_then(|v| v.as_i64()) {
        if let Some(err) = validate_priority(p) {
            return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
        }
    }
    if let Some(r) = payload.get("region").and_then(|v| v.as_str()) {
        if let Some(err) = validate_region(r) {
            return json_error("ValidationError", &err, StatusCode::BAD_REQUEST);
        }
    }

    let peer = PeerSite {
        site_id: site_id.clone(),
        endpoint: payload.get("endpoint").and_then(|v| v.as_str()).unwrap_or(&existing.endpoint).to_string(),
        region: payload.get("region").and_then(|v| v.as_str()).unwrap_or(&existing.region).to_string(),
        priority: payload.get("priority").and_then(|v| v.as_i64()).unwrap_or(existing.priority as i64) as i32,
        display_name: payload.get("display_name").and_then(|v| v.as_str()).unwrap_or(&existing.display_name).to_string(),
        connection_id: payload.get("connection_id").and_then(|v| v.as_str()).map(|s| s.to_string()).or(existing.connection_id),
        created_at: existing.created_at,
        is_healthy: existing.is_healthy,
        last_health_check: existing.last_health_check,
    };

    registry.update_peer(peer.clone());
    json_response(StatusCode::OK, serde_json::to_value(&peer).unwrap())
}

pub async fn delete_peer_site(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(site_id): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("NotFound", "Site registry not available", StatusCode::NOT_FOUND),
    };

    if !registry.delete_peer(&site_id) {
        return json_error("NotFound", &format!("Peer site '{}' not found", site_id), StatusCode::NOT_FOUND);
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn check_peer_health(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(site_id): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("NotFound", "Site registry not available", StatusCode::NOT_FOUND),
    };

    if registry.get_peer(&site_id).is_none() {
        return json_error("NotFound", &format!("Peer site '{}' not found", site_id), StatusCode::NOT_FOUND);
    }

    json_response(StatusCode::OK, serde_json::json!({
        "site_id": site_id,
        "is_healthy": false,
        "error": "Health check not implemented in standalone mode",
        "checked_at": chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
    }))
}

pub async fn get_topology(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_response(StatusCode::OK, serde_json::json!({"sites": [], "total": 0, "healthy_count": 0})),
    };

    let local = registry.get_local_site();
    let peers = registry.list_peers();

    let mut sites: Vec<serde_json::Value> = Vec::new();
    if let Some(l) = local {
        let mut v = serde_json::to_value(&l).unwrap();
        v.as_object_mut().unwrap().insert("is_local".to_string(), serde_json::json!(true));
        v.as_object_mut().unwrap().insert("is_healthy".to_string(), serde_json::json!(true));
        sites.push(v);
    }
    for p in &peers {
        let mut v = serde_json::to_value(p).unwrap();
        v.as_object_mut().unwrap().insert("is_local".to_string(), serde_json::json!(false));
        sites.push(v);
    }

    sites.sort_by_key(|s| s.get("priority").and_then(|v| v.as_i64()).unwrap_or(100));

    let healthy_count = sites.iter().filter(|s| s.get("is_healthy").and_then(|v| v.as_bool()).unwrap_or(false)).count();

    json_response(StatusCode::OK, serde_json::json!({
        "sites": sites,
        "total": sites.len(),
        "healthy_count": healthy_count,
    }))
}

pub async fn check_bidirectional_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(site_id): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let registry = match &state.site_registry {
        Some(r) => r,
        None => return json_error("NotFound", "Site registry not available", StatusCode::NOT_FOUND),
    };

    if registry.get_peer(&site_id).is_none() {
        return json_error("NotFound", &format!("Peer site '{}' not found", site_id), StatusCode::NOT_FOUND);
    }

    let local = registry.get_local_site();
    json_response(StatusCode::OK, serde_json::json!({
        "site_id": site_id,
        "local_site_id": local.as_ref().map(|l| &l.site_id),
        "local_endpoint": local.as_ref().map(|l| &l.endpoint),
        "local_bidirectional_rules": [],
        "local_site_sync_enabled": false,
        "remote_status": null,
        "issues": [{"code": "NOT_IMPLEMENTED", "message": "Bidirectional status check not implemented in standalone mode", "severity": "warning"}],
        "is_fully_configured": false,
    }))
}

pub async fn iam_list_users(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let users = state.iam.list_users().await;
    json_response(StatusCode::OK, serde_json::json!({"users": users}))
}

pub async fn iam_get_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(identifier): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match state.iam.get_user(&identifier).await {
        Some(user) => json_response(StatusCode::OK, user),
        None => json_error("NotFound", &format!("User '{}' not found", identifier), StatusCode::NOT_FOUND),
    }
}

pub async fn iam_get_user_policies(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(identifier): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match state.iam.get_user_policies(&identifier) {
        Some(policies) => json_response(StatusCode::OK, serde_json::json!({"policies": policies})),
        None => json_error("NotFound", &format!("User '{}' not found", identifier), StatusCode::NOT_FOUND),
    }
}

pub async fn iam_create_access_key(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(identifier): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match state.iam.create_access_key(&identifier) {
        Ok(result) => json_response(StatusCode::CREATED, result),
        Err(e) => json_error("InvalidRequest", &e, StatusCode::BAD_REQUEST),
    }
}

pub async fn iam_delete_access_key(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((_identifier, access_key)): Path<(String, String)>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match state.iam.delete_access_key(&access_key) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => json_error("InvalidRequest", &e, StatusCode::BAD_REQUEST),
    }
}

pub async fn iam_disable_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(identifier): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match state.iam.set_user_enabled(&identifier, false).await {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({"status": "disabled"})),
        Err(e) => json_error("InvalidRequest", &e, StatusCode::BAD_REQUEST),
    }
}

pub async fn iam_enable_user(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(identifier): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match state.iam.set_user_enabled(&identifier, true).await {
        Ok(()) => json_response(StatusCode::OK, serde_json::json!({"status": "enabled"})),
        Err(e) => json_error("InvalidRequest", &e, StatusCode::BAD_REQUEST),
    }
}

pub async fn list_website_domains(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let store = match &state.website_domains {
        Some(s) => s,
        None => return json_error("InvalidRequest", "Website hosting is not enabled", StatusCode::BAD_REQUEST),
    };
    json_response(StatusCode::OK, serde_json::json!(store.list_all()))
}

pub async fn create_website_domain(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let store = match &state.website_domains {
        Some(s) => s,
        None => return json_error("InvalidRequest", "Website hosting is not enabled", StatusCode::BAD_REQUEST),
    };

    let payload = match read_json_body(body).await {
        Some(v) => v,
        None => return json_error("MalformedJSON", "Invalid JSON body", StatusCode::BAD_REQUEST),
    };

    let domain = normalize_domain(payload.get("domain").and_then(|v| v.as_str()).unwrap_or(""));
    if domain.is_empty() {
        return json_error("ValidationError", "domain is required", StatusCode::BAD_REQUEST);
    }
    if !is_valid_domain(&domain) {
        return json_error("ValidationError", &format!("Invalid domain: '{}'", domain), StatusCode::BAD_REQUEST);
    }

    let bucket = payload.get("bucket").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if bucket.is_empty() {
        return json_error("ValidationError", "bucket is required", StatusCode::BAD_REQUEST);
    }

    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => {}
        _ => return json_error("NoSuchBucket", &format!("Bucket '{}' does not exist", bucket), StatusCode::NOT_FOUND),
    }

    if store.get_bucket(&domain).is_some() {
        return json_error("Conflict", &format!("Domain '{}' is already mapped", domain), StatusCode::CONFLICT);
    }

    store.set_mapping(&domain, &bucket);
    json_response(StatusCode::CREATED, serde_json::json!({"domain": domain, "bucket": bucket}))
}

pub async fn get_website_domain(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(domain): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let store = match &state.website_domains {
        Some(s) => s,
        None => return json_error("InvalidRequest", "Website hosting is not enabled", StatusCode::BAD_REQUEST),
    };

    let domain = normalize_domain(&domain);
    match store.get_bucket(&domain) {
        Some(bucket) => json_response(StatusCode::OK, serde_json::json!({"domain": domain, "bucket": bucket})),
        None => json_error("NotFound", &format!("No mapping found for domain '{}'", domain), StatusCode::NOT_FOUND),
    }
}

pub async fn update_website_domain(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(domain): Path<String>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let store = match &state.website_domains {
        Some(s) => s,
        None => return json_error("InvalidRequest", "Website hosting is not enabled", StatusCode::BAD_REQUEST),
    };

    let domain = normalize_domain(&domain);
    let payload = match read_json_body(body).await {
        Some(v) => v,
        None => return json_error("MalformedJSON", "Invalid JSON body", StatusCode::BAD_REQUEST),
    };

    let bucket = payload.get("bucket").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if bucket.is_empty() {
        return json_error("ValidationError", "bucket is required", StatusCode::BAD_REQUEST);
    }

    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => {}
        _ => return json_error("NoSuchBucket", &format!("Bucket '{}' does not exist", bucket), StatusCode::NOT_FOUND),
    }

    if store.get_bucket(&domain).is_none() {
        return json_error("NotFound", &format!("No mapping found for domain '{}'", domain), StatusCode::NOT_FOUND);
    }

    store.set_mapping(&domain, &bucket);
    json_response(StatusCode::OK, serde_json::json!({"domain": domain, "bucket": bucket}))
}

pub async fn delete_website_domain(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(domain): Path<String>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let store = match &state.website_domains {
        Some(s) => s,
        None => return json_error("InvalidRequest", "Website hosting is not enabled", StatusCode::BAD_REQUEST),
    };

    let domain = normalize_domain(&domain);
    if !store.delete_mapping(&domain) {
        return json_error("NotFound", &format!("No mapping found for domain '{}'", domain), StatusCode::NOT_FOUND);
    }
    StatusCode::NO_CONTENT.into_response()
}

#[derive(serde::Deserialize, Default)]
pub struct PaginationQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn gc_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match &state.gc {
        Some(gc) => json_response(StatusCode::OK, gc.status().await),
        None => json_response(StatusCode::OK, serde_json::json!({"enabled": false, "message": "GC is not enabled. Set GC_ENABLED=true to enable."})),
    }
}

pub async fn gc_run(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let gc = match &state.gc {
        Some(gc) => gc,
        None => return json_error("InvalidRequest", "GC is not enabled", StatusCode::BAD_REQUEST),
    };

    let payload = read_json_body(body).await.unwrap_or(serde_json::json!({}));
    let dry_run = payload.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);

    match gc.run_now(dry_run).await {
        Ok(result) => json_response(StatusCode::OK, result),
        Err(e) => json_error("Conflict", &e, StatusCode::CONFLICT),
    }
}

pub async fn gc_history(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match &state.gc {
        Some(gc) => json_response(StatusCode::OK, serde_json::json!({"executions": gc.history().await})),
        None => json_response(StatusCode::OK, serde_json::json!({"executions": []})),
    }
}

pub async fn integrity_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match &state.integrity {
        Some(checker) => json_response(StatusCode::OK, checker.status().await),
        None => json_response(StatusCode::OK, serde_json::json!({"enabled": false, "message": "Integrity checker is not enabled. Set INTEGRITY_ENABLED=true to enable."})),
    }
}

pub async fn integrity_run(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    body: Body,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    let checker = match &state.integrity {
        Some(c) => c,
        None => return json_error("InvalidRequest", "Integrity checker is not enabled", StatusCode::BAD_REQUEST),
    };

    let payload = read_json_body(body).await.unwrap_or(serde_json::json!({}));
    let dry_run = payload.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
    let auto_heal = payload.get("auto_heal").and_then(|v| v.as_bool()).unwrap_or(false);

    match checker.run_now(dry_run, auto_heal).await {
        Ok(result) => json_response(StatusCode::OK, result),
        Err(e) => json_error("Conflict", &e, StatusCode::CONFLICT),
    }
}

pub async fn integrity_history(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> Response {
    if let Some(err) = require_admin(&principal) { return err; }
    match &state.integrity {
        Some(checker) => json_response(StatusCode::OK, serde_json::json!({"executions": checker.history().await})),
        None => json_response(StatusCode::OK, serde_json::json!({"executions": []})),
    }
}
