use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use http_body_util::BodyExt;
use myfsio_common::types::{Principal, PrincipalKind};
use sha2::{Digest, Sha256};

use crate::handlers::RelayContext;
use crate::services::audit_log::{AuditEntry, AuditTarget};
use crate::services::cluster_attest::{verify_admin_attest, verify_cluster_attest};
use crate::state::{AppState, RelayIdempotencyEntry};

fn json_error(code: &str, message: &str, status: StatusCode) -> Response {
    let body = serde_json::json!({"error": {"code": code, "message": message}}).to_string();
    (
        status,
        [("content-type", "application/json")],
        body,
    )
        .into_response()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

pub async fn relay_inbound_layer(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());

    let peer_principal = match req.extensions().get::<Principal>() {
        Some(p) if p.is_peer() => p.clone(),
        _ => {
            return json_error(
                "AccessDenied",
                "Peer principal required for /admin/peer/*",
                StatusCode::FORBIDDEN,
            );
        }
    };
    let peer_site_id = peer_principal
        .peer_site_id()
        .unwrap_or("")
        .to_string();

    let psk = match state.config.cluster_psk.as_deref() {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => {
            return json_error(
                "ServiceUnavailable",
                "Cluster federation is disabled (MYFSIO_CLUSTER_PSK not set)",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
    };

    let amz_date = header_str(req.headers(), "x-amz-date").to_string();
    let origin_site = header_str(req.headers(), "x-myfsio-origin-site").to_string();
    let admin_user = header_str(req.headers(), "x-myfsio-admin-user").to_string();
    let admin_attest = header_str(req.headers(), "x-myfsio-admin-attest").to_string();
    let cluster_attest = header_str(req.headers(), "x-myfsio-cluster-attest").to_string();
    let idempotency_key = header_str(req.headers(), "x-myfsio-idempotency-key").to_string();
    let correlation_id = {
        let v = header_str(req.headers(), "x-myfsio-correlation-id").to_string();
        if v.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            v
        }
    };

    if origin_site.is_empty()
        || admin_user.is_empty()
        || admin_attest.is_empty()
        || cluster_attest.is_empty()
        || idempotency_key.is_empty()
        || amz_date.is_empty()
    {
        return json_error(
            "InvalidArgument",
            "Missing relay attestation headers",
            StatusCode::BAD_REQUEST,
        );
    }

    if origin_site != peer_site_id {
        return json_error(
            "AccessDenied",
            "x-myfsio-origin-site does not match peer principal site_id",
            StatusCode::FORBIDDEN,
        );
    }

    if !verify_cluster_attest(&psk, &amz_date, &origin_site, &idempotency_key, &cluster_attest) {
        return json_error(
            "AccessDenied",
            "Invalid cluster attestation",
            StatusCode::FORBIDDEN,
        );
    }
    if !verify_admin_attest(&psk, &amz_date, &admin_user, &admin_attest) {
        return json_error(
            "AccessDenied",
            "Invalid admin attestation",
            StatusCode::FORBIDDEN,
        );
    }

    let path_with_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());

    let (parts_for_replay, request_body) = req.into_parts();
    let body_bytes = match Body::from(request_body).collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return json_error(
                "InternalError",
                &format!("Body read failed: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    let request_fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(parts_for_replay.method.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(path_with_query.as_bytes());
        hasher.update(b"\n");
        hasher.update(&body_bytes);
        hex::encode(hasher.finalize())
    };
    let mut req = Request::from_parts(parts_for_replay, Body::from(body_bytes.clone()));

    let idemp_cache_key = format!("{}:{}", origin_site, idempotency_key);
    let ttl = Duration::from_secs(state.config.relay_idempotency_ttl_secs);
    {
        let mut cache = state.relay_idempotency_cache.lock();
        if let Some(entry) = cache.get(&idemp_cache_key) {
            if entry.stored_at.elapsed() < ttl {
                if entry.request_fingerprint != request_fingerprint {
                    return json_error(
                        "InvalidArgument",
                        "x-myfsio-idempotency-key was previously used with a different method/path/body within the TTL window. Use a fresh idempotency key for distinct operations.",
                        StatusCode::CONFLICT,
                    );
                }
                let status = StatusCode::from_u16(entry.status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let body_bytes = entry.body.clone();
                return (
                    status,
                    [
                        ("content-type", "application/json"),
                        ("x-myfsio-idempotent-replay", "true"),
                    ],
                    body_bytes,
                )
                    .into_response();
            }
        }
    }

    let synthetic_admin = Principal {
        access_key: peer_principal.access_key.clone(),
        user_id: admin_user.clone(),
        display_name: format!("relay:{}", admin_user),
        is_admin: true,
        kind: PrincipalKind::User,
    };
    req.extensions_mut().insert(synthetic_admin);
    req.extensions_mut().insert(RelayContext {
        origin_site_id: origin_site.clone(),
        admin_user_id: admin_user.clone(),
        idempotency_key: idempotency_key.clone(),
        correlation_id: correlation_id.clone(),
    });

    let response = next.run(req).await;

    let (parts, body) = response.into_parts();
    let collected = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::error!("relay response read failed: {}", e);
            return json_error(
                "InternalError",
                "Relay response read failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };
    let status_code = parts.status.as_u16();
    let body_vec = collected.to_vec();

    {
        let mut cache = state.relay_idempotency_cache.lock();
        cache.put(
            idemp_cache_key,
            RelayIdempotencyEntry {
                stored_at: Instant::now(),
                status: status_code,
                body: body_vec.clone(),
                request_fingerprint: request_fingerprint.clone(),
            },
        );
    }

    let result = if (200..400).contains(&status_code) {
        "ok"
    } else {
        "error"
    };
    state.audit_log.record(AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        correlation_id,
        origin_site_id: Some(origin_site),
        admin_user_id: Some(admin_user),
        action: format!("{} {}", method, path),
        method,
        path,
        target: AuditTarget::Local,
        result: result.to_string(),
        status_code,
        peer_ip,
        idempotency_key: Some(idempotency_key),
        error: if result == "error" {
            Some(String::from_utf8_lossy(&body_vec).to_string())
        } else {
            None
        },
    });

    Response::from_parts(parts, Body::from(body_vec))
}

pub async fn relay_outbound(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((site_id, sub_path)): Path<(String, String)>,
    req: Request,
) -> Response {
    if !principal.is_admin {
        return json_error(
            "AccessDenied",
            "Admin access required to dispatch relay",
            StatusCode::FORBIDDEN,
        );
    }
    if principal.is_peer() {
        return json_error(
            "AccessDenied",
            "Peer principals cannot dispatch relays",
            StatusCode::FORBIDDEN,
        );
    }

    let psk = match state.config.cluster_psk.as_deref() {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => {
            return json_error(
                "ServiceUnavailable",
                "Cluster federation is disabled (MYFSIO_CLUSTER_PSK not set)",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
    };

    let registry = match state.site_registry.as_ref() {
        Some(r) => r.clone(),
        None => {
            return json_error(
                "NotFound",
                "Site registry not configured",
                StatusCode::NOT_FOUND,
            );
        }
    };

    let _peer = match registry.get_peer(&site_id) {
        Some(p) => p,
        None => {
            return json_error(
                "NotFound",
                &format!("Peer '{}' not registered", site_id),
                StatusCode::NOT_FOUND,
            );
        }
    };

    let connection_id = match _peer.connection_id.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => {
            return json_error(
                "InvalidArgument",
                &format!("Peer '{}' has no connection_id; cannot relay", site_id),
                StatusCode::BAD_REQUEST,
            );
        }
    };
    let connection = match state.connections.get(&connection_id) {
        Some(c) => c,
        None => {
            return json_error(
                "NotFound",
                &format!("Connection '{}' not found", connection_id),
                StatusCode::NOT_FOUND,
            );
        }
    };

    let local_site_id = registry
        .get_local_site()
        .map(|s| s.site_id)
        .unwrap_or_default();
    if local_site_id.is_empty() {
        return json_error(
            "ServiceUnavailable",
            "Local site identity not configured (set SITE_ID)",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }

    let method = req.method().clone();
    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
    let target_path = format!("/admin/peer/{}{}", sub_path, query);

    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let supplied_idempotency = req
        .headers()
        .get("x-myfsio-idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let supplied_correlation = req
        .headers()
        .get("x-myfsio-correlation-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let idempotency_key = supplied_idempotency
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let correlation_id = supplied_correlation
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let body_bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(e) => {
            return json_error(
                "InternalError",
                &format!("Body read failed: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            );
        }
    };

    let method_str = method.as_str().to_string();
    let result = state
        .peer_admin
        .relay_request(
            &connection.endpoint_url,
            method.as_str(),
            &target_path,
            &connection,
            body_bytes,
            content_type.as_deref(),
            &psk,
            &local_site_id,
            &principal.user_id,
            &idempotency_key,
            &correlation_id,
        )
        .await;

    match result {
        Ok(resp) => {
            let status_u16 = resp.status;
            let status =
                StatusCode::from_u16(resp.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = resp.body;

            let outcome = if (200..400).contains(&status_u16) {
                "ok"
            } else {
                "error"
            };
            state.audit_log.record(AuditEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                correlation_id: correlation_id.clone(),
                origin_site_id: Some(local_site_id),
                admin_user_id: Some(principal.user_id.clone()),
                action: format!("relay {} {}", method_str, target_path),
                method: method_str,
                path: format!("/admin/relay/{}/{}", site_id, sub_path),
                target: AuditTarget::Outbound,
                result: outcome.to_string(),
                status_code: status_u16,
                peer_ip: None,
                idempotency_key: Some(idempotency_key.clone()),
                error: if outcome == "error" {
                    Some(String::from_utf8_lossy(&body).to_string())
                } else {
                    None
                },
            });

            let mut response = Response::new(Body::from(body));
            *response.status_mut() = status;
            if let Some(ct) = resp.content_type {
                if let Ok(value) = ct.parse() {
                    response.headers_mut().insert("content-type", value);
                }
            }
            response
                .headers_mut()
                .insert("x-myfsio-correlation-id", correlation_id.parse().unwrap());
            response
                .headers_mut()
                .insert("x-myfsio-idempotency-key", idempotency_key.parse().unwrap());
            response
        }
        Err(e) => {
            state.audit_log.record(AuditEntry {
                ts: chrono::Utc::now().to_rfc3339(),
                correlation_id: correlation_id.clone(),
                origin_site_id: Some(local_site_id),
                admin_user_id: Some(principal.user_id.clone()),
                action: format!("relay {} {}", method_str, target_path),
                method: method_str,
                path: format!("/admin/relay/{}/{}", site_id, sub_path),
                target: AuditTarget::Outbound,
                result: "error".to_string(),
                status_code: 502,
                peer_ip: None,
                idempotency_key: Some(idempotency_key),
                error: Some(e.clone()),
            });
            json_error(
                "BadGateway",
                &format!("Relay failed: {}", e),
                StatusCode::BAD_GATEWAY,
            )
        }
    }
}
