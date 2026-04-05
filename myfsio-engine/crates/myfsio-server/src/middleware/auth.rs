use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use chrono::{NaiveDateTime, Utc};
use myfsio_auth::sigv4;
use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_common::types::Principal;

use crate::state::AppState;

pub async fn auth_layer(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let uri = req.uri().clone();
    let path = uri.path().to_string();

    if path == "/" && req.method() == axum::http::Method::GET {
        match try_auth(&state, &req) {
            AuthResult::Ok(principal) => {
                if let Err(err) = authorize_request(&state, &principal, &req) {
                    return error_response(err, &path);
                }
                req.extensions_mut().insert(principal);
            }
            AuthResult::Denied(err) => return error_response(err, &path),
            AuthResult::NoAuth => {
                return error_response(
                    S3Error::new(S3ErrorCode::AccessDenied, "Missing credentials"),
                    &path,
                );
            }
        }
        return next.run(req).await;
    }

    match try_auth(&state, &req) {
        AuthResult::Ok(principal) => {
            if let Err(err) = authorize_request(&state, &principal, &req) {
                return error_response(err, &path);
            }
            req.extensions_mut().insert(principal);
            next.run(req).await
        }
        AuthResult::Denied(err) => error_response(err, &path),
        AuthResult::NoAuth => {
            error_response(
                S3Error::new(S3ErrorCode::AccessDenied, "Missing credentials"),
                &path,
            )
        }
    }
}

enum AuthResult {
    Ok(Principal),
    Denied(S3Error),
    NoAuth,
}

fn authorize_request(state: &AppState, principal: &Principal, req: &Request) -> Result<(), S3Error> {
    let path = req.uri().path();
    if path == "/" {
        if state.iam.authorize(principal, None, "list", None) {
            return Ok(());
        }
        return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
    }

    if path.starts_with("/admin/") || path.starts_with("/kms/") {
        return Ok(());
    }

    let mut segments = path.trim_start_matches('/').split('/').filter(|s| !s.is_empty());
    let bucket = match segments.next() {
        Some(b) => b,
        None => {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
        }
    };
    let remaining: Vec<&str> = segments.collect();
    let query = req.uri().query().unwrap_or("");

    if remaining.is_empty() {
        let action = resolve_bucket_action(req.method(), query);
        if state.iam.authorize(principal, Some(bucket), action, None) {
            return Ok(());
        }
        return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
    }

    let object_key = remaining.join("/");
    if req.method() == Method::PUT {
        if let Some(copy_source) = req
            .headers()
            .get("x-amz-copy-source")
            .and_then(|v| v.to_str().ok())
        {
            let source = copy_source.strip_prefix('/').unwrap_or(copy_source);
            if let Some((src_bucket, src_key)) = source.split_once('/') {
                let source_allowed =
                    state.iam.authorize(principal, Some(src_bucket), "read", Some(src_key));
                let dest_allowed =
                    state.iam.authorize(principal, Some(bucket), "write", Some(&object_key));
                if source_allowed && dest_allowed {
                    return Ok(());
                }
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
            }
        }
    }

    let action = resolve_object_action(req.method(), query);
    if state
        .iam
        .authorize(principal, Some(bucket), action, Some(&object_key))
    {
        return Ok(());
    }

    Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"))
}

fn resolve_bucket_action(method: &Method, query: &str) -> &'static str {
    if has_query_key(query, "versioning") {
        return "versioning";
    }
    if has_query_key(query, "tagging") {
        return "tagging";
    }
    if has_query_key(query, "cors") {
        return "cors";
    }
    if has_query_key(query, "location") {
        return "list";
    }
    if has_query_key(query, "encryption") {
        return "encryption";
    }
    if has_query_key(query, "lifecycle") {
        return "lifecycle";
    }
    if has_query_key(query, "acl") {
        return "share";
    }
    if has_query_key(query, "policy") || has_query_key(query, "policyStatus") {
        return "policy";
    }
    if has_query_key(query, "replication") {
        return "replication";
    }
    if has_query_key(query, "quota") {
        return "quota";
    }
    if has_query_key(query, "website") {
        return "website";
    }
    if has_query_key(query, "object-lock") {
        return "object_lock";
    }
    if has_query_key(query, "notification") {
        return "notification";
    }
    if has_query_key(query, "logging") {
        return "logging";
    }
    if has_query_key(query, "versions") || has_query_key(query, "uploads") {
        return "list";
    }
    if has_query_key(query, "delete") {
        return "delete";
    }

    match *method {
        Method::GET => "list",
        Method::HEAD => "read",
        Method::PUT => "create_bucket",
        Method::DELETE => "delete_bucket",
        Method::POST => "write",
        _ => "list",
    }
}

fn resolve_object_action(method: &Method, query: &str) -> &'static str {
    if has_query_key(query, "tagging") {
        return if *method == Method::GET { "read" } else { "write" };
    }
    if has_query_key(query, "acl") {
        return if *method == Method::GET { "read" } else { "write" };
    }
    if has_query_key(query, "retention") || has_query_key(query, "legal-hold") {
        return "object_lock";
    }
    if has_query_key(query, "attributes") {
        return "read";
    }
    if has_query_key(query, "uploads") || has_query_key(query, "uploadId") {
        return match *method {
            Method::GET => "read",
            _ => "write",
        };
    }
    if has_query_key(query, "select") {
        return "read";
    }

    match *method {
        Method::GET | Method::HEAD => "read",
        Method::PUT => "write",
        Method::DELETE => "delete",
        Method::POST => "write",
        _ => "read",
    }
}

fn has_query_key(query: &str, key: &str) -> bool {
    if query.is_empty() {
        return false;
    }
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .any(|part| part == key || part.starts_with(&format!("{}=", key)))
}

fn try_auth(state: &AppState, req: &Request) -> AuthResult {
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("AWS4-HMAC-SHA256 ") {
                return verify_sigv4_header(state, req, auth_str);
            }
        }
    }

    let query = req.uri().query().unwrap_or("");
    if query.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256") {
        return verify_sigv4_query(state, req);
    }

    if let (Some(ak), Some(sk)) = (
        req.headers().get("x-access-key").and_then(|v| v.to_str().ok()),
        req.headers().get("x-secret-key").and_then(|v| v.to_str().ok()),
    ) {
        return match state.iam.authenticate(ak, sk) {
            Some(principal) => AuthResult::Ok(principal),
            None => AuthResult::Denied(
                S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch),
            ),
        };
    }

    AuthResult::NoAuth
}

fn verify_sigv4_header(state: &AppState, req: &Request, auth_str: &str) -> AuthResult {
    let parts: Vec<&str> = auth_str
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .unwrap()
        .split(", ")
        .collect();

    if parts.len() != 3 {
        return AuthResult::Denied(
            S3Error::new(S3ErrorCode::InvalidArgument, "Malformed Authorization header"),
        );
    }

    let credential = parts[0].strip_prefix("Credential=").unwrap_or("");
    let signed_headers_str = parts[1].strip_prefix("SignedHeaders=").unwrap_or("");
    let provided_signature = parts[2].strip_prefix("Signature=").unwrap_or("");

    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 {
        return AuthResult::Denied(
            S3Error::new(S3ErrorCode::InvalidArgument, "Malformed credential"),
        );
    }

    let access_key = cred_parts[0];
    let date_stamp = cred_parts[1];
    let region = cred_parts[2];
    let service = cred_parts[3];

    let amz_date = req
        .headers()
        .get("x-amz-date")
        .or_else(|| req.headers().get("date"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if amz_date.is_empty() {
        return AuthResult::Denied(
            S3Error::new(S3ErrorCode::AccessDenied, "Missing Date header"),
        );
    }

    if let Some(err) = check_timestamp_freshness(amz_date, state.config.sigv4_timestamp_tolerance_secs) {
        return AuthResult::Denied(err);
    }

    let secret_key = match state.iam.get_secret_key(access_key) {
        Some(sk) => sk,
        None => {
            return AuthResult::Denied(
                S3Error::from_code(S3ErrorCode::InvalidAccessKeyId),
            );
        }
    };

    let method = req.method().as_str();
    let canonical_uri = req.uri().path();

    let query_params = parse_query_params(req.uri().query().unwrap_or(""));

    let payload_hash = req
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD");

    let signed_headers: Vec<&str> = signed_headers_str.split(';').collect();
    let header_values: Vec<(String, String)> = signed_headers
        .iter()
        .map(|&name| {
            let value = req
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            (name.to_string(), value.to_string())
        })
        .collect();

    let verified = sigv4::verify_sigv4_signature(
        method,
        canonical_uri,
        &query_params,
        signed_headers_str,
        &header_values,
        payload_hash,
        amz_date,
        date_stamp,
        region,
        service,
        &secret_key,
        provided_signature,
    );

    if !verified {
        return AuthResult::Denied(
            S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch),
        );
    }

    match state.iam.get_principal(access_key) {
        Some(p) => AuthResult::Ok(p),
        None => AuthResult::Denied(
            S3Error::from_code(S3ErrorCode::InvalidAccessKeyId),
        ),
    }
}

fn verify_sigv4_query(state: &AppState, req: &Request) -> AuthResult {
    let query = req.uri().query().unwrap_or("");
    let params = parse_query_params(query);
    let param_map: std::collections::HashMap<&str, &str> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let credential = match param_map.get("X-Amz-Credential") {
        Some(c) => *c,
        None => {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::InvalidArgument, "Missing X-Amz-Credential"),
            );
        }
    };

    let signed_headers_str = param_map
        .get("X-Amz-SignedHeaders")
        .copied()
        .unwrap_or("host");
    let provided_signature = match param_map.get("X-Amz-Signature") {
        Some(s) => *s,
        None => {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::InvalidArgument, "Missing X-Amz-Signature"),
            );
        }
    };
    let amz_date = match param_map.get("X-Amz-Date") {
        Some(d) => *d,
        None => {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::InvalidArgument, "Missing X-Amz-Date"),
            );
        }
    };
    let expires_str = match param_map.get("X-Amz-Expires") {
        Some(e) => *e,
        None => {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::InvalidArgument, "Missing X-Amz-Expires"),
            );
        }
    };

    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 {
        return AuthResult::Denied(
            S3Error::new(S3ErrorCode::InvalidArgument, "Malformed credential"),
        );
    }

    let access_key = cred_parts[0];
    let date_stamp = cred_parts[1];
    let region = cred_parts[2];
    let service = cred_parts[3];

    let expires: u64 = match expires_str.parse() {
        Ok(e) => e,
        Err(_) => {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::InvalidArgument, "Invalid X-Amz-Expires"),
            );
        }
    };

    if expires < state.config.presigned_url_min_expiry
        || expires > state.config.presigned_url_max_expiry
    {
        return AuthResult::Denied(
            S3Error::new(S3ErrorCode::InvalidArgument, "X-Amz-Expires out of range"),
        );
    }

    if let Ok(request_time) =
        NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ")
    {
        let request_utc = request_time.and_utc();
        let now = Utc::now();
        let elapsed = (now - request_utc).num_seconds();
        if elapsed > expires as i64 {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::AccessDenied, "Request has expired"),
            );
        }
        if elapsed < -(state.config.sigv4_timestamp_tolerance_secs as i64) {
            return AuthResult::Denied(
                S3Error::new(S3ErrorCode::AccessDenied, "Request is too far in the future"),
            );
        }
    }

    let secret_key = match state.iam.get_secret_key(access_key) {
        Some(sk) => sk,
        None => {
            return AuthResult::Denied(
                S3Error::from_code(S3ErrorCode::InvalidAccessKeyId),
            );
        }
    };

    let method = req.method().as_str();
    let canonical_uri = req.uri().path();

    let query_params_no_sig: Vec<(String, String)> = params
        .iter()
        .filter(|(k, _)| k != "X-Amz-Signature")
        .cloned()
        .collect();

    let payload_hash = "UNSIGNED-PAYLOAD";

    let signed_headers: Vec<&str> = signed_headers_str.split(';').collect();
    let header_values: Vec<(String, String)> = signed_headers
        .iter()
        .map(|&name| {
            let value = req
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            (name.to_string(), value.to_string())
        })
        .collect();

    let verified = sigv4::verify_sigv4_signature(
        method,
        canonical_uri,
        &query_params_no_sig,
        signed_headers_str,
        &header_values,
        payload_hash,
        amz_date,
        date_stamp,
        region,
        service,
        &secret_key,
        provided_signature,
    );

    if !verified {
        return AuthResult::Denied(
            S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch),
        );
    }

    match state.iam.get_principal(access_key) {
        Some(p) => AuthResult::Ok(p),
        None => AuthResult::Denied(
            S3Error::from_code(S3ErrorCode::InvalidAccessKeyId),
        ),
    }
}

fn check_timestamp_freshness(amz_date: &str, tolerance_secs: u64) -> Option<S3Error> {
    let request_time = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ").ok()?;
    let request_utc = request_time.and_utc();
    let now = Utc::now();
    let diff = (now - request_utc).num_seconds().unsigned_abs();

    if diff > tolerance_secs {
        return Some(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Request timestamp too old or too far in the future",
        ));
    }
    None
}

fn parse_query_params(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((
                urlencoding_decode(key),
                urlencoding_decode(value),
            ))
        })
        .collect()
}

fn urlencoding_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

fn error_response(err: S3Error, resource: &str) -> Response {
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let body = err
        .with_resource(resource.to_string())
        .with_request_id(request_id)
        .to_xml();
    (status, [("content-type", "application/xml")], body).into_response()
}
