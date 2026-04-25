use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use chrono::{NaiveDateTime, Utc};
use myfsio_auth::sigv4;
use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_common::types::Principal;
use myfsio_storage::traits::StorageEngine;
use serde_json::Value;
use std::time::Instant;
use tokio::io::AsyncReadExt;

use crate::middleware::sha_body::{is_hex_sha256, Sha256VerifyBody};
use crate::services::acl::acl_from_bucket_config;
use crate::state::AppState;

fn wrap_body_for_sha256_verification(req: &mut Request) {
    let declared = match req
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return,
    };
    if !is_hex_sha256(&declared) {
        return;
    }
    let is_chunked = req
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("aws-chunked"))
        .unwrap_or(false);
    if is_chunked {
        return;
    }
    let body = std::mem::replace(req.body_mut(), axum::body::Body::empty());
    let wrapped = Sha256VerifyBody::new(body, declared);
    *req.body_mut() = axum::body::Body::new(wrapped);
}

#[derive(Clone, Debug)]
struct OriginalCanonicalPath(String);

fn website_error_response(
    status: StatusCode,
    body: Option<Vec<u8>>,
    content_type: &str,
    include_body: bool,
) -> Response {
    let (body, content_type) = match body {
        Some(body) => (body, content_type),
        None => (
            default_website_error_body(status).into_bytes(),
            "text/html; charset=utf-8",
        ),
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    headers.insert(
        header::CONTENT_LENGTH,
        body.len().to_string().parse().unwrap(),
    );
    if include_body {
        (status, headers, body.clone()).into_response()
    } else {
        (status, headers).into_response()
    }
}

fn default_website_error_body(status: StatusCode) -> String {
    let code = status.as_u16();
    if status == StatusCode::NOT_FOUND {
        "<h1>404 page not found</h1>".to_string()
    } else {
        let reason = status.canonical_reason().unwrap_or("Error");
        format!("{code} {reason}")
    }
}

fn parse_range_header(range_header: &str, total_size: u64) -> Option<(u64, u64)> {
    let range_spec = range_header.strip_prefix("bytes=")?;
    if let Some(suffix) = range_spec.strip_prefix('-') {
        let suffix_len: u64 = suffix.parse().ok()?;
        if suffix_len == 0 || suffix_len > total_size {
            return None;
        }
        return Some((total_size - suffix_len, total_size - 1));
    }

    let (start_str, end_str) = range_spec.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;
    let end = if end_str.is_empty() {
        total_size.saturating_sub(1)
    } else {
        end_str
            .parse::<u64>()
            .ok()?
            .min(total_size.saturating_sub(1))
    };

    if start > end || start >= total_size {
        return None;
    }
    Some((start, end))
}

fn website_content_type(key: &str, metadata: &std::collections::HashMap<String, String>) -> String {
    metadata
        .get("__content_type__")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| {
            mime_guess::from_path(key)
                .first_raw()
                .unwrap_or("application/octet-stream")
                .to_string()
        })
}

fn parse_website_config(value: &Value) -> Option<(String, Option<String>)> {
    match value {
        Value::Object(map) => {
            let index_document = map
                .get("index_document")
                .or_else(|| map.get("IndexDocument"))
                .and_then(|v| v.as_str())
                .unwrap_or("index.html")
                .to_string();
            let error_document = map
                .get("error_document")
                .or_else(|| map.get("ErrorDocument"))
                .and_then(|v| v.as_str())
                .map(|v| v.to_string());
            Some((index_document, error_document))
        }
        Value::String(raw) => {
            if let Ok(json) = serde_json::from_str::<Value>(raw) {
                return parse_website_config(&json);
            }
            let doc = roxmltree::Document::parse(raw).ok()?;
            let index_document = doc
                .descendants()
                .find(|node| node.is_element() && node.tag_name().name() == "Suffix")
                .and_then(|node| node.text())
                .map(|text| text.trim().to_string())
                .filter(|text| !text.is_empty())
                .unwrap_or_else(|| "index.html".to_string());
            let error_document = doc
                .descendants()
                .find(|node| node.is_element() && node.tag_name().name() == "Key")
                .and_then(|node| node.text())
                .map(|text| text.trim().to_string())
                .filter(|text| !text.is_empty());
            Some((index_document, error_document))
        }
        _ => None,
    }
}

async fn serve_website_document(
    state: &AppState,
    bucket: &str,
    key: &str,
    method: &axum::http::Method,
    range_header: Option<&str>,
    status: StatusCode,
) -> Option<Response> {
    let metadata = state.storage.get_object_metadata(bucket, key).await.ok()?;
    let (meta, mut reader) = state.storage.get_object(bucket, key).await.ok()?;
    let content_type = website_content_type(key, &metadata);

    if method == axum::http::Method::HEAD {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
        headers.insert(
            header::CONTENT_LENGTH,
            meta.size.to_string().parse().unwrap(),
        );
        headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
        return Some((status, headers).into_response());
    }

    let mut bytes = Vec::new();
    if reader.read_to_end(&mut bytes).await.is_err() {
        return None;
    }

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());

    if status == StatusCode::OK {
        if let Some(range_header) = range_header {
            let Some((start, end)) = parse_range_header(range_header, bytes.len() as u64) else {
                let mut range_headers = HeaderMap::new();
                range_headers.insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{}", bytes.len()).parse().unwrap(),
                );
                return Some((StatusCode::RANGE_NOT_SATISFIABLE, range_headers).into_response());
            };
            let body = bytes[start as usize..=end as usize].to_vec();
            headers.insert(
                header::CONTENT_RANGE,
                format!("bytes {}-{}/{}", start, end, bytes.len())
                    .parse()
                    .unwrap(),
            );
            headers.insert(
                header::CONTENT_LENGTH,
                body.len().to_string().parse().unwrap(),
            );
            return Some((StatusCode::PARTIAL_CONTENT, headers, body).into_response());
        }
    }

    headers.insert(
        header::CONTENT_LENGTH,
        bytes.len().to_string().parse().unwrap(),
    );
    Some((status, headers, bytes).into_response())
}

async fn maybe_serve_website(
    state: &AppState,
    method: Method,
    host: String,
    uri_path: String,
    range_header: Option<String>,
) -> Option<Response> {
    if !state.config.website_hosting_enabled {
        return None;
    }
    if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
        return None;
    }
    let request_path = uri_path.trim_start_matches('/').to_string();
    let include_error_body = method != axum::http::Method::HEAD;
    let store = state.website_domains.as_ref()?;
    let bucket = store.get_bucket(&host)?;
    if !matches!(state.storage.bucket_exists(&bucket).await, Ok(true)) {
        return Some(website_error_response(
            StatusCode::NOT_FOUND,
            None,
            "text/plain; charset=utf-8",
            include_error_body,
        ));
    }

    let bucket_config = state.storage.get_bucket_config(&bucket).await.ok()?;
    let Some(website_config) = bucket_config.website.as_ref() else {
        return Some(website_error_response(
            StatusCode::NOT_FOUND,
            None,
            "text/plain; charset=utf-8",
            include_error_body,
        ));
    };
    let Some((index_document, error_document)) = parse_website_config(website_config) else {
        return Some(website_error_response(
            StatusCode::NOT_FOUND,
            None,
            "text/plain; charset=utf-8",
            include_error_body,
        ));
    };

    let mut object_key = if request_path.is_empty() || uri_path.ends_with('/') {
        if request_path.is_empty() {
            index_document.clone()
        } else {
            format!("{}{}", request_path, index_document)
        }
    } else {
        request_path.clone()
    };

    let exists = state
        .storage
        .head_object(&bucket, &object_key)
        .await
        .is_ok();
    if !exists && !request_path.is_empty() && !request_path.ends_with('/') {
        let alternate = format!("{}/{}", request_path, index_document);
        if state.storage.head_object(&bucket, &alternate).await.is_ok() {
            object_key = alternate;
        } else if let Some(error_key) = error_document.as_deref() {
            return serve_website_document(
                state,
                &bucket,
                error_key,
                &method,
                range_header.as_deref(),
                StatusCode::NOT_FOUND,
            )
            .await
            .or_else(|| {
                Some(website_error_response(
                    StatusCode::NOT_FOUND,
                    None,
                    "text/plain; charset=utf-8",
                    include_error_body,
                ))
            });
        } else {
            return Some(website_error_response(
                StatusCode::NOT_FOUND,
                None,
                "text/plain; charset=utf-8",
                include_error_body,
            ));
        }
    } else if !exists {
        if let Some(error_key) = error_document.as_deref() {
            return serve_website_document(
                state,
                &bucket,
                error_key,
                &method,
                range_header.as_deref(),
                StatusCode::NOT_FOUND,
            )
            .await
            .or_else(|| {
                Some(website_error_response(
                    StatusCode::NOT_FOUND,
                    None,
                    "text/plain; charset=utf-8",
                    include_error_body,
                ))
            });
        }
        return Some(website_error_response(
            StatusCode::NOT_FOUND,
            None,
            "text/plain; charset=utf-8",
            include_error_body,
        ));
    }

    serve_website_document(
        state,
        &bucket,
        &object_key,
        &method,
        range_header.as_deref(),
        StatusCode::OK,
    )
    .await
}

fn virtual_host_candidate(host: &str) -> Option<String> {
    let (candidate, _) = host.split_once('.')?;
    if candidate.is_empty() || matches!(candidate, "www" | "s3" | "api" | "admin" | "kms") {
        return None;
    }
    if myfsio_storage::validation::validate_bucket_name(candidate).is_some() {
        return None;
    }
    Some(candidate.to_string())
}

async fn virtual_host_bucket(
    state: &AppState,
    host: &str,
    path: &str,
    method: &Method,
) -> Option<String> {
    if path.starts_with("/ui")
        || path.starts_with("/admin")
        || path.starts_with("/kms")
        || path.starts_with("/myfsio")
    {
        return None;
    }

    let bucket = virtual_host_candidate(host)?;
    if path == format!("/{}", bucket) || path.starts_with(&format!("/{}/", bucket)) {
        return None;
    }

    match state.storage.bucket_exists(&bucket).await {
        Ok(true) => Some(bucket),
        Ok(false) if *method == Method::PUT && path == "/" => Some(bucket),
        _ => None,
    }
}

fn rewrite_uri_for_virtual_host(uri: &Uri, bucket: &str) -> Option<Uri> {
    let path = uri.path();
    let rewritten_path = if path == "/" {
        format!("/{}/", bucket)
    } else {
        format!("/{}{}", bucket, path)
    };
    let path_and_query = match uri.query() {
        Some(query) => format!("{}?{}", rewritten_path, query),
        None => rewritten_path,
    };

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(path_and_query.parse().ok()?);
    Uri::from_parts(parts).ok()
}

fn sigv4_canonical_path(req: &Request) -> &str {
    req.extensions()
        .get::<OriginalCanonicalPath>()
        .map(|path| path.0.as_str())
        .unwrap_or_else(|| req.uri().path())
}

pub async fn auth_layer(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let start = Instant::now();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let method = req.method().clone();
    let query = uri.query().unwrap_or("").to_string();
    let copy_source = req
        .headers()
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .map(|value| value.to_string());
    let endpoint_type = classify_endpoint(&path, &query);
    let bytes_in = req
        .headers()
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())
        .map(|value| value.trim().to_ascii_lowercase());
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let response = if path == "/myfsio/health" {
        next.run(req).await
    } else if let Some(response) = maybe_serve_website(
        &state,
        method.clone(),
        host.clone().unwrap_or_default(),
        path.clone(),
        range_header,
    )
    .await
    {
        response
    } else {
        let auth_path = if let Some(bucket) =
            virtual_host_bucket(&state, host.as_deref().unwrap_or_default(), &path, &method).await
        {
            if let Some(rewritten) = rewrite_uri_for_virtual_host(req.uri(), &bucket) {
                req.extensions_mut()
                    .insert(OriginalCanonicalPath(path.clone()));
                *req.uri_mut() = rewritten;
                req.uri().path().to_string()
            } else {
                path.clone()
            }
        } else {
            path.clone()
        };

        match try_auth(&state, &req) {
            AuthResult::NoAuth => match authorize_request(
                &state,
                None,
                &method,
                &auth_path,
                &query,
                copy_source.as_deref(),
            )
            .await
            {
                Ok(()) => next.run(req).await,
                Err(err) => error_response(err, &auth_path),
            },
            AuthResult::Ok(principal) => {
                if let Err(err) = authorize_request(
                    &state,
                    Some(&principal),
                    &method,
                    &auth_path,
                    &query,
                    copy_source.as_deref(),
                )
                .await
                {
                    error_response(err, &auth_path)
                } else {
                    req.extensions_mut().insert(principal);
                    wrap_body_for_sha256_verification(&mut req);
                    next.run(req).await
                }
            }
            AuthResult::Denied(err) => error_response(err, &auth_path),
        }
    };

    if let Some(metrics) = &state.metrics {
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let status = response.status().as_u16();
        let bytes_out = response
            .headers()
            .get(axum::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        let error_code = if status >= 400 {
            Some(s3_code_for_status(status))
        } else {
            None
        };
        metrics.record_request(
            method.as_str(),
            endpoint_type,
            status,
            latency_ms,
            bytes_in,
            bytes_out,
            error_code,
        );
    }

    response
}

fn classify_endpoint(path: &str, query: &str) -> &'static str {
    if path == "/" {
        return "list_buckets";
    }
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if segments.is_empty() {
        return "other";
    }
    if segments.len() == 1 {
        if query.contains("uploads") {
            return "list_multipart_uploads";
        }
        if query.contains("versioning") {
            return "bucket_versioning";
        }
        if query.contains("lifecycle") {
            return "bucket_lifecycle";
        }
        if query.contains("policy") {
            return "bucket_policy";
        }
        if query.contains("website") {
            return "bucket_website";
        }
        if query.contains("encryption") {
            return "bucket_encryption";
        }
        if query.contains("replication") {
            return "bucket_replication";
        }
        return "bucket";
    }
    if query.contains("uploadId") {
        return "multipart_part";
    }
    if query.contains("uploads") {
        return "multipart_init";
    }
    if query.contains("tagging") {
        return "object_tagging";
    }
    if query.contains("acl") {
        return "object_acl";
    }
    "object"
}

fn s3_code_for_status(status: u16) -> &'static str {
    match status {
        400 => "BadRequest",
        401 => "Unauthorized",
        403 => "AccessDenied",
        404 => "NotFound",
        405 => "MethodNotAllowed",
        409 => "Conflict",
        411 => "MissingContentLength",
        412 => "PreconditionFailed",
        413 => "EntityTooLarge",
        416 => "InvalidRange",
        500 => "InternalError",
        501 => "NotImplemented",
        503 => "ServiceUnavailable",
        _ => "Other",
    }
}

enum AuthResult {
    Ok(Principal),
    Denied(S3Error),
    NoAuth,
}

async fn authorize_request(
    state: &AppState,
    principal: Option<&Principal>,
    method: &Method,
    path: &str,
    query: &str,
    copy_source: Option<&str>,
) -> Result<(), S3Error> {
    if path == "/myfsio/health" {
        return Ok(());
    }
    if path == "/" {
        if let Some(principal) = principal {
            if state.iam.authorize(principal, None, "list", None) {
                return Ok(());
            }
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
        }
        return Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Missing credentials",
        ));
    }

    if path.starts_with("/admin/") || path.starts_with("/kms/") {
        return if principal.is_some() {
            Ok(())
        } else {
            Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Missing credentials",
            ))
        };
    }

    let mut segments = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty());
    let bucket = match segments.next() {
        Some(b) => b,
        None => {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
        }
    };
    let remaining: Vec<&str> = segments.collect();

    if remaining.is_empty() {
        let action = resolve_bucket_action(method, query);
        return authorize_action(state, principal, bucket, action, None).await;
    }

    let object_key = remaining.join("/");
    if *method == Method::PUT {
        if let Some(copy_source) = copy_source {
            let source = copy_source.strip_prefix('/').unwrap_or(copy_source);
            if let Some((src_bucket, src_key)) = source.split_once('/') {
                let source_allowed =
                    authorize_action(state, principal, src_bucket, "read", Some(src_key))
                        .await
                        .is_ok();
                let dest_allowed =
                    authorize_action(state, principal, bucket, "write", Some(&object_key))
                        .await
                        .is_ok();
                if source_allowed && dest_allowed {
                    return Ok(());
                }
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
            }
        }
    }

    let action = resolve_object_action(method, query);
    authorize_action(state, principal, bucket, action, Some(&object_key)).await
}

async fn authorize_action(
    state: &AppState,
    principal: Option<&Principal>,
    bucket: &str,
    action: &str,
    object_key: Option<&str>,
) -> Result<(), S3Error> {
    let iam_allowed = principal
        .map(|principal| {
            state
                .iam
                .authorize(principal, Some(bucket), action, object_key)
        })
        .unwrap_or(false);
    let policy_decision = evaluate_bucket_policy(
        state,
        principal.map(|principal| principal.access_key.as_str()),
        bucket,
        action,
        object_key,
    )
    .await;

    if matches!(policy_decision, PolicyDecision::Deny) {
        return Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Access denied by bucket policy",
        ));
    }
    if iam_allowed || matches!(policy_decision, PolicyDecision::Allow) {
        return Ok(());
    }
    if evaluate_bucket_acl(
        state,
        bucket,
        principal.map(|principal| principal.access_key.as_str()),
        action,
        principal.is_some(),
    )
    .await
    {
        return Ok(());
    }

    if principal.is_some() {
        Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"))
    } else {
        Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Missing credentials",
        ))
    }
}

async fn evaluate_bucket_acl(
    state: &AppState,
    bucket: &str,
    principal_id: Option<&str>,
    action: &str,
    is_authenticated: bool,
) -> bool {
    let config = match state.storage.get_bucket_config(bucket).await {
        Ok(config) => config,
        Err(_) => return false,
    };
    let Some(value) = config.acl.as_ref() else {
        return false;
    };
    let Some(acl) = acl_from_bucket_config(value) else {
        return false;
    };
    acl.allowed_actions(principal_id, is_authenticated)
        .contains(action)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyDecision {
    Allow,
    Deny,
    Neutral,
}

async fn evaluate_bucket_policy(
    state: &AppState,
    access_key: Option<&str>,
    bucket: &str,
    action: &str,
    object_key: Option<&str>,
) -> PolicyDecision {
    let config = match state.storage.get_bucket_config(bucket).await {
        Ok(config) => config,
        Err(_) => return PolicyDecision::Neutral,
    };
    let policy: &Value = match config.policy.as_ref() {
        Some(policy) => policy,
        None => return PolicyDecision::Neutral,
    };
    let mut decision = PolicyDecision::Neutral;

    match policy.get("Statement") {
        Some(Value::Array(items)) => {
            for statement in items.iter() {
                match evaluate_policy_statement(statement, access_key, bucket, action, object_key) {
                    PolicyDecision::Deny => return PolicyDecision::Deny,
                    PolicyDecision::Allow => decision = PolicyDecision::Allow,
                    PolicyDecision::Neutral => {}
                }
            }
        }
        Some(statement) => {
            return evaluate_policy_statement(statement, access_key, bucket, action, object_key);
        }
        None => return PolicyDecision::Neutral,
    }

    decision
}

fn evaluate_policy_statement(
    statement: &Value,
    access_key: Option<&str>,
    bucket: &str,
    action: &str,
    object_key: Option<&str>,
) -> PolicyDecision {
    if !statement_matches_principal(statement, access_key)
        || !statement_matches_action(statement, action)
        || !statement_matches_resource(statement, bucket, object_key)
    {
        return PolicyDecision::Neutral;
    }

    match statement
        .get("Effect")
        .and_then(|value| value.as_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("deny") => PolicyDecision::Deny,
        Some("allow") => PolicyDecision::Allow,
        _ => PolicyDecision::Neutral,
    }
}

fn statement_matches_principal(statement: &Value, access_key: Option<&str>) -> bool {
    match statement.get("Principal") {
        Some(principal) => principal_value_matches(principal, access_key),
        None => false,
    }
}

fn principal_value_matches(value: &Value, access_key: Option<&str>) -> bool {
    match value {
        Value::String(token) => token == "*" || access_key == Some(token.as_str()),
        Value::Array(items) => items
            .iter()
            .any(|item| principal_value_matches(item, access_key)),
        Value::Object(map) => map
            .values()
            .any(|item| principal_value_matches(item, access_key)),
        _ => false,
    }
}

fn statement_matches_action(statement: &Value, action: &str) -> bool {
    match statement.get("Action") {
        Some(Value::String(value)) => policy_action_matches(value, action),
        Some(Value::Array(items)) => items.iter().any(|item| {
            item.as_str()
                .map(|value| policy_action_matches(value, action))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn policy_action_matches(policy_action: &str, requested_action: &str) -> bool {
    let normalized_policy_action = normalize_policy_action(policy_action);
    normalized_policy_action == "*" || normalized_policy_action == requested_action
}

fn normalize_policy_action(action: &str) -> String {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized == "*" {
        return normalized;
    }
    match normalized.as_str() {
        "s3:listbucket"
        | "s3:listallmybuckets"
        | "s3:listbucketversions"
        | "s3:listmultipartuploads"
        | "s3:listparts" => "list".to_string(),
        "s3:getobject"
        | "s3:getobjectversion"
        | "s3:getobjecttagging"
        | "s3:getobjectversiontagging"
        | "s3:getobjectacl"
        | "s3:getbucketversioning"
        | "s3:headobject"
        | "s3:headbucket" => "read".to_string(),
        "s3:putobject"
        | "s3:createbucket"
        | "s3:putobjecttagging"
        | "s3:putbucketversioning"
        | "s3:createmultipartupload"
        | "s3:uploadpart"
        | "s3:completemultipartupload"
        | "s3:abortmultipartupload"
        | "s3:copyobject" => "write".to_string(),
        "s3:deleteobject"
        | "s3:deleteobjectversion"
        | "s3:deletebucket"
        | "s3:deleteobjecttagging" => "delete".to_string(),
        "s3:putobjectacl" | "s3:putbucketacl" | "s3:getbucketacl" => "share".to_string(),
        "s3:putbucketpolicy" | "s3:getbucketpolicy" | "s3:deletebucketpolicy" => {
            "policy".to_string()
        }
        "s3:getreplicationconfiguration"
        | "s3:putreplicationconfiguration"
        | "s3:deletereplicationconfiguration"
        | "s3:replicateobject"
        | "s3:replicatetags"
        | "s3:replicatedelete" => "replication".to_string(),
        "s3:getlifecycleconfiguration"
        | "s3:putlifecycleconfiguration"
        | "s3:deletelifecycleconfiguration"
        | "s3:getbucketlifecycle"
        | "s3:putbucketlifecycle" => "lifecycle".to_string(),
        "s3:getbucketcors" | "s3:putbucketcors" | "s3:deletebucketcors" => "cors".to_string(),
        other => other.to_string(),
    }
}

fn statement_matches_resource(statement: &Value, bucket: &str, object_key: Option<&str>) -> bool {
    match statement.get("Resource") {
        Some(Value::String(resource)) => resource_matches(resource, bucket, object_key),
        Some(Value::Array(items)) => items.iter().any(|item| {
            item.as_str()
                .map(|resource| resource_matches(resource, bucket, object_key))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn resource_matches(resource: &str, bucket: &str, object_key: Option<&str>) -> bool {
    let remainder = match resource.strip_prefix("arn:aws:s3:::") {
        Some(value) => value,
        None => return false,
    };

    match remainder.split_once('/') {
        Some((resource_bucket, resource_key)) => object_key
            .map(|key| wildcard_match(bucket, resource_bucket) && wildcard_match(key, resource_key))
            .unwrap_or(false),
        None => object_key.is_none() && wildcard_match(bucket, remainder),
    }
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    let value = value.as_bytes();
    let pattern = pattern.as_bytes();
    let mut value_idx = 0usize;
    let mut pattern_idx = 0usize;
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while value_idx < value.len() {
        if pattern_idx < pattern.len()
            && (pattern[pattern_idx] == b'?'
                || pattern[pattern_idx].eq_ignore_ascii_case(&value[value_idx]))
        {
            value_idx += 1;
            pattern_idx += 1;
        } else if pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
            star_idx = Some(pattern_idx);
            pattern_idx += 1;
            match_idx = value_idx;
        } else if let Some(star) = star_idx {
            pattern_idx = star + 1;
            match_idx += 1;
            value_idx = match_idx;
        } else {
            return false;
        }
    }

    while pattern_idx < pattern.len() && pattern[pattern_idx] == b'*' {
        pattern_idx += 1;
    }

    pattern_idx == pattern.len()
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
        return if *method == Method::GET {
            "read"
        } else {
            "write"
        };
    }
    if has_query_key(query, "acl") {
        return if *method == Method::GET {
            "read"
        } else {
            "write"
        };
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
        req.headers()
            .get("x-access-key")
            .and_then(|v| v.to_str().ok()),
        req.headers()
            .get("x-secret-key")
            .and_then(|v| v.to_str().ok()),
    ) {
        return match state.iam.authenticate(ak, sk) {
            Some(principal) => AuthResult::Ok(principal),
            None => AuthResult::Denied(S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch)),
        };
    }

    AuthResult::NoAuth
}

fn verify_sigv4_header(state: &AppState, req: &Request, auth_str: &str) -> AuthResult {
    let parts: Vec<&str> = auth_str
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .unwrap()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() != 3 {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Malformed Authorization header",
        ));
    }

    let mut credential: &str = "";
    let mut signed_headers_str: &str = "";
    let mut provided_signature: &str = "";
    for part in &parts {
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = v;
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers_str = v;
        } else if let Some(v) = part.strip_prefix("Signature=") {
            provided_signature = v;
        }
    }
    if credential.is_empty() || signed_headers_str.is_empty() || provided_signature.is_empty() {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Malformed Authorization header",
        ));
    }

    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Malformed credential",
        ));
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
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Missing Date header",
        ));
    }

    if let Some(err) =
        check_timestamp_freshness(amz_date, state.config.sigv4_timestamp_tolerance_secs)
    {
        return AuthResult::Denied(err);
    }

    let secret_key = match state.iam.get_secret_key(access_key) {
        Some(sk) => sk,
        None => {
            return AuthResult::Denied(S3Error::from_code(S3ErrorCode::InvalidAccessKeyId));
        }
    };

    let method = req.method().as_str();
    let canonical_uri = sigv4_canonical_path(req);

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
        return AuthResult::Denied(S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch));
    }

    match state.iam.get_principal(access_key) {
        Some(p) => AuthResult::Ok(p),
        None => AuthResult::Denied(S3Error::from_code(S3ErrorCode::InvalidAccessKeyId)),
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
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing X-Amz-Credential",
            ));
        }
    };

    let signed_headers_str = param_map
        .get("X-Amz-SignedHeaders")
        .copied()
        .unwrap_or("host");
    let provided_signature = match param_map.get("X-Amz-Signature") {
        Some(s) => *s,
        None => {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing X-Amz-Signature",
            ));
        }
    };
    let amz_date = match param_map.get("X-Amz-Date") {
        Some(d) => *d,
        None => {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing X-Amz-Date",
            ));
        }
    };
    let expires_str = match param_map.get("X-Amz-Expires") {
        Some(e) => *e,
        None => {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Missing X-Amz-Expires",
            ));
        }
    };

    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "Malformed credential",
        ));
    }

    let access_key = cred_parts[0];
    let date_stamp = cred_parts[1];
    let region = cred_parts[2];
    let service = cred_parts[3];

    let expires: u64 = match expires_str.parse() {
        Ok(e) => e,
        Err(_) => {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "Invalid X-Amz-Expires",
            ));
        }
    };

    if expires < state.config.presigned_url_min_expiry
        || expires > state.config.presigned_url_max_expiry
    {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::InvalidArgument,
            "X-Amz-Expires out of range",
        ));
    }

    if let Ok(request_time) = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        let request_utc = request_time.and_utc();
        let now = Utc::now();
        let elapsed = (now - request_utc).num_seconds();
        if elapsed > expires as i64 {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Request has expired",
            ));
        }
        if elapsed < -(state.config.sigv4_timestamp_tolerance_secs as i64) {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::RequestTimeTooSkewed,
                "Request is too far in the future",
            ));
        }
    }

    let secret_key = match state.iam.get_secret_key(access_key) {
        Some(sk) => sk,
        None => {
            return AuthResult::Denied(S3Error::from_code(S3ErrorCode::InvalidAccessKeyId));
        }
    };

    let method = req.method().as_str();
    let canonical_uri = sigv4_canonical_path(req);

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
        return AuthResult::Denied(S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch));
    }

    match state.iam.get_principal(access_key) {
        Some(p) => AuthResult::Ok(p),
        None => AuthResult::Denied(S3Error::from_code(S3ErrorCode::InvalidAccessKeyId)),
    }
}

fn check_timestamp_freshness(amz_date: &str, tolerance_secs: u64) -> Option<S3Error> {
    let request_time = NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ").ok()?;
    let request_utc = request_time.and_utc();
    let now = Utc::now();
    let diff = (now - request_utc).num_seconds().unsigned_abs();

    if diff > tolerance_secs {
        return Some(S3Error::new(
            S3ErrorCode::RequestTimeTooSkewed,
            format!(
                "The difference between the request time and the server's time is too large ({}s, tolerance {}s)",
                diff, tolerance_secs
            ),
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
            Some((urlencoding_decode(key), urlencoding_decode(value)))
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
    let code_str = err.code.as_str();
    let body = err
        .with_resource(resource.to_string())
        .with_request_id(request_id)
        .to_xml();
    (
        status,
        [
            ("content-type", "application/xml"),
            ("x-amz-error-code", code_str),
        ],
        body,
    )
        .into_response()
}
