use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use chrono::{NaiveDateTime, Utc};
use myfsio_auth::policy::{self, RequestContext};
use myfsio_auth::s3_action::{wildcard_match, wildcard_match_case_sensitive};
use myfsio_auth::sigv4;
use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_common::types::Principal;
use myfsio_storage::traits::StorageEngine;
use serde_json::Value;
use std::time::Instant;

use crate::handlers::object_read;
use crate::middleware::sha_body::{is_hex_sha256, Sha256VerifyBody};
use crate::services::acl::acl_from_bucket_config;
use crate::services::peer_nonce::NonceRecordOutcome;
use crate::state::AppState;

tokio::task_local! {
    pub(crate) static REQUEST_CONTEXT: RequestContext;
}

pub(crate) fn current_request_context(principal: Option<&Principal>) -> RequestContext {
    REQUEST_CONTEXT
        .try_with(|ctx| ctx.clone())
        .unwrap_or_else(|_| RequestContext::for_principal(principal))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamingPayloadVariant {
    SignedPayload,
    SignedPayloadTrailer,
}

#[derive(Clone, Debug)]
pub struct StreamingSigV4Context {
    pub signing_key: Vec<u8>,
    pub timestamp: String,
    pub credential_scope: String,
    pub seed_signature: String,
    pub payload_variant: StreamingPayloadVariant,
}

fn wrap_body_for_sha256_verification(req: &mut Request, strict_streaming_sigv4: bool) {
    let declared = match req
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return,
    };

    let upper = declared.to_ascii_uppercase();
    let is_streaming_signed = upper == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        || upper == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
    let is_streaming_unsigned = upper == "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
    let is_streaming = is_streaming_signed || is_streaming_unsigned;

    if is_streaming {
        if is_streaming_signed && !strict_streaming_sigv4 {
            static STREAMING_SIGV4_WARN: std::sync::Once = std::sync::Once::new();
            STREAMING_SIGV4_WARN.call_once(|| {
                tracing::warn!(
                    payload_type = %upper,
                    "Accepting streaming SigV4 requests without per-chunk signature validation because STRICT_STREAMING_SIGV4=false"
                );
            });
        }
        return;
    }

    if !is_hex_sha256(&declared) {
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

fn apply_website_object_headers(headers: &mut HeaderMap, meta: &myfsio_common::types::ObjectMeta) {
    if let Some(ref etag) = meta.etag {
        if let Ok(value) = format!("\"{}\"", etag).parse() {
            headers.insert(header::ETAG, value);
        }
    }
    if let Ok(value) = meta
        .last_modified
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
        .parse()
    {
        headers.insert(header::LAST_MODIFIED, value);
    }
    if let Some(enc_info) =
        myfsio_crypto::encryption::EncryptionMetadata::from_metadata(&meta.internal_metadata)
    {
        if let Ok(value) = enc_info.algorithm.as_str().parse() {
            headers.insert("x-amz-server-side-encryption", value);
        }
    }
    for (k, v) in &meta.metadata {
        if let Ok(header_val) = v.parse() {
            if let Ok(name) = format!("x-amz-meta-{}", k).parse::<axum::http::HeaderName>() {
                headers.insert(name, header_val);
            }
        }
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
    let content_type = website_content_type(key, &metadata);
    let include_body = method != axum::http::Method::HEAD;

    if method == axum::http::Method::HEAD {
        let meta = state.storage.head_object(bucket, key).await.ok()?;
        if object_read::requires_customer_key(&meta) {
            return Some(website_error_response(
                StatusCode::FORBIDDEN,
                None,
                "text/plain; charset=utf-8",
                include_body,
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
        headers.insert(
            header::CONTENT_LENGTH,
            object_read::plaintext_size(&meta)
                .to_string()
                .parse()
                .unwrap(),
        );
        headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
        apply_website_object_headers(&mut headers, &meta);
        return Some((status, headers).into_response());
    }

    let range = match status {
        StatusCode::OK => range_header,
        _ => None,
    };
    let window = range.and_then(object_read::parse_range_hint);
    let snapshot = object_read::snapshot_object_for_read(state, bucket, key, None, window)
        .await
        .ok()?;
    if object_read::requires_customer_key(&snapshot.meta) {
        snapshot.discard().await;
        return Some(website_error_response(
            StatusCode::FORBIDDEN,
            None,
            "text/plain; charset=utf-8",
            include_body,
        ));
    }

    let served = match object_read::serve_object_data(
        state,
        snapshot,
        range,
        &HeaderMap::new(),
        Some((bucket, key)),
    )
    .await
    {
        Ok(served) => served,
        Err(object_read::ObjectReadError::RangeNotSatisfiable(total)) => {
            let mut range_headers = HeaderMap::new();
            range_headers.insert(
                header::CONTENT_RANGE,
                format!("bytes */{}", total).parse().unwrap(),
            );
            return Some((StatusCode::RANGE_NOT_SATISFIABLE, range_headers).into_response());
        }
        Err(_) => return None,
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    apply_website_object_headers(&mut headers, &served.meta);
    headers.insert(
        header::CONTENT_LENGTH,
        served.content_length.to_string().parse().unwrap(),
    );

    if let Some((start, end)) = served.range {
        headers.insert(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, served.total_size)
                .parse()
                .unwrap(),
        );
        return Some((StatusCode::PARTIAL_CONTENT, headers, served.body).into_response());
    }

    Some((status, headers, served.body).into_response())
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
    if myfsio_storage::validation::is_reserved_bucket_name(&bucket) {
        return Some(website_error_response(
            StatusCode::NOT_FOUND,
            None,
            "text/plain; charset=utf-8",
            include_error_body,
        ));
    }
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
    if path == "/ui"
        || path.starts_with("/ui/")
        || path == "/myfsio"
        || path.starts_with("/myfsio/")
    {
        return None;
    }

    let bucket = virtual_host_candidate(host)?;
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

fn is_website_request(state: &AppState, method: &Method, host: &str) -> bool {
    state.config.website_hosting_enabled
        && (*method == Method::GET || *method == Method::HEAD)
        && state
            .website_domains
            .as_ref()
            .is_some_and(|store| store.get_bucket(host).is_some())
}

pub async fn virtual_host_rewrite_layer(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(':').next())
        .map(|value| value.trim().to_ascii_lowercase());

    if let Some(host) = host {
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        if !is_website_request(&state, &method, &host) {
            if let Some(bucket) = virtual_host_bucket(&state, &host, &path, &method).await {
                if let Some(rewritten) = rewrite_uri_for_virtual_host(req.uri(), &bucket) {
                    req.extensions_mut().insert(OriginalCanonicalPath(path));
                    *req.uri_mut() = rewritten;
                }
            }
        }
    }

    next.run(req).await
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
        let auth_path = path.clone();

        match try_auth(&state, &req) {
            AuthResult::NoAuth => {
                let ctx = build_request_context(&state, &req, None);
                match authorize_request(
                    &state,
                    None,
                    &method,
                    &auth_path,
                    &query,
                    copy_source.as_deref(),
                    &ctx,
                )
                .await
                {
                    Ok(()) => REQUEST_CONTEXT.scope(ctx, next.run(req)).await,
                    Err(err) => error_response(err, &auth_path),
                }
            }
            AuthResult::Ok(principal, streaming_context) => {
                let ctx = build_request_context(&state, &req, Some(&principal));
                if let Err(err) = authorize_request(
                    &state,
                    Some(&principal),
                    &method,
                    &auth_path,
                    &query,
                    copy_source.as_deref(),
                    &ctx,
                )
                .await
                {
                    error_response(err, &auth_path)
                } else {
                    if let Some(registry) = state.site_registry.as_ref() {
                        if registry.is_peer_inbound_access_key(&principal.access_key) {
                            req.extensions_mut()
                                .insert(crate::middleware::ReplicationPeerRequest);
                        }
                    }
                    req.extensions_mut().insert(principal);
                    if let Some(context) = streaming_context {
                        req.extensions_mut().insert(context);
                    }
                    wrap_body_for_sha256_verification(
                        &mut req,
                        state.config.strict_streaming_sigv4,
                    );
                    REQUEST_CONTEXT.scope(ctx, next.run(req)).await
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
            Some(
                response
                    .headers()
                    .get("x-amz-error-code")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
                    .unwrap_or_else(|| s3_code_for_status(status).to_string()),
            )
        } else {
            None
        };
        let request_id = response
            .headers()
            .get("x-amz-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let (bucket, key) = bucket_key_from_path(&path);
        metrics.record_request(
            method.as_str(),
            endpoint_type,
            status,
            latency_ms,
            bytes_in,
            bytes_out,
            error_code.as_deref(),
            bucket.as_deref(),
            key.as_deref(),
            request_id.as_deref(),
            "api",
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

fn bucket_key_from_path(path: &str) -> (Option<String>, Option<String>) {
    if path == "/" || path == "/myfsio" || path.starts_with("/myfsio/") {
        return (None, None);
    }
    if path == "/ui" || path.starts_with("/ui/") {
        return (None, None);
    }
    let trimmed = path.trim_start_matches('/');
    let Some((bucket, rest)) = trimmed.split_once('/') else {
        return if trimmed.is_empty() {
            (None, None)
        } else {
            (Some(trimmed.to_string()), None)
        };
    };
    if bucket.is_empty() {
        return (None, None);
    }
    let key = if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    };
    (Some(bucket.to_string()), key)
}

enum AuthResult {
    Ok(Principal, Option<StreamingSigV4Context>),
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
    ctx: &RequestContext,
) -> Result<(), S3Error> {
    if path == "/myfsio/health" {
        return Ok(());
    }
    if let Some(p) = principal {
        if p.is_peer() && !is_path_allowed_for_peer(path) {
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Peer credentials are restricted to cluster admin endpoints",
            ));
        }
    }
    if path == "/" {
        if let Some(principal) = principal {
            if state.iam.authorize_with_context(
                principal,
                None,
                "list",
                Some("s3:ListAllMyBuckets"),
                None,
                ctx,
            ) {
                return Ok(());
            }
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
        }
        return Err(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Missing credentials",
        ));
    }

    if path.starts_with("/myfsio/admin/") {
        return if principal.is_some() {
            Ok(())
        } else {
            Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Missing credentials",
            ))
        };
    }

    if path.starts_with("/myfsio/kms/") {
        return match principal {
            Some(p) if p.is_admin => Ok(()),
            Some(_) => Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "KMS access requires admin privileges",
            )),
            None => Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Missing credentials",
            )),
        };
    }

    let mut segments = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty());
    let bucket_raw = match segments.next() {
        Some(b) => b,
        None => {
            return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
        }
    };
    let bucket = &urlencoding_decode(bucket_raw);
    if let Some(reason) = myfsio_storage::validation::bucket_name_rejection(bucket) {
        return Err(S3Error::new(S3ErrorCode::InvalidBucketName, reason));
    }
    let remaining: Vec<String> = segments.map(urlencoding_decode).collect();

    if remaining.is_empty() {
        if *method == Method::POST
            && matches!(
                crate::handlers::parse_bucket_subresource(Some(query)),
                Ok(Some(crate::handlers::BucketSubresource::Delete))
            )
        {
            return Ok(());
        }
        let (action, s3_action) = resolve_bucket_action(method, query)?;
        return authorize_action(
            state,
            principal,
            bucket,
            action,
            Some(s3_action),
            None,
            method_access(method),
            ctx,
        )
        .await;
    }

    let object_key = remaining.join("/");
    let object_subresource = match crate::handlers::parse_object_subresource(Some(query)) {
        Ok(value) => value,
        Err(selectors) => return Err(crate::handlers::ambiguous_subresource_error(&selectors)),
    };
    let copy_eligible = matches!(
        object_subresource,
        None | Some(crate::handlers::ObjectSubresource::UploadId)
    );
    if *method == Method::PUT && copy_eligible {
        if let Some(copy_source) = copy_source {
            let source = copy_source.strip_prefix('/').unwrap_or(copy_source);
            if let Some((src_bucket_raw, src_key_and_query)) = source.split_once('/') {
                let src_key_raw = src_key_and_query
                    .split_once('?')
                    .map(|(key, _)| key)
                    .unwrap_or(src_key_and_query);
                let src_bucket = urlencoding_decode(src_bucket_raw);
                let src_key = urlencoding_decode(src_key_raw);
                if let Some(reason) = myfsio_storage::validation::bucket_name_rejection(&src_bucket)
                {
                    return Err(S3Error::new(S3ErrorCode::InvalidBucketName, reason));
                }
                let source_allowed = authorize_action(
                    state,
                    principal,
                    &src_bucket,
                    "read",
                    Some("s3:GetObject"),
                    Some(&src_key),
                    Some(false),
                    ctx,
                )
                .await
                .is_ok();
                let dest_allowed = authorize_action(
                    state,
                    principal,
                    bucket,
                    "write",
                    Some("s3:PutObject"),
                    Some(&object_key),
                    Some(true),
                    ctx,
                )
                .await
                .is_ok();
                if source_allowed && dest_allowed {
                    return Ok(());
                }
                return Err(S3Error::new(S3ErrorCode::AccessDenied, "Access denied"));
            }
        }
    }

    let (action, s3_action) = resolve_object_action(method, query)?;
    authorize_action(
        state,
        principal,
        bucket,
        action,
        Some(s3_action),
        Some(&object_key),
        method_access(method),
        ctx,
    )
    .await
}

pub async fn ui_authorize(
    state: &AppState,
    principal: &Principal,
    bucket: &str,
    action: &str,
    s3_action: Option<&str>,
    object_key: Option<&str>,
) -> Result<(), String> {
    let ctx = RequestContext::for_principal(Some(principal));
    authorize_action(
        state,
        Some(principal),
        bucket,
        action,
        s3_action,
        object_key,
        None,
        &ctx,
    )
    .await
    .map_err(|err| err.message)
}

pub async fn ui_authorize_list(
    state: &AppState,
    principal: &Principal,
    bucket: &str,
    prefix: &str,
) -> Result<(), String> {
    let mut ctx = RequestContext::for_principal(Some(principal));
    ctx.set("s3:prefix", prefix.to_string());
    let iam_allowed = state.iam.authorize_with_context(
        principal,
        Some(bucket),
        "list",
        Some("s3:ListBucket"),
        Some(prefix),
        &ctx,
    );
    let policy_decision = evaluate_bucket_policy(
        state,
        Some(principal),
        bucket,
        "list",
        Some("s3:ListBucket"),
        None,
        None,
        &ctx,
    )
    .await;

    if matches!(policy_decision, PolicyDecision::Deny) {
        return Err("Access denied by bucket policy".to_string());
    }
    if iam_allowed || matches!(policy_decision, PolicyDecision::Allow) {
        return Ok(());
    }
    if evaluate_bucket_acl(
        state,
        bucket,
        Some(principal.access_key.as_str()),
        "list",
        true,
    )
    .await
    {
        return Ok(());
    }
    Err("Access denied".to_string())
}

pub async fn ui_can_see_bucket(state: &AppState, principal: &Principal, bucket: &str) -> bool {
    let ctx = RequestContext::for_principal(Some(principal));
    let iam_allowed = state.iam.authorize_with_context(
        principal,
        Some(bucket),
        "list",
        Some("s3:ListBucket"),
        None,
        &ctx,
    );
    let policy_decision = evaluate_bucket_policy(
        state,
        Some(principal),
        bucket,
        "list",
        Some("s3:ListBucket"),
        None,
        None,
        &ctx,
    )
    .await;

    if matches!(policy_decision, PolicyDecision::Deny) {
        return false;
    }
    if iam_allowed || matches!(policy_decision, PolicyDecision::Allow) {
        return true;
    }
    evaluate_bucket_acl(
        state,
        bucket,
        Some(principal.access_key.as_str()),
        "list",
        true,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorize_action(
    state: &AppState,
    principal: Option<&Principal>,
    bucket: &str,
    action: &str,
    s3_action: Option<&str>,
    object_key: Option<&str>,
    write: Option<bool>,
    ctx: &RequestContext,
) -> Result<(), S3Error> {
    let enriched;
    let ctx = match object_key {
        Some(key) if conditions_need_existing_tags(state, principal, bucket).await => {
            enriched = with_existing_object_tags(state, bucket, key, ctx).await?;
            &enriched
        }
        _ => ctx,
    };
    let iam_allowed = principal
        .map(|principal| {
            state.iam.authorize_with_context(
                principal,
                Some(bucket),
                action,
                s3_action,
                object_key,
                ctx,
            )
        })
        .unwrap_or(false);
    let policy_decision = evaluate_bucket_policy(
        state, principal, bucket, action, s3_action, object_key, write, ctx,
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

const EXISTING_TAG_KEY_PREFIX: &str = "s3:existingobjecttag/";

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
}

pub(crate) fn build_request_context(
    state: &AppState,
    req: &Request,
    principal: Option<&Principal>,
) -> RequestContext {
    let mut ctx = RequestContext::for_principal(principal);
    let headers = req.headers();
    let trusted_proxies = state.config.num_trusted_proxies;

    if let Some(ip) = crate::middleware::ratelimit::client_ip(req, trusted_proxies) {
        ctx.set("aws:SourceIp", ip.to_string());
    }

    let forwarded_https = trusted_proxies > 0
        && header_str(headers, "x-forwarded-proto")
            .map(|value| {
                value
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("https")
            })
            .unwrap_or(false);
    let scheme_https = req
        .uri()
        .scheme()
        .map(|scheme| *scheme == axum::http::uri::Scheme::HTTPS)
        .unwrap_or(false);
    ctx.set(
        "aws:SecureTransport",
        if forwarded_https || scheme_https {
            "true"
        } else {
            "false"
        },
    );
    ctx.set("aws:RequestedRegion", state.config.region.clone());

    if let Some(value) = header_str(headers, "referer") {
        ctx.set("aws:Referer", value);
    }
    if let Some(value) = header_str(headers, "user-agent") {
        ctx.set("aws:UserAgent", value);
    }

    for (name, value) in headers.iter() {
        let name = name.as_str();
        if !name.starts_with("x-amz-") {
            continue;
        }
        if let Ok(value) = value.to_str() {
            ctx.set(&format!("s3:{}", name), value.trim().to_string());
        }
    }
    if let Some(value) = header_str(headers, "x-amz-object-lock-mode") {
        ctx.set("s3:object-lock-mode", value);
    }
    if let Some(value) = header_str(headers, "x-amz-object-lock-retain-until-date") {
        ctx.set("s3:object-lock-retain-until-date", value);
    }
    if let Some(value) = header_str(headers, "x-amz-object-lock-legal-hold") {
        ctx.set("s3:object-lock-legal-hold", value);
    }

    if let Some(raw) = header_str(headers, "x-amz-tagging") {
        let pairs = parse_query_params(&raw);
        let keys: Vec<String> = pairs.iter().map(|(key, _)| key.clone()).collect();
        for (key, value) in &pairs {
            ctx.set(&format!("s3:RequestObjectTag/{}", key), value.clone());
            ctx.set(&format!("aws:RequestTag/{}", key), value.clone());
        }
        ctx.set_multi("s3:RequestObjectTagKeys", keys.clone());
        ctx.set_multi("aws:TagKeys", keys);
    }

    let query = req.uri().query().unwrap_or("");
    let mut signed_query = false;
    let mut query_amz_date: Option<String> = None;
    for (key, value) in parse_query_params(query) {
        match key.as_str() {
            "prefix" => ctx.set("s3:prefix", value),
            "delimiter" => ctx.set("s3:delimiter", value),
            "max-keys" => ctx.set("s3:max-keys", value),
            "versionId" => ctx.set("s3:VersionId", value),
            "X-Amz-Algorithm" => signed_query = true,
            "X-Amz-Date" => query_amz_date = Some(value),
            _ => {}
        }
    }

    if principal.is_some() {
        let header_auth = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.starts_with("AWS4-HMAC-SHA256 "))
            .unwrap_or(false);
        if header_auth || signed_query {
            ctx.set(
                "s3:authType",
                if header_auth {
                    "REST-HEADER"
                } else {
                    "REST-QUERY-STRING"
                },
            );
            ctx.set("s3:signatureversion", "AWS4-HMAC-SHA256");
            let amz_date = header_str(headers, "x-amz-date").or(query_amz_date);
            if let Some(signed_at) = amz_date
                .as_deref()
                .and_then(|value| NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ").ok())
            {
                let age_ms = Utc::now()
                    .signed_duration_since(signed_at.and_utc())
                    .num_milliseconds()
                    .max(0);
                ctx.set("s3:signatureAge", age_ms.to_string());
            }
        } else {
            ctx.set("s3:authType", "REST-HEADER");
        }
    }

    ctx
}

fn bucket_policy_references_key_prefix(policy: &Value, prefix: &str) -> bool {
    let statements: Vec<&Value> = match policy.get("Statement") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(other) => vec![other],
        None => return false,
    };
    statements.into_iter().any(|statement| {
        statement
            .get("Condition")
            .is_some_and(|condition| policy::condition_references_key_prefix(condition, prefix))
    })
}

async fn conditions_need_existing_tags(
    state: &AppState,
    principal: Option<&Principal>,
    bucket: &str,
) -> bool {
    if let Some(principal) = principal {
        if !principal.is_admin
            && state
                .iam
                .user_conditions_reference(principal, EXISTING_TAG_KEY_PREFIX)
        {
            return true;
        }
    }
    match state.storage.get_bucket_config(bucket).await {
        Ok(config) => config.policy.as_ref().is_some_and(|policy| {
            bucket_policy_references_key_prefix(policy, EXISTING_TAG_KEY_PREFIX)
        }),
        Err(_) => false,
    }
}

async fn with_existing_object_tags(
    state: &AppState,
    bucket: &str,
    key: &str,
    ctx: &RequestContext,
) -> Result<RequestContext, S3Error> {
    use myfsio_storage::error::StorageError;
    let mut enriched = ctx.clone();
    match state.storage.get_object_tags(bucket, key).await {
        Ok(tags) => {
            for tag in tags {
                enriched.set(&format!("s3:ExistingObjectTag/{}", tag.key), tag.value);
            }
        }
        Err(
            StorageError::ObjectNotFound { .. }
            | StorageError::BucketNotFound(_)
            | StorageError::VersionNotFound { .. }
            | StorageError::DeleteMarker { .. },
        ) => {}
        Err(err) => {
            tracing::warn!(
                bucket,
                key,
                error = %err,
                "Unable to load object tags for policy condition evaluation; denying"
            );
            return Err(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Unable to evaluate object tag conditions",
            ));
        }
    }
    Ok(enriched)
}

#[allow(clippy::too_many_arguments)]
async fn evaluate_bucket_policy(
    state: &AppState,
    principal: Option<&Principal>,
    bucket: &str,
    action: &str,
    s3_action: Option<&str>,
    object_key: Option<&str>,
    write: Option<bool>,
    ctx: &RequestContext,
) -> PolicyDecision {
    let config = match state.storage.get_bucket_config(bucket).await {
        Ok(config) => config,
        Err(_) => return PolicyDecision::Neutral,
    };
    if config.unreadable {
        return PolicyDecision::Deny;
    }
    let policy_doc: &Value = match config.policy.as_ref() {
        Some(policy) => policy,
        None => return PolicyDecision::Neutral,
    };
    let mut decision = PolicyDecision::Neutral;

    match policy_doc.get("Statement") {
        Some(Value::Array(items)) => {
            for statement in items.iter() {
                match evaluate_policy_statement(
                    statement, principal, bucket, action, s3_action, object_key, write, ctx,
                ) {
                    PolicyDecision::Deny => return PolicyDecision::Deny,
                    PolicyDecision::Allow => decision = PolicyDecision::Allow,
                    PolicyDecision::Neutral => {}
                }
            }
        }
        Some(statement) => {
            return evaluate_policy_statement(
                statement, principal, bucket, action, s3_action, object_key, write, ctx,
            );
        }
        None => return PolicyDecision::Neutral,
    }

    decision
}

#[allow(clippy::too_many_arguments)]
fn evaluate_policy_statement(
    statement: &Value,
    principal: Option<&Principal>,
    bucket: &str,
    action: &str,
    s3_action: Option<&str>,
    object_key: Option<&str>,
    write: Option<bool>,
    ctx: &RequestContext,
) -> PolicyDecision {
    let effect = match statement
        .get("Effect")
        .and_then(|value| value.as_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("deny") => PolicyDecision::Deny,
        Some("allow") => PolicyDecision::Allow,
        _ => return PolicyDecision::Neutral,
    };

    let principal_ok = match (
        statement.get("Principal").filter(|v| !v.is_null()),
        statement.get("NotPrincipal").filter(|v| !v.is_null()),
    ) {
        (Some(value), _) => policy::principal_matches(value, principal),
        (None, Some(value)) => !policy::principal_matches(value, principal),
        (None, None) => false,
    };
    if !principal_ok {
        return PolicyDecision::Neutral;
    }

    let action_gate = if matches!(effect, PolicyDecision::Allow) {
        write
    } else {
        None
    };
    let action_ok = match (
        statement.get("Action").filter(|v| !v.is_null()),
        statement.get("NotAction").filter(|v| !v.is_null()),
    ) {
        (Some(value), _) => action_list_matches(value, action, s3_action, action_gate),
        (None, Some(value)) => !action_list_matches(value, action, s3_action, None),
        (None, None) => false,
    };
    if !action_ok {
        return PolicyDecision::Neutral;
    }

    let resource_ok = match (
        statement.get("Resource").filter(|v| !v.is_null()),
        statement.get("NotResource").filter(|v| !v.is_null()),
    ) {
        (Some(value), _) => resource_list_matches(value, bucket, object_key, ctx),
        (None, Some(value)) => !resource_list_matches(value, bucket, object_key, ctx),
        (None, None) => false,
    };
    if !resource_ok {
        return PolicyDecision::Neutral;
    }

    if let Some(condition) = statement.get("Condition").filter(|v| !v.is_null()) {
        match policy::evaluate_condition_checked(condition, ctx) {
            Ok(true) => {}
            Ok(false) => return PolicyDecision::Neutral,
            Err(_) => {
                return if matches!(effect, PolicyDecision::Deny) {
                    PolicyDecision::Deny
                } else {
                    PolicyDecision::Neutral
                };
            }
        }
    }

    effect
}

const PRESIGNED_UNSIGNED_HEADER_ALLOWLIST: &[&str] = &[
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-decoded-content-length",
];

fn action_list_matches(
    value: &Value,
    action: &str,
    s3_action: Option<&str>,
    write: Option<bool>,
) -> bool {
    match value {
        Value::String(item) => action_grant_matches(item, action, s3_action, write),
        Value::Array(items) => items.iter().any(|item| {
            item.as_str()
                .map(|value| action_grant_matches(value, action, s3_action, write))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn action_grant_matches(
    policy_action: &str,
    requested_action: &str,
    requested_s3_action: Option<&str>,
    write: Option<bool>,
) -> bool {
    if !policy_action_matches(policy_action, requested_action, requested_s3_action) {
        return false;
    }
    match (write, policy_action_is_write(policy_action)) {
        (Some(requested_write), Some(policy_write)) => requested_write == policy_write,
        _ => true,
    }
}

fn policy_action_is_write(policy_action: &str) -> Option<bool> {
    let normalized = policy_action.trim().to_ascii_lowercase();
    let verb = normalized
        .strip_prefix("s3:")
        .unwrap_or(normalized.as_str());
    if verb.starts_with("get") || verb.starts_with("list") || verb.starts_with("head") {
        Some(false)
    } else if verb.starts_with("put") || verb.starts_with("delete") || verb.starts_with("create") {
        Some(true)
    } else {
        None
    }
}

fn method_access(method: &Method) -> Option<bool> {
    match *method {
        Method::GET | Method::HEAD => Some(false),
        Method::PUT | Method::POST | Method::DELETE => Some(true),
        _ => None,
    }
}

fn policy_action_matches(
    policy_action: &str,
    requested_action: &str,
    requested_s3_action: Option<&str>,
) -> bool {
    myfsio_auth::s3_action::action_matches(policy_action, requested_action, requested_s3_action)
}

fn resource_list_matches(
    value: &Value,
    bucket: &str,
    object_key: Option<&str>,
    ctx: &RequestContext,
) -> bool {
    match value {
        Value::String(resource) => resource_matches_with_context(resource, bucket, object_key, ctx),
        Value::Array(items) => items.iter().any(|item| {
            item.as_str()
                .map(|resource| resource_matches_with_context(resource, bucket, object_key, ctx))
                .unwrap_or(false)
        }),
        _ => false,
    }
}

fn resource_matches_with_context(
    resource: &str,
    bucket: &str,
    object_key: Option<&str>,
    ctx: &RequestContext,
) -> bool {
    match policy::substitute_variables(resource, ctx) {
        Some(resolved) => resource_matches(&resolved, bucket, object_key),
        None => false,
    }
}

fn resource_matches(resource: &str, bucket: &str, object_key: Option<&str>) -> bool {
    if resource.trim() == "*" {
        return true;
    }
    let remainder = match resource.strip_prefix("arn:aws:s3:::") {
        Some(value) => value,
        None => return false,
    };

    match remainder.split_once('/') {
        Some((resource_bucket, resource_key)) => object_key
            .map(|key| {
                wildcard_match(bucket, resource_bucket)
                    && wildcard_match_case_sensitive(key, resource_key)
            })
            .unwrap_or(false),
        None => object_key.is_none() && wildcard_match(bucket, remainder),
    }
}

fn resolve_bucket_action(
    method: &Method,
    query: &str,
) -> Result<(&'static str, &'static str), S3Error> {
    match crate::handlers::parse_bucket_subresource(Some(query)) {
        Err(selectors) => Err(crate::handlers::ambiguous_subresource_error(&selectors)),
        Ok(Some(subresource)) => Ok((subresource.action(), subresource.s3_action(method))),
        Ok(None) => Ok((
            match *method {
                Method::GET => "list",
                Method::HEAD => "read",
                Method::PUT => "create_bucket",
                Method::DELETE => "delete_bucket",
                Method::POST => "write",
                _ => "list",
            },
            crate::handlers::bucket_method_default_s3_action(method),
        )),
    }
}

fn resolve_object_action(
    method: &Method,
    query: &str,
) -> Result<(&'static str, &'static str), S3Error> {
    match crate::handlers::parse_object_subresource(Some(query)) {
        Err(selectors) => Err(crate::handlers::ambiguous_subresource_error(&selectors)),
        Ok(Some(subresource)) => Ok((subresource.action(method), subresource.s3_action(method))),
        Ok(None) => Ok((
            crate::handlers::object_method_default_action(method),
            crate::handlers::object_method_default_s3_action(method),
        )),
    }
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

    let has_legacy_headers =
        req.headers().get("x-access-key").is_some() || req.headers().get("x-secret-key").is_some();
    if has_legacy_headers && !state.config.allow_legacy_header_auth {
        tracing::warn!(
            "Rejecting x-access-key/x-secret-key auth (set ALLOW_LEGACY_HEADER_AUTH=true to re-enable; SigV4 is preferred)"
        );
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::AccessDenied,
            "Legacy header authentication is disabled (set ALLOW_LEGACY_HEADER_AUTH=true to re-enable)",
        ));
    }

    if state.config.allow_legacy_header_auth {
        if let (Some(ak), Some(sk)) = (
            req.headers()
                .get("x-access-key")
                .and_then(|v| v.to_str().ok()),
            req.headers()
                .get("x-secret-key")
                .and_then(|v| v.to_str().ok()),
        ) {
            return match state.iam.authenticate(ak, sk) {
                Some(principal) => {
                    if principal.is_peer() {
                        tracing::warn!(
                            "Peer credential '{}' attempted x-access-key/x-secret-key auth; peer credentials are SigV4-only",
                            principal.access_key
                        );
                        return AuthResult::Denied(S3Error::new(
                            S3ErrorCode::AccessDenied,
                            "Peer credentials must use SigV4 authentication",
                        ));
                    }
                    AuthResult::Ok(principal, None)
                }
                None => AuthResult::Denied(S3Error::from_code(S3ErrorCode::SignatureDoesNotMatch)),
            };
        }
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
    let signed_lc: Vec<String> = signed_headers
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    if !signed_lc.iter().any(|h| h == "host") {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "SignedHeaders must include host",
        ));
    }
    if !signed_lc.iter().any(|h| h == "x-amz-date" || h == "date") {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "SignedHeaders must include x-amz-date or date",
        ));
    }
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
        Some(p) => {
            if let Some(err) =
                enforce_peer_freshness_and_nonce(state, &p, amz_date, provided_signature)
            {
                return AuthResult::Denied(err);
            }
            let payload_variant = match payload_hash.to_ascii_uppercase().as_str() {
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => {
                    Some(StreamingPayloadVariant::SignedPayload)
                }
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => {
                    Some(StreamingPayloadVariant::SignedPayloadTrailer)
                }
                _ => None,
            };
            let streaming_context = payload_variant.map(|payload_variant| StreamingSigV4Context {
                signing_key: sigv4::derive_signing_key(&secret_key, date_stamp, region, service),
                timestamp: amz_date.to_string(),
                credential_scope: format!("{}/{}/{}/aws4_request", date_stamp, region, service),
                seed_signature: provided_signature.to_ascii_lowercase(),
                payload_variant,
            });
            AuthResult::Ok(p, streaming_context)
        }
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

    let request_time = match NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        Ok(t) => t,
        Err(_) => {
            return AuthResult::Denied(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Malformed X-Amz-Date",
            ));
        }
    };
    {
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
    let signed_lc: Vec<String> = signed_headers
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    if !signed_lc.iter().any(|h| h == "host") {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "X-Amz-SignedHeaders must include host",
        ));
    }
    if let Some(unsigned) = req.headers().keys().find(|name| {
        let lower = name.as_str().to_ascii_lowercase();
        lower.starts_with("x-amz-")
            && !PRESIGNED_UNSIGNED_HEADER_ALLOWLIST.contains(&lower.as_str())
            && !signed_lc.contains(&lower)
    }) {
        return AuthResult::Denied(S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            format!(
                "Header '{}' must be included in X-Amz-SignedHeaders",
                unsigned.as_str()
            ),
        ));
    }
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
        Some(p) => {
            if let Some(err) =
                enforce_peer_freshness_and_nonce(state, &p, amz_date, provided_signature)
            {
                return AuthResult::Denied(err);
            }
            AuthResult::Ok(p, None)
        }
        None => AuthResult::Denied(S3Error::from_code(S3ErrorCode::InvalidAccessKeyId)),
    }
}

fn is_path_allowed_for_peer(path: &str) -> bool {
    path == "/myfsio/admin/cluster/overview" || path.starts_with("/myfsio/admin/peer/")
}

fn enforce_peer_freshness_and_nonce(
    state: &AppState,
    principal: &Principal,
    amz_date: &str,
    signature: &str,
) -> Option<S3Error> {
    if !principal.is_peer() {
        return None;
    }
    if let Some(err) =
        check_timestamp_freshness(amz_date, state.config.peer_sigv4_timestamp_tolerance_secs)
    {
        return Some(err);
    }
    match NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        Ok(request_time) => {
            if request_time.and_utc() < state.boot_time_utc {
                return Some(S3Error::new(
                    S3ErrorCode::AccessDenied,
                    "Peer request timestamp predates server start; re-sign and retry",
                ));
            }
        }
        Err(_) => {
            return Some(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Malformed request timestamp",
            ));
        }
    }
    let key = format!("{}:{}", principal.access_key, signature);
    if state.peer_request_nonces.lock().get(&key).is_some() {
        return Some(S3Error::new(
            S3ErrorCode::SignatureDoesNotMatch,
            "Peer request signature replay detected",
        ));
    }
    match state.peer_nonce_store.record(&key) {
        Ok(NonceRecordOutcome::Recorded) => {
            state.peer_request_nonces.lock().put(key, Instant::now());
            None
        }
        Ok(NonceRecordOutcome::Replay) => {
            state.peer_request_nonces.lock().put(key, Instant::now());
            Some(S3Error::new(
                S3ErrorCode::SignatureDoesNotMatch,
                "Peer request signature replay detected",
            ))
        }
        Err(error) => {
            tracing::error!(error = %error, "Peer replay nonce persistence is unavailable");
            Some(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Peer replay protection is unavailable",
            ))
        }
    }
}

fn check_timestamp_freshness(amz_date: &str, tolerance_secs: u64) -> Option<S3Error> {
    let request_time = match NaiveDateTime::parse_from_str(amz_date, "%Y%m%dT%H%M%SZ") {
        Ok(t) => t,
        Err(_) => {
            return Some(S3Error::new(
                S3ErrorCode::AccessDenied,
                "Malformed request timestamp",
            ));
        }
    };
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
    crate::s3_response::s3_error_response(err.with_resource(resource.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        action_grant_matches, policy_action_matches, resource_matches, wildcard_match,
        wildcard_match_case_sensitive,
    };

    #[test]
    fn subresource_read_grant_does_not_authorize_write() {
        assert!(action_grant_matches(
            "s3:GetBucketCors",
            "cors",
            None,
            Some(false)
        ));
        assert!(!action_grant_matches(
            "s3:GetBucketCors",
            "cors",
            None,
            Some(true)
        ));
        assert!(action_grant_matches(
            "s3:PutBucketCors",
            "cors",
            None,
            Some(true)
        ));
        assert!(!action_grant_matches(
            "s3:PutBucketCors",
            "cors",
            None,
            Some(false)
        ));
        assert!(action_grant_matches(
            "s3:GetLifecycleConfiguration",
            "lifecycle",
            None,
            Some(false)
        ));
        assert!(!action_grant_matches(
            "s3:GetLifecycleConfiguration",
            "lifecycle",
            None,
            Some(true)
        ));
    }

    #[test]
    fn wildcards_and_core_actions_still_match_with_gate() {
        assert!(action_grant_matches("s3:*", "cors", None, Some(true)));
        assert!(action_grant_matches("s3:*", "cors", None, Some(false)));
        assert!(action_grant_matches("*", "cors", None, Some(true)));
        assert!(action_grant_matches(
            "s3:GetObject",
            "read",
            None,
            Some(false)
        ));
        assert!(action_grant_matches(
            "s3:PutObject",
            "write",
            None,
            Some(true)
        ));
    }

    #[test]
    fn no_method_disposition_skips_gate() {
        assert!(action_grant_matches("s3:GetBucketCors", "cors", None, None));
        assert!(action_grant_matches("s3:PutBucketCors", "cors", None, None));
    }

    #[test]
    fn star_action_matches_anything() {
        assert!(policy_action_matches("*", "read", None));
        assert!(policy_action_matches("*", "delete", None));
        assert!(policy_action_matches("*", "policy", None));
        assert!(policy_action_matches("*", "read", Some("s3:GetObject")));
    }

    #[test]
    fn s3_star_action_matches_any_s3_action() {
        assert!(policy_action_matches("s3:*", "read", None));
        assert!(policy_action_matches("s3:*", "write", None));
        assert!(policy_action_matches("s3:*", "delete", None));
        assert!(policy_action_matches("s3:*", "list", None));
        assert!(policy_action_matches("s3:*", "policy", None));
        assert!(policy_action_matches("s3:*", "read", Some("s3:GetObject")));
        assert!(policy_action_matches(
            "s3:*",
            "policy",
            Some("s3:PutBucketPolicy")
        ));
    }

    #[test]
    fn s3_get_star_matches_read_only() {
        assert!(policy_action_matches("s3:Get*", "read", None));
        assert!(!policy_action_matches("s3:Get*", "write", None));
        assert!(!policy_action_matches("s3:Get*", "delete", None));
        assert!(policy_action_matches(
            "s3:Get*",
            "read",
            Some("s3:GetObject")
        ));
        assert!(policy_action_matches(
            "s3:Get*",
            "read",
            Some("s3:GetObjectTagging")
        ));
        assert!(!policy_action_matches(
            "s3:Get*",
            "write",
            Some("s3:PutObject")
        ));
    }

    #[test]
    fn s3_put_star_matches_write_and_share_policy_lifecycle() {
        assert!(policy_action_matches("s3:Put*", "write", None));
        assert!(policy_action_matches("s3:PutObject*", "write", None));
        assert!(policy_action_matches("s3:PutBucket*", "versioning", None));
        assert!(policy_action_matches("s3:PutBucket*", "tagging", None));
        assert!(!policy_action_matches("s3:PutBucket*", "write", None));
    }

    #[test]
    fn s3_list_star_matches_list() {
        assert!(policy_action_matches("s3:List*", "list", None));
        assert!(!policy_action_matches("s3:List*", "read", None));
        assert!(policy_action_matches(
            "s3:List*",
            "list",
            Some("s3:ListBucket")
        ));
    }

    #[test]
    fn s3_delete_star_matches_delete() {
        assert!(policy_action_matches("s3:Delete*", "delete", None));
        assert!(!policy_action_matches("s3:Delete*", "write", None));
    }

    #[test]
    fn exact_action_still_matches() {
        assert!(policy_action_matches("s3:GetObject", "read", None));
        assert!(policy_action_matches("s3:PutObject", "write", None));
        assert!(!policy_action_matches("s3:GetObject", "write", None));
        assert!(policy_action_matches(
            "s3:GetObject",
            "read",
            Some("s3:GetObject")
        ));
        assert!(policy_action_matches(
            "s3:PutObject",
            "write",
            Some("s3:PutObject")
        ));
    }

    #[test]
    fn narrow_grant_no_longer_authorizes_whole_action_class() {
        assert!(!policy_action_matches(
            "s3:GetObjectTagging",
            "read",
            Some("s3:GetObject")
        ));
        assert!(!policy_action_matches(
            "s3:GetObjectAcl",
            "read",
            Some("s3:GetObject")
        ));
        assert!(!policy_action_matches(
            "s3:GetObject",
            "read",
            Some("s3:GetObjectTagging")
        ));
        assert!(!policy_action_matches(
            "s3:PutObjectTagging",
            "write",
            Some("s3:PutObject")
        ));
        assert!(!policy_action_matches(
            "s3:DeleteObjectTagging",
            "delete",
            Some("s3:DeleteObject")
        ));
        assert!(policy_action_matches(
            "s3:GetObjectTagging",
            "read",
            Some("s3:GetObjectTagging")
        ));
    }

    #[test]
    fn s3_action_aliases_are_canonicalized() {
        assert!(policy_action_matches(
            "s3:HeadObject",
            "read",
            Some("s3:GetObject")
        ));
        assert!(policy_action_matches(
            "s3:HeadBucket",
            "read",
            Some("s3:ListBucket")
        ));
        assert!(policy_action_matches(
            "s3:UploadPart",
            "write",
            Some("s3:PutObject")
        ));
        assert!(policy_action_matches(
            "s3:CopyObject",
            "write",
            Some("s3:PutObject")
        ));
        assert!(policy_action_matches(
            "s3:GetObjectVersion",
            "read",
            Some("s3:GetObject")
        ));
        assert!(policy_action_matches(
            "s3:ListParts",
            "read",
            Some("s3:ListMultipartUploadParts")
        ));
        assert!(policy_action_matches(
            "s3:PutBucketLifecycle",
            "lifecycle",
            Some("s3:PutLifecycleConfiguration")
        ));
        assert!(policy_action_matches(
            "s3:GetObjectVersion*",
            "read",
            Some("s3:GetObject")
        ));
        assert!(policy_action_matches(
            "s3:Upload*",
            "write",
            Some("s3:PutObject")
        ));
    }

    #[test]
    fn internal_action_names_still_work_in_policies() {
        assert!(policy_action_matches("read", "read", Some("s3:GetObject")));
        assert!(policy_action_matches(
            "versioning",
            "versioning",
            Some("s3:PutBucketVersioning")
        ));
        assert!(!policy_action_matches(
            "read",
            "write",
            Some("s3:PutObject")
        ));
    }

    #[test]
    fn glob_over_exact_names_stays_scoped() {
        assert!(!policy_action_matches(
            "s3:GetObject*",
            "read",
            Some("s3:GetBucketVersioning")
        ));
        assert!(policy_action_matches(
            "s3:GetObject*",
            "read",
            Some("s3:GetObjectTagging")
        ));
        assert!(!policy_action_matches(
            "s3:NeverHeardOf*",
            "read",
            Some("s3:GetObject")
        ));
    }

    #[test]
    fn unknown_glob_pattern_does_not_match_unknown_action() {
        assert!(!policy_action_matches("s3:NeverHeardOf*", "read", None));
    }

    #[test]
    fn wildcard_match_basic() {
        assert!(wildcard_match("s3:getobject", "s3:get*"));
        assert!(wildcard_match("s3:listbucket", "s3:list*"));
        assert!(!wildcard_match("s3:listbucket", "s3:get*"));
    }

    #[test]
    fn bypass_governance_is_its_own_policy_action() {
        assert!(policy_action_matches(
            "s3:BypassGovernanceRetention",
            "bypass_governance",
            None
        ));
        assert!(policy_action_matches("s3:*", "bypass_governance", None));
        assert!(!policy_action_matches(
            "s3:DeleteObject",
            "bypass_governance",
            None
        ));
        assert!(!policy_action_matches(
            "s3:Delete*",
            "bypass_governance",
            None
        ));
        assert!(!policy_action_matches(
            "s3:BypassGovernanceRetention",
            "delete",
            None
        ));
        assert!(policy_action_matches(
            "s3:BypassGovernanceRetention",
            "bypass_governance",
            Some("s3:BypassGovernanceRetention")
        ));
        assert!(!policy_action_matches(
            "s3:DeleteObject",
            "bypass_governance",
            Some("s3:BypassGovernanceRetention")
        ));
    }

    #[test]
    fn action_patterns_remain_case_insensitive() {
        assert!(policy_action_matches("s3:getobject", "read", None));
        assert!(policy_action_matches("S3:GETOBJECT", "read", None));
        assert!(policy_action_matches("s3:GeT*", "read", None));
        assert!(wildcard_match("s3:GetObject", "S3:get*"));
        assert!(policy_action_matches(
            "S3:GETOBJECT",
            "read",
            Some("s3:GetObject")
        ));
        assert!(policy_action_matches(
            "s3:GeT*",
            "read",
            Some("s3:GetObject")
        ));
    }

    #[test]
    fn resource_key_segment_matches_case_sensitively() {
        assert!(resource_matches(
            "arn:aws:s3:::b/public/*",
            "b",
            Some("public/x")
        ));
        assert!(!resource_matches(
            "arn:aws:s3:::b/public/*",
            "b",
            Some("PUBLIC/secret")
        ));
        assert!(!resource_matches(
            "arn:aws:s3:::b/public/*",
            "b",
            Some("Public/secret")
        ));
    }

    #[test]
    fn resource_bucket_segment_matches_case_insensitively() {
        assert!(resource_matches("arn:aws:s3:::MyBucket", "mybucket", None));
        assert!(resource_matches(
            "arn:aws:s3:::MyBucket/data/*",
            "mybucket",
            Some("data/report.csv")
        ));
        assert!(resource_matches("arn:aws:s3:::my*", "mybucket", None));
    }

    #[test]
    fn case_sensitive_wildcards_preserve_glob_semantics() {
        assert!(wildcard_match_case_sensitive("public/a/b.txt", "public/*"));
        assert!(wildcard_match_case_sensitive("public/ab.txt", "public/?b*"));
        assert!(!wildcard_match_case_sensitive(
            "public/ab.txt",
            "public/?B*"
        ));
        assert!(wildcard_match_case_sensitive("abc", "*"));
        assert!(!wildcard_match_case_sensitive("abc", "abcd"));
        assert!(wildcard_match("public/AB.txt", "public/?b*"));
    }

    mod statements {
        use super::super::{evaluate_policy_statement, PolicyDecision};
        use myfsio_auth::policy::RequestContext;
        use myfsio_common::types::Principal;
        use serde_json::{json, Value};

        fn alice() -> Principal {
            Principal::new("AKALICE".into(), "u-alice".into(), "alice".into(), false)
        }

        fn eval(
            statement: Value,
            principal: Option<&Principal>,
            action: &str,
            s3: &str,
            key: Option<&str>,
            ctx: &RequestContext,
        ) -> PolicyDecision {
            evaluate_policy_statement(
                &statement,
                principal,
                "docs",
                action,
                Some(s3),
                key,
                None,
                ctx,
            )
        }

        #[test]
        fn not_action_not_resource_not_principal() {
            let alice = alice();
            let ctx = RequestContext::for_principal(Some(&alice));
            let deny_all_but_get = json!({
                "Effect": "Deny", "Principal": "*", "NotAction": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::docs", "arn:aws:s3:::docs/*"]
            });
            assert_eq!(
                eval(
                    deny_all_but_get.clone(),
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("k"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            assert_eq!(
                eval(
                    deny_all_but_get.clone(),
                    Some(&alice),
                    "write",
                    "s3:PutObject",
                    Some("k"),
                    &ctx
                ),
                PolicyDecision::Deny
            );
            assert_eq!(
                eval(
                    deny_all_but_get,
                    Some(&alice),
                    "list",
                    "s3:ListBucket",
                    None,
                    &ctx
                ),
                PolicyDecision::Neutral
            );

            let deny_outside_public = json!({
                "Effect": "Deny", "Principal": "*", "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::docs/public/*"
            });
            assert_eq!(
                eval(
                    deny_outside_public.clone(),
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("public/a"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            assert_eq!(
                eval(
                    deny_outside_public,
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("private/a"),
                    &ctx
                ),
                PolicyDecision::Deny
            );

            let deny_everyone_but_alice = json!({
                "Effect": "Deny", "NotPrincipal": {"AWS": "arn:aws:iam::myfsio:user/u-alice"},
                "Action": "s3:*", "Resource": "arn:aws:s3:::docs/*"
            });
            assert_eq!(
                eval(
                    deny_everyone_but_alice.clone(),
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            let bob = Principal::new("AKBOB".into(), "u-bob".into(), "bob".into(), false);
            let bob_ctx = RequestContext::for_principal(Some(&bob));
            assert_eq!(
                eval(
                    deny_everyone_but_alice.clone(),
                    Some(&bob),
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &bob_ctx
                ),
                PolicyDecision::Deny
            );
            let anon_ctx = RequestContext::for_principal(None);
            assert_eq!(
                eval(
                    deny_everyone_but_alice,
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &anon_ctx
                ),
                PolicyDecision::Deny
            );
        }

        #[test]
        fn conditions_and_variables_in_statements() {
            let alice = alice();
            let mut ctx = RequestContext::for_principal(Some(&alice));
            ctx.set("aws:SourceIp", "10.0.0.5");
            let home = json!({
                "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*",
                "Resource": "arn:aws:s3:::docs/home/${aws:username}/*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
            });
            assert_eq!(
                eval(
                    home.clone(),
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("home/alice/x"),
                    &ctx
                ),
                PolicyDecision::Allow
            );
            assert_eq!(
                eval(
                    home.clone(),
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("home/bob/x"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            ctx.set("aws:SourceIp", "192.0.2.1");
            assert_eq!(
                eval(
                    home.clone(),
                    Some(&alice),
                    "read",
                    "s3:GetObject",
                    Some("home/alice/x"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            let anon = RequestContext::for_principal(None);
            assert_eq!(
                eval(
                    home,
                    None,
                    "read",
                    "s3:GetObject",
                    Some("home/alice/x"),
                    &anon
                ),
                PolicyDecision::Neutral
            );
        }

        #[test]
        fn statements_without_required_elements_are_neutral() {
            let ctx = RequestContext::for_principal(None);
            assert_eq!(
                eval(
                    json!({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}),
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            assert_eq!(
                eval(
                    json!({"Effect": "Allow", "Principal": "*", "Resource": "arn:aws:s3:::docs/*"}),
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            assert_eq!(
                eval(
                    json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}),
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            assert_eq!(
                eval(
                    json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::docs/*", "Condition": {"Bogus": {"k": "v"}}}),
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Neutral
            );
            assert_eq!(
                eval(
                    json!({"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::docs/*", "Condition": {"Bogus": {"k": "v"}}}),
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Deny
            );
            assert_eq!(
                eval(
                    json!({"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}),
                    None,
                    "read",
                    "s3:GetObject",
                    Some("a"),
                    &ctx
                ),
                PolicyDecision::Allow
            );
        }
    }
}
