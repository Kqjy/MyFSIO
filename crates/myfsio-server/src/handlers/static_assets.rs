use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::embedded;
use crate::state::AppState;

pub async fn serve(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let normalized = path.trim_start_matches('/').to_string();
    if normalized.is_empty() || normalized.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }

    let use_disk = std::env::var("STATIC_DIR").is_ok() && state.config.static_dir.is_dir();
    if use_disk {
        let candidate = state.config.static_dir.join(&normalized);
        if let Ok(canonical) = candidate.canonicalize() {
            if canonical.starts_with(
                state
                    .config
                    .static_dir
                    .canonicalize()
                    .unwrap_or_else(|_| state.config.static_dir.clone()),
            ) {
                if let Ok(bytes) = tokio::fs::read(&canonical).await {
                    let mime = mime_guess::from_path(&canonical).first_or_octet_stream();
                    let etag = compute_etag(&bytes);
                    if let Some(resp) = not_modified_response(&etag, &headers) {
                        return resp;
                    }
                    return build_response(&normalized, bytes, mime.as_ref(), &etag);
                }
            }
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    match embedded::static_file(&normalized) {
        Some(file) => {
            let mime = mime_guess::from_path(&normalized).first_or_octet_stream();
            let etag = embedded_etag(&normalized, file.data.as_ref());
            if let Some(resp) = not_modified_response(&etag, &headers) {
                return resp;
            }
            build_response(&normalized, file.data.into_owned(), mime.as_ref(), &etag)
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn compute_etag(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("\"{:.16x}\"", hasher.finalize())
}

fn embedded_etag(path: &str, bytes: &[u8]) -> String {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(etag) = guard.get(path) {
            return etag.clone();
        }
    }
    let etag = compute_etag(bytes);
    if let Ok(mut guard) = cache.lock() {
        guard.insert(path.to_string(), etag.clone());
    }
    etag
}

fn not_modified_response(etag: &str, request_headers: &HeaderMap) -> Option<Response> {
    let if_none_match = request_headers
        .get(header::IF_NONE_MATCH)?
        .to_str()
        .ok()?;
    if !if_none_match.split(',').any(|tag| tag.trim() == etag) {
        return None;
    }
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NOT_MODIFIED;
    if let Ok(v) = HeaderValue::from_str(etag) {
        resp.headers_mut().insert(header::ETAG, v);
    }
    Some(resp)
}

fn build_response(path: &str, bytes: Vec<u8>, mime: &str, etag: &str) -> Response {
    let len = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    if let Ok(value) = HeaderValue::from_str(mime) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, v);
    }
    let cache_control = if path.starts_with("js/vendor/") {
        HeaderValue::from_static("public, max-age=86400")
    } else {
        HeaderValue::from_static("public, max-age=300, must-revalidate")
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, cache_control);
    response
}
