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
                    return build_response(&normalized, bytes, mime.as_ref(), &headers);
                }
            }
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    match embedded::static_file(&normalized) {
        Some(file) => {
            let mime = mime_guess::from_path(&normalized).first_or_octet_stream();
            build_response(&normalized, file.data.into_owned(), mime.as_ref(), &headers)
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn build_response(_path: &str, bytes: Vec<u8>, mime: &str, request_headers: &HeaderMap) -> Response {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let etag = format!("\"{:.16x}\"", hasher.finalize());

    if let Some(if_none_match) = request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
    {
        if if_none_match.split(',').any(|tag| tag.trim() == etag) {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::NOT_MODIFIED;
            if let Ok(v) = HeaderValue::from_str(&etag) {
                resp.headers_mut().insert(header::ETAG, v);
            }
            return resp;
        }
    }

    let len = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    if let Ok(value) = HeaderValue::from_str(mime) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, v);
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300, must-revalidate"),
    );
    response
}
