use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};

use crate::embedded;
use crate::state::AppState;

pub async fn serve(State(state): State<AppState>, Path(path): Path<String>) -> Response {
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
                    return build_response(&normalized, bytes, mime.as_ref());
                }
            }
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    match embedded::static_file(&normalized) {
        Some(file) => {
            let mime = mime_guess::from_path(&normalized).first_or_octet_stream();
            build_response(&normalized, file.data.into_owned(), mime.as_ref())
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn build_response(_path: &str, bytes: Vec<u8>, mime: &str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    if let Ok(value) = HeaderValue::from_str(mime) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    response
}
