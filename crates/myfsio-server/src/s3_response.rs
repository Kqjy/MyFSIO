use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use myfsio_common::error::S3Error;

pub fn s3_error_response(mut err: S3Error) -> Response {
    if err.resource.is_empty() {
        err.resource = "/".to_string();
    }
    let request_id = err.ensure_request_id().to_string();
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let code_str = err.code.as_str();
    let body = err.to_xml();

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/xml"));
    if let Ok(v) = HeaderValue::from_str(code_str) {
        headers.insert("x-amz-error-code", v);
    }
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        headers.insert("x-amz-request-id", v);
    }
    let host_id = derive_host_id(&request_id);
    if let Ok(v) = HeaderValue::from_str(&host_id) {
        headers.insert("x-amz-id-2", v);
    }

    (status, headers, body).into_response()
}

pub fn s3_error_response_with_headers(mut err: S3Error, extra: HeaderMap) -> Response {
    if err.resource.is_empty() {
        err.resource = "/".to_string();
    }
    let request_id = err.ensure_request_id().to_string();
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let code_str = err.code.as_str();
    let body = err.to_xml();

    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/xml"));
    if let Ok(v) = HeaderValue::from_str(code_str) {
        headers.insert("x-amz-error-code", v);
    }
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        headers.insert("x-amz-request-id", v);
    }
    let host_id = derive_host_id(&request_id);
    if let Ok(v) = HeaderValue::from_str(&host_id) {
        headers.insert("x-amz-id-2", v);
    }
    for (k, v) in extra.into_iter().filter_map(|(k, v)| k.map(|k| (k, v))) {
        headers.insert(k, v);
    }

    (status, headers, body).into_response()
}

fn derive_host_id(request_id: &str) -> String {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    if request_id.is_empty() {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"myfsio-host-id\0");
    hasher.update(request_id.as_bytes());
    B64.encode(hasher.finalize())
}
