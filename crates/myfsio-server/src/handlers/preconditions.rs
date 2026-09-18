use super::*;

pub(super) fn evaluate_get_preconditions(
    headers: &HeaderMap,
    meta: &myfsio_common::types::ObjectMeta,
) -> Option<Response> {
    let if_match = headers.get("if-match").and_then(|v| v.to_str().ok());
    let if_none_match = headers.get("if-none-match").and_then(|v| v.to_str().ok());

    if if_match.is_some() && if_none_match.is_some() {
        return Some(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "If-Match and If-None-Match must not both be present",
        )));
    }

    if let Some(value) = if_match {
        if !etag_condition_matches(value, meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    } else if let Some(value) = headers
        .get("if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if meta.last_modified > t {
                return Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )));
            }
        }
    }

    if let Some(value) = if_none_match {
        if etag_condition_matches(value, meta.etag.as_deref()) {
            return Some(not_modified_response(meta));
        }
    } else if let Some(value) = headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if meta.last_modified <= t {
                return Some(not_modified_response(meta));
            }
        }
    }

    None
}

pub(super) fn not_modified_response(meta: &myfsio_common::types::ObjectMeta) -> Response {
    let mut headers = HeaderMap::new();
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            headers.insert("x-amz-version-id", value);
        }
    }
    apply_stored_response_headers(&mut headers, &meta.internal_metadata);
    (StatusCode::NOT_MODIFIED, headers).into_response()
}

pub(super) async fn evaluate_put_preconditions(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Option<Response> {
    let has_if_match = headers.contains_key("if-match");
    let has_if_none_match = headers.contains_key("if-none-match");
    let has_if_unmodified = headers.contains_key("if-unmodified-since");
    let has_if_modified = headers.contains_key("if-modified-since");
    if !has_if_match && !has_if_none_match && !has_if_unmodified && !has_if_modified {
        return None;
    }

    if has_if_match && has_if_none_match {
        return Some(s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "If-Match and If-None-Match must not both be present",
        )));
    }

    match state.storage.head_object(bucket, key).await {
        Ok(meta) => {
            if let Some(value) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
                if !etag_condition_matches(value, meta.etag.as_deref()) {
                    return Some(s3_error_response(S3Error::from_code(
                        S3ErrorCode::PreconditionFailed,
                    )));
                }
            } else if let Some(value) = headers
                .get("if-unmodified-since")
                .and_then(|v| v.to_str().ok())
            {
                if let Some(t) = parse_http_date(value) {
                    if meta.last_modified > t {
                        return Some(s3_error_response(S3Error::from_code(
                            S3ErrorCode::PreconditionFailed,
                        )));
                    }
                }
            }
            if let Some(value) = headers.get("if-none-match").and_then(|v| v.to_str().ok()) {
                if etag_condition_matches(value, meta.etag.as_deref()) {
                    return Some(s3_error_response(S3Error::from_code(
                        S3ErrorCode::PreconditionFailed,
                    )));
                }
            } else if let Some(value) = headers
                .get("if-modified-since")
                .and_then(|v| v.to_str().ok())
            {
                if let Some(t) = parse_http_date(value) {
                    if meta.last_modified <= t {
                        return Some(s3_error_response(S3Error::from_code(
                            S3ErrorCode::PreconditionFailed,
                        )));
                    }
                }
            }
            None
        }
        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. })
        | Err(myfsio_storage::error::StorageError::DeleteMarker { .. }) => {
            if has_if_match || has_if_unmodified {
                Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )))
            } else {
                None
            }
        }
        Err(err) => Some(storage_err_response(err)),
    }
}

pub(super) fn evaluate_copy_preconditions(
    headers: &HeaderMap,
    source_meta: &myfsio_common::types::ObjectMeta,
) -> Option<Response> {
    let if_match = headers
        .get("x-amz-copy-source-if-match")
        .and_then(|v| v.to_str().ok());
    let if_none_match = headers
        .get("x-amz-copy-source-if-none-match")
        .and_then(|v| v.to_str().ok());

    if let Some(value) = if_match {
        if !etag_condition_matches(value, source_meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    } else if let Some(value) = headers
        .get("x-amz-copy-source-if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if source_meta.last_modified > t {
                return Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )));
            }
        }
    }

    if let Some(value) = if_none_match {
        if etag_condition_matches(value, source_meta.etag.as_deref()) {
            return Some(s3_error_response(S3Error::from_code(
                S3ErrorCode::PreconditionFailed,
            )));
        }
    } else if let Some(value) = headers
        .get("x-amz-copy-source-if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(t) = parse_http_date(value) {
            if source_meta.last_modified <= t {
                return Some(s3_error_response(S3Error::from_code(
                    S3ErrorCode::PreconditionFailed,
                )));
            }
        }
    }

    None
}

pub(super) fn bypass_governance_header(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-bypass-governance-retention")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub(crate) async fn governance_bypass_authorized(
    state: &AppState,
    principal: Option<&myfsio_common::types::Principal>,
    bucket: &str,
    key: Option<&str>,
) -> bool {
    let Some(principal) = principal else {
        return false;
    };
    if principal.is_admin {
        return true;
    }
    crate::middleware::authorize_action(
        state,
        Some(principal),
        bucket,
        "bypass_governance",
        Some("s3:BypassGovernanceRetention"),
        key,
        None,
        &crate::middleware::current_request_context(Some(principal)),
    )
    .await
    .is_ok()
}

pub(crate) async fn governance_bypass_allowed(
    state: &AppState,
    principal: Option<&myfsio_common::types::Principal>,
    bucket: &str,
    key: Option<&str>,
    headers: &HeaderMap,
) -> bool {
    bypass_governance_header(headers)
        && governance_bypass_authorized(state, principal, bucket, key).await
}

pub(super) fn put_conditions_from_headers(
    headers: &HeaderMap,
) -> myfsio_storage::traits::PutConditions {
    myfsio_storage::traits::PutConditions {
        if_match: headers
            .get("if-match")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        if_none_match: headers
            .get("if-none-match")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string),
        if_unmodified_since: headers
            .get("if-unmodified-since")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date),
        if_modified_since: headers
            .get("if-modified-since")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date),
    }
}

pub(super) fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    let trimmed = value.trim();
    if let Ok(dt) = DateTime::parse_from_rfc2822(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%A, %d-%b-%y %H:%M:%S GMT") {
        return Some(naive.and_utc());
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(trimmed, "%a %b %e %H:%M:%S %Y") {
        return Some(naive.and_utc());
    }
    None
}

pub(super) fn etag_condition_matches(condition: &str, etag: Option<&str>) -> bool {
    let trimmed = condition.trim();
    if trimmed == "*" {
        return true;
    }

    let current = match etag {
        Some(e) => e.trim_matches('"'),
        None => return false,
    };

    trimmed
        .split(',')
        .map(|v| v.trim().trim_matches('"'))
        .any(|candidate| candidate == current || candidate == "*")
}

pub(super) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
