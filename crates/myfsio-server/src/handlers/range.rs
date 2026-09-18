use super::*;

pub(super) async fn range_get_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    range_str: &str,
    query: &ObjectQuery,
    headers: &HeaderMap,
) -> Response {
    range_get_handler_inner(state, bucket, key, range_str, query, headers, None).await
}

pub(super) async fn range_get_handler_inner(
    state: &AppState,
    bucket: &str,
    key: &str,
    range_str: &str,
    query: &ObjectQuery,
    headers: &HeaderMap,
    parts_count: Option<u32>,
) -> Response {
    let window = object_read::parse_range_hint(range_str);
    let snapshot = match object_read::snapshot_object_for_read(
        state,
        bucket,
        key,
        query.effective_version_id(),
        window,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(e) => return storage_err_response(e),
    };

    serve_range_from_snapshot(state, snapshot, range_str, query, headers, parts_count).await
}

pub(super) async fn serve_range_from_snapshot(
    state: &AppState,
    snapshot: object_read::ObjectSnapshot,
    range_str: &str,
    query: &ObjectQuery,
    headers: &HeaderMap,
    parts_count: Option<u32>,
) -> Response {
    if let Some(resp) = evaluate_get_preconditions(headers, &snapshot.meta) {
        snapshot.discard().await;
        return resp;
    }

    if mpu_is_sse_c(&snapshot.meta.internal_metadata) {
        let object_read::ObjectSnapshot { meta, link, .. } = snapshot;
        return serve_mpu_sse_c(state, link, meta, headers, query, Some(range_str), None).await;
    }

    if let Err(resp) = require_sse_c_key_for_object(state, &snapshot.meta, headers) {
        snapshot.discard().await;
        return resp;
    }

    let served =
        match object_read::serve_object_data(state, snapshot, Some(range_str), headers, None).await
        {
            Ok(served) => served,
            Err(err) => return object_read_error_response(err),
        };

    let (start, end) = served
        .range
        .unwrap_or((0, served.total_size.saturating_sub(1)));
    let resp_headers = partial_content_headers(
        start,
        end,
        served.total_size,
        &served.meta,
        served.meta.key.as_str(),
        query,
        headers,
        served.encryption_algorithm.as_deref(),
        parts_count,
    );
    (StatusCode::PARTIAL_CONTENT, resp_headers, served.body).into_response()
}

pub(super) fn object_read_error_response(err: object_read::ObjectReadError) -> Response {
    match err {
        object_read::ObjectReadError::Storage(e) => storage_err_response(e),
        object_read::ObjectReadError::Rejected(response) => response,
        object_read::ObjectReadError::RangeNotSatisfiable(total) => {
            let mut extra = HeaderMap::new();
            if let Ok(v) = format!("bytes */{}", total).parse() {
                extra.insert(axum::http::header::CONTENT_RANGE, v);
            }
            crate::s3_response::s3_error_response_with_headers(
                S3Error::new(
                    myfsio_common::error::S3ErrorCode::InvalidRange,
                    format!("Range not satisfiable for size {}", total),
                ),
                extra,
            )
        }
        object_read::ObjectReadError::Internal(message) => s3_error_response(S3Error::new(
            myfsio_common::error::S3ErrorCode::InternalError,
            message,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn partial_content_headers(
    start: u64,
    end: u64,
    plaintext_size: u64,
    meta: &myfsio_common::types::ObjectMeta,
    key: &str,
    query: &ObjectQuery,
    request_headers: &HeaderMap,
    enc_header: Option<&str>,
    parts_count: Option<u32>,
) -> HeaderMap {
    let length = end - start + 1;
    let mut headers = HeaderMap::new();
    headers.insert("content-length", length.to_string().parse().unwrap());
    headers.insert(
        "content-range",
        format!("bytes {}-{}/{}", start, end, plaintext_size)
            .parse()
            .unwrap(),
    );
    if let Some(ref etag) = meta.etag {
        headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut headers, key, meta.content_type.as_deref());
    headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(alg) = enc_header {
        headers.insert("x-amz-server-side-encryption", alg.parse().unwrap());
    }
    apply_stored_kms_key_header(&mut headers, &meta.internal_metadata);
    apply_stored_response_headers(&mut headers, &meta.internal_metadata);
    if start == 0 && end + 1 == plaintext_size && checksum_mode_enabled(request_headers) {
        apply_stored_checksum_headers(&mut headers, &meta.internal_metadata);
    }
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            headers.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            headers.insert("x-amz-version-id", value);
        }
    }

    apply_user_metadata(&mut headers, &meta.metadata);
    apply_response_overrides(&mut headers, query);

    if let Some(count) = parts_count {
        headers.insert("x-amz-mp-parts-count", count.to_string().parse().unwrap());
    }
    headers
}

pub(super) fn parse_range(range_str: &str, total_size: u64) -> Option<(u64, u64)> {
    let range_spec = range_str.strip_prefix("bytes=")?;

    if total_size == 0 {
        return None;
    }

    if let Some(suffix) = range_spec.strip_prefix('-') {
        let suffix_len: u64 = suffix.parse().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let start = total_size.saturating_sub(suffix_len);
        return Some((start, total_size - 1));
    }

    let (start_str, end_str) = range_spec.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;

    let end = if end_str.is_empty() {
        total_size - 1
    } else {
        let e: u64 = end_str.parse().ok()?;
        e.min(total_size - 1)
    };

    if start > end || start >= total_size {
        return None;
    }

    Some((start, end))
}

#[cfg(test)]
mod range_tests {
    use super::parse_range;

    #[test]
    fn parses_explicit_range() {
        assert_eq!(parse_range("bytes=0-3", 100), Some((0, 3)));
        assert_eq!(parse_range("bytes=10-19", 100), Some((10, 19)));
    }

    #[test]
    fn open_ended_range_clamps_to_end() {
        assert_eq!(parse_range("bytes=10-", 100), Some((10, 99)));
    }

    #[test]
    fn end_past_eof_clamps() {
        assert_eq!(parse_range("bytes=0-200", 100), Some((0, 99)));
    }

    #[test]
    fn suffix_range_returns_tail() {
        assert_eq!(parse_range("bytes=-10", 100), Some((90, 99)));
    }

    #[test]
    fn suffix_larger_than_size_returns_full_object() {
        assert_eq!(parse_range("bytes=-100", 4), Some((0, 3)));
        assert_eq!(parse_range("bytes=-1000000", 50), Some((0, 49)));
    }

    #[test]
    fn empty_object_rejects_range() {
        assert_eq!(parse_range("bytes=0-0", 0), None);
        assert_eq!(parse_range("bytes=-10", 0), None);
    }

    #[test]
    fn suffix_zero_rejected() {
        assert_eq!(parse_range("bytes=-0", 100), None);
    }

    #[test]
    fn start_past_eof_rejected() {
        assert_eq!(parse_range("bytes=200-300", 100), None);
    }

    #[test]
    fn missing_prefix_rejected() {
        assert_eq!(parse_range("0-3", 100), None);
    }
}
