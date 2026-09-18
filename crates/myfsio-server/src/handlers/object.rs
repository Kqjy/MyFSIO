use super::*;
use futures::TryStreamExt;

pub async fn put_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    raw_query: axum::extract::RawQuery,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    streaming_sigv4: Option<axum::extract::Extension<crate::middleware::StreamingSigV4Context>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(unsupported) = unsupported_object_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The object subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }
    if let Some(resp) = guard_object_subresource(raw_query.0.as_deref(), &Method::PUT) {
        return resp;
    }
    let key = normalize_object_key(key);
    let peer_marker = peer.as_ref().map(|e| &e.0);
    let principal_ref = principal.as_ref().map(|e| &e.0);
    let owner_id = principal_ref
        .map(|p| p.user_id.clone())
        .unwrap_or_else(|| "myfsio".to_string());
    if query.tagging.is_some() {
        if query.effective_version_id().is_some() {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "PUT Object Tagging with versionId is not supported on archived versions",
            ));
        }
        let resp = config::put_object_tagging(&state, &bucket, &key, body).await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
        }
        return resp;
    }
    if query.acl.is_some() {
        let resp = config::put_object_acl(
            &state,
            &bucket,
            &key,
            query.effective_version_id(),
            &headers,
            body,
        )
        .await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
        }
        return resp;
    }
    if query.retention.is_some() {
        let resp = config::put_object_retention(
            &state,
            &bucket,
            &key,
            query.effective_version_id(),
            principal_ref,
            &headers,
            body,
        )
        .await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
        }
        return resp;
    }
    if query.legal_hold.is_some() {
        let resp = config::put_object_legal_hold(
            &state,
            &bucket,
            &key,
            query.effective_version_id(),
            body,
        )
        .await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
        }
        return resp;
    }

    if let Some(ref upload_id) = query.upload_id {
        if let Some(part_number) = query.part_number {
            if !(1..=10000).contains(&part_number) {
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Part number must be an integer between 1 and 10000",
                ));
            }
            if let Some(copy_source) = headers
                .get("x-amz-copy-source")
                .and_then(|v| v.to_str().ok())
            {
                let range = headers
                    .get("x-amz-copy-source-range")
                    .and_then(|v| v.to_str().ok());
                return upload_part_copy_handler(
                    &state,
                    &bucket,
                    upload_id,
                    part_number,
                    copy_source,
                    range,
                    &headers,
                )
                .await;
            }
            return upload_part_handler_with_chunking(
                &state,
                &bucket,
                upload_id,
                part_number,
                &headers,
                body,
                is_aws_chunked(&headers),
                streaming_sigv4.as_ref().map(|context| context.0.clone()),
            )
            .await;
        }
    }

    if let Some(copy_source) = headers
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
    {
        return copy_object_handler(
            &state,
            copy_source,
            &bucket,
            &key,
            peer_marker,
            principal_ref,
            &headers,
        )
        .await;
    }

    let bypass_governance =
        governance_bypass_allowed(&state, principal_ref, &bucket, Some(&key), &headers).await;
    if let Err(response) =
        ensure_object_lock_allows_write(&state, &bucket, &key, bypass_governance).await
    {
        return response;
    }
    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(&state, &bucket, &key, bypass_governance).await
    {
        return response;
    }
    if let Some(response) = evaluate_put_preconditions(&state, &bucket, &key, &headers).await {
        return response;
    }

    let content_type = guessed_content_type(
        &key,
        headers.get("content-type").and_then(|v| v.to_str().ok()),
    );

    let mut metadata = HashMap::new();
    metadata.insert("__content_type__".to_string(), content_type);
    if let Err(response) = insert_standard_object_metadata(&headers, &mut metadata) {
        return response;
    }
    if let Err(response) = apply_object_acl(&headers, &mut metadata, &owner_id) {
        return response;
    }
    if let Err(response) = validate_sse_request(&state, &headers) {
        return response;
    }
    let resolved_enc_ctx = match resolve_encryption_context(&state, &bucket, &headers).await {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if let Err(response) = validate_kms_key_usable(&state, resolved_enc_ctx.as_ref()).await {
        return response;
    }

    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
            if myfsio_storage::validation::is_reserved_user_metadata_key(meta_key) {
                continue;
            }
            if let Ok(val) = value.to_str() {
                metadata.insert(meta_key.to_string(), val.to_string());
            }
        }
    }

    let tags = match headers
        .get("x-amz-tagging")
        .and_then(|value| value.to_str().ok())
        .map(parse_tagging_header)
        .transpose()
    {
        Ok(tags) => tags,
        Err(response) => return response,
    };
    if let Some(ref tags) = tags {
        if tags.len() > state.config.object_tag_limit {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidTag,
                format!("Maximum {} tags allowed", state.config.object_tag_limit),
            ));
        }
    }

    persist_additional_checksums(&headers, &mut metadata);
    object_lock::apply_default_retention(&state, &bucket, &mut metadata).await;

    let aws_chunked = is_aws_chunked(&headers);
    let declared_len = declared_body_length(&headers, aws_chunked);
    let raw: myfsio_storage::traits::AsyncReadStream = if aws_chunked {
        match decode_aws_chunked_body(
            body,
            &headers,
            streaming_sigv4.map(|context| context.0),
            state.config.strict_streaming_sigv4,
        ) {
            Ok(stream) => stream,
            Err(response) => return response,
        }
    } else {
        Box::pin(tokio_util::io::StreamReader::new(
            body.into_data_stream().map_err(std::io::Error::other),
        ))
    };
    let raw = match apply_upload_checksum_verification(
        enforce_declared_length(raw, declared_len),
        &headers,
    ) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let boxed = spool_upload_stream(
        raw,
        state.config.upload_stream_buffer_bytes,
        state.config.stream_chunk_size,
        state.disk_limiter.spool_gauge(),
    );

    let _disk_permit = match acquire_disk_write_permit(&state).await {
        Ok(permit) => permit,
        Err(response) => return response,
    };

    let commit_options = myfsio_storage::traits::PutCommitOptions {
        etag_override: None,
        conditions: put_conditions_from_headers(&headers),
        bypass_governance,
        tags: None,
    };

    if let Some(enc_ctx) = resolved_enc_ctx {
        let Some(enc_svc) = state.encryption.as_ref() else {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "Encryption requested but the encryption service is disabled",
            ));
        };
        let prepared = match state.storage.allocate_prepared_tmp_path() {
            Ok(path) => path,
            Err(e) => return storage_err_response(e),
        };
        let outcome = match enc_svc
            .encrypt_stream_to_file(boxed, &prepared, &enc_ctx)
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                let _ = tokio::fs::remove_file(&prepared).await;
                return encryption_failure_response(err);
            }
        };
        let enc_size = match tokio::fs::metadata(&prepared).await {
            Ok(m) => m.len(),
            Err(e) => {
                let _ = tokio::fs::remove_file(&prepared).await;
                return storage_err_response(myfsio_storage::error::StorageError::Io(e));
            }
        };
        let mut full_meta = metadata;
        for (k, v) in outcome.metadata.to_metadata_map() {
            full_meta.insert(k, v);
        }
        if let Some(ref ck) = enc_ctx.customer_key {
            full_meta.insert(SSE_C_KEY_MD5_META.to_string(), sse_c_key_md5(ck));
        }

        let meta = match state
            .storage
            .put_object_prepared(
                &bucket,
                &key,
                &prepared,
                enc_size,
                outcome.plaintext_md5_hex.clone(),
                Some(full_meta),
                commit_options,
            )
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        };
        if let Some(ref tags) = tags {
            if let Err(e) = state.storage.set_object_tags(&bucket, &key, tags).await {
                return storage_err_response(e);
            }
        }

        let mut resp_headers = HeaderMap::new();
        if let Some(ref etag) = meta.etag {
            resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
        }
        if let Some(ref vid) = meta.version_id {
            if let Ok(value) = vid.parse() {
                resp_headers.insert("x-amz-version-id", value);
            }
        }
        resp_headers.insert(
            "x-amz-server-side-encryption",
            enc_ctx.algorithm.as_str().parse().unwrap(),
        );
        apply_stored_response_headers(&mut resp_headers, &meta.internal_metadata);
        apply_stored_checksum_headers(&mut resp_headers, &meta.internal_metadata);
        apply_stored_encryption_headers(&mut resp_headers, &meta.internal_metadata, &headers);
        notifications::emit_object_created(
            &state,
            &bucket,
            &key,
            outcome.plaintext_size,
            meta.etag.as_deref(),
            "",
            "",
            "",
            "Put",
        );
        trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
        return (StatusCode::OK, resp_headers).into_response();
    }

    match state
        .storage
        .put_object_with_commit(&bucket, &key, boxed, Some(metadata), commit_options)
        .await
    {
        Ok(meta) => {
            if let Some(ref tags) = tags {
                if let Err(e) = state.storage.set_object_tags(&bucket, &key, tags).await {
                    return storage_err_response(e);
                }
            }

            let mut resp_headers = HeaderMap::new();
            if let Some(ref etag) = meta.etag {
                resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            }
            if let Some(ref vid) = meta.version_id {
                if let Ok(value) = vid.parse() {
                    resp_headers.insert("x-amz-version-id", value);
                }
            }
            let stored = state
                .storage
                .get_object_metadata(&bucket, &key)
                .await
                .unwrap_or_default();
            apply_stored_response_headers(&mut resp_headers, &stored);
            apply_stored_checksum_headers(&mut resp_headers, &stored);
            apply_stored_encryption_headers(&mut resp_headers, &stored, &headers);
            notifications::emit_object_created(
                &state,
                &bucket,
                &key,
                meta.size,
                meta.etag.as_deref(),
                "",
                "",
                "",
                "Put",
            );
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
            (StatusCode::OK, resp_headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    raw_query: axum::extract::RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Some(unsupported) = unsupported_object_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The object subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }
    if let Some(resp) = guard_object_subresource(raw_query.0.as_deref(), &Method::GET) {
        return resp;
    }
    let key = normalize_object_key(key);
    if query.tagging.is_some() {
        return config::get_object_tagging(&state, &bucket, &key, query.effective_version_id())
            .await;
    }
    if query.acl.is_some() {
        return config::get_object_acl(&state, &bucket, &key, query.effective_version_id()).await;
    }
    if query.retention.is_some() {
        return config::get_object_retention(&state, &bucket, &key, query.effective_version_id())
            .await;
    }
    if query.legal_hold.is_some() {
        return config::get_object_legal_hold(&state, &bucket, &key, query.effective_version_id())
            .await;
    }
    if query.attributes.is_some() {
        return object_attributes_handler(
            &state,
            &bucket,
            &key,
            query.effective_version_id(),
            &headers,
        )
        .await;
    }
    if let Some(ref upload_id) = query.upload_id {
        return list_parts_handler(&state, &bucket, &key, upload_id, &query).await;
    }

    let version_id = query.effective_version_id();

    let range_header = headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if range_header.is_some() && query.part_number.is_some() {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "Cannot specify both Range and partNumber on the same request",
        ));
    }

    if let Some(ref range_str) = range_header {
        return range_get_handler(&state, &bucket, &key, range_str, &query, &headers).await;
    }

    let part_window = match query.part_number {
        Some(part_number) => {
            let head = match version_id {
                Some(v) => state.storage.head_object_version(&bucket, &key, v).await,
                None => state.storage.head_object(&bucket, &key).await,
            };
            head.ok()
                .and_then(|head_meta| resolve_part_view(&head_meta, part_number).ok())
                .filter(|view| view.multipart && view.length > 0)
                .map(|view| myfsio_storage::traits::RangeHint {
                    start: Some(view.start),
                    end: Some(view.start + view.length - 1),
                })
        }
        None => None,
    };
    let snapshot =
        match object_read::snapshot_object_for_read(&state, &bucket, &key, version_id, part_window)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(e) => return storage_err_response(e),
        };

    if mpu_is_sse_c(&snapshot.meta.internal_metadata) {
        if let Some(resp) = evaluate_get_preconditions(&headers, &snapshot.meta) {
            snapshot.discard().await;
            return resp;
        }
        let object_read::ObjectSnapshot { meta, link, .. } = snapshot;
        return serve_mpu_sse_c(
            &state,
            link,
            meta,
            &headers,
            &query,
            None,
            query.part_number,
        )
        .await;
    }

    if let Some(part_number) = query.part_number {
        match resolve_part_view(&snapshot.meta, part_number) {
            Ok(view) if view.multipart => {
                if view.length == 0 {
                    if let Some(resp) = evaluate_get_preconditions(&headers, &snapshot.meta) {
                        snapshot.discard().await;
                        return resp;
                    }
                    snapshot.discard().await;
                    let mut h = build_part_response_headers(&key, &snapshot.meta, &view, &query);
                    apply_user_metadata(&mut h, &snapshot.meta.metadata);
                    return (StatusCode::PARTIAL_CONTENT, h).into_response();
                }
                let range_str = format!("bytes={}-{}", view.start, view.start + view.length - 1);
                return serve_range_from_snapshot(
                    &state,
                    snapshot,
                    &range_str,
                    &query,
                    &headers,
                    Some(view.parts_count),
                )
                .await;
            }
            Ok(_) => {}
            Err(resp) => {
                snapshot.discard().await;
                return resp;
            }
        }
    }

    if let Some(resp) = evaluate_get_preconditions(&headers, &snapshot.meta) {
        snapshot.discard().await;
        return resp;
    }

    if let Err(resp) = require_sse_c_key_for_object(&state, &snapshot.meta, &headers) {
        snapshot.discard().await;
        return resp;
    }

    let verification_target = version_id
        .is_none()
        .then_some((bucket.as_str(), key.as_str()));
    let served =
        match object_read::serve_object_data(&state, snapshot, None, &headers, verification_target)
            .await
        {
            Ok(served) => served,
            Err(err) => return object_read_error_response(err),
        };
    let enc_header = served.encryption_algorithm.as_deref();
    let body = served.body;

    let meta = &served.meta;
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        "content-length",
        served.content_length.to_string().parse().unwrap(),
    );
    if let Some(ref etag) = meta.etag {
        resp_headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
    }
    insert_content_type(&mut resp_headers, &key, meta.content_type.as_deref());
    resp_headers.insert(
        "last-modified",
        meta.last_modified
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string()
            .parse()
            .unwrap(),
    );
    resp_headers.insert("accept-ranges", "bytes".parse().unwrap());
    if let Some(alg) = enc_header {
        resp_headers.insert("x-amz-server-side-encryption", alg.parse().unwrap());
    }
    apply_stored_kms_key_header(&mut resp_headers, &meta.internal_metadata);
    apply_stored_response_headers(&mut resp_headers, &meta.internal_metadata);
    if checksum_mode_enabled(&headers) {
        apply_stored_checksum_headers(&mut resp_headers, &meta.internal_metadata);
    }
    if let Some(ref requested_version) = query.version_id {
        if let Ok(value) = requested_version.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    } else if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    }
    apply_user_metadata(&mut resp_headers, &meta.metadata);
    apply_response_overrides(&mut resp_headers, &query);

    (StatusCode::OK, resp_headers, body).into_response()
}

pub async fn post_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    raw_query: axum::extract::RawQuery,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(unsupported) = unsupported_object_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The object subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }
    if let Some(resp) = guard_object_subresource(raw_query.0.as_deref(), &Method::POST) {
        return resp;
    }
    let key = normalize_object_key(key);
    let peer_marker = peer.as_ref().map(|e| &e.0);
    let principal_ref = principal.as_ref().map(|e| &e.0);
    if query.uploads.is_some() {
        return initiate_multipart_handler(&state, &bucket, &key, &headers).await;
    }

    if let Some(ref upload_id) = query.upload_id {
        return complete_multipart_handler(
            &state,
            &bucket,
            &key,
            upload_id,
            peer_marker,
            principal_ref,
            &headers,
            body,
        )
        .await;
    }

    if query.select.is_some() {
        return select::post_select_object_content(&state, &bucket, &key, &headers, body).await;
    }

    s3_error_response(S3Error::from_code(S3ErrorCode::MethodNotAllowed))
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    raw_query: axum::extract::RawQuery,
    peer: Option<axum::extract::Extension<crate::middleware::ReplicationPeerRequest>>,
    principal: Option<axum::extract::Extension<myfsio_common::types::Principal>>,
    headers: HeaderMap,
) -> Response {
    if let Some(unsupported) = unsupported_object_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The object subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }
    if let Some(resp) = guard_object_subresource(raw_query.0.as_deref(), &Method::DELETE) {
        return resp;
    }
    let key = normalize_object_key(key);
    let peer_marker = peer.as_ref().map(|e| &e.0);
    let principal_ref = principal.as_ref().map(|e| &e.0);
    if query.tagging.is_some() {
        if query.effective_version_id().is_some() {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidArgument,
                "DELETE Object Tagging with versionId is not supported on archived versions",
            ));
        }
        let resp = config::delete_object_tagging(&state, &bucket, &key).await;
        if resp.status().is_success() {
            trigger_replication_for_request(&state, peer_marker, &bucket, &key, "write", None);
        }
        return resp;
    }
    if query.acl.is_some() {
        return StatusCode::NO_CONTENT.into_response();
    }

    if let Some(ref upload_id) = query.upload_id {
        return abort_multipart_handler(&state, &bucket, upload_id).await;
    }

    let bypass_governance =
        governance_bypass_allowed(&state, principal_ref, &bucket, Some(&key), &headers).await;

    if let Some(version_id) = query.effective_version_id() {
        if let Err(response) = ensure_object_version_lock_allows_delete(
            &state,
            &bucket,
            &key,
            version_id,
            bypass_governance,
        )
        .await
        {
            return response;
        }
        return match state
            .storage
            .delete_object_version_checked(&bucket, &key, version_id, bypass_governance)
            .await
        {
            Ok(outcome) => {
                let mut resp_headers = HeaderMap::new();
                if let Some(ref vid) = outcome.version_id {
                    if let Ok(value) = vid.parse() {
                        resp_headers.insert("x-amz-version-id", value);
                    }
                }
                if outcome.is_delete_marker {
                    resp_headers.insert("x-amz-delete-marker", "true".parse().unwrap());
                }
                notifications::emit_object_removed(&state, &bucket, &key, "", "", "", "Delete");
                let action = if outcome.is_delete_marker {
                    "delete-marker"
                } else {
                    "delete"
                };
                trigger_replication_for_request(
                    &state,
                    peer_marker,
                    &bucket,
                    &key,
                    action,
                    outcome.version_id.as_deref().or(Some(version_id)),
                );
                (StatusCode::NO_CONTENT, resp_headers).into_response()
            }
            Err(e) => storage_err_response(e),
        };
    }

    if let Err(response) =
        ensure_object_lock_allows_write(&state, &bucket, &key, bypass_governance).await
    {
        return response;
    }

    match state
        .storage
        .delete_object_checked(&bucket, &key, bypass_governance)
        .await
    {
        Ok(outcome) => {
            let mut resp_headers = HeaderMap::new();
            if let Some(ref vid) = outcome.version_id {
                if let Ok(value) = vid.parse() {
                    resp_headers.insert("x-amz-version-id", value);
                }
            }
            if outcome.is_delete_marker {
                resp_headers.insert("x-amz-delete-marker", "true".parse().unwrap());
            }
            notifications::emit_object_removed(&state, &bucket, &key, "", "", "", "Delete");
            let action = if outcome.is_delete_marker {
                "delete-marker"
            } else {
                "delete"
            };
            trigger_replication_for_request(
                &state,
                peer_marker,
                &bucket,
                &key,
                action,
                outcome.version_id.as_deref(),
            );
            (StatusCode::NO_CONTENT, resp_headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}

pub async fn head_object(
    State(state): State<AppState>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<ObjectQuery>,
    raw_query: axum::extract::RawQuery,
    headers: HeaderMap,
) -> Response {
    if let Some(unsupported) = unsupported_object_subresource(raw_query.0.as_deref()) {
        return s3_error_response(S3Error::new(
            S3ErrorCode::NotImplemented,
            format!(
                "The object subresource '?{}' is not implemented by this server",
                unsupported
            ),
        ));
    }
    let key = normalize_object_key(key);
    let checksum_requested = checksum_mode_enabled(&headers);
    let version_id = query.effective_version_id();
    let result = match version_id {
        Some(version_id) => {
            state
                .storage
                .head_object_version(&bucket, &key, version_id)
                .await
        }
        None => state.storage.head_object(&bucket, &key).await,
    };

    match result {
        Ok(meta) => {
            if let Some(resp) = evaluate_get_preconditions(&headers, &meta) {
                return resp;
            }

            if mpu_is_sse_c(&meta.internal_metadata) {
                return head_mpu_sse_c(&meta, &headers, &query);
            }

            let enc_info = myfsio_crypto::encryption::EncryptionMetadata::from_metadata(
                &meta.internal_metadata,
            );
            if let Some(ref info) = enc_info {
                if info.algorithm == "AES256" && info.encrypted_data_key.is_none() {
                    if let Err(resp) = require_sse_c_key_match(&headers, &meta.internal_metadata) {
                        return resp;
                    }
                }
            }

            let part_view = match query.part_number {
                Some(n) => match resolve_part_view(&meta, n) {
                    Ok(v) => Some(v),
                    Err(resp) => return resp,
                },
                None => None,
            };

            if let Some(view) = part_view.as_ref().filter(|v| v.multipart) {
                let mut headers = build_part_response_headers(&key, &meta, view, &query);
                apply_user_metadata(&mut headers, &meta.metadata);
                return (StatusCode::PARTIAL_CONTENT, headers).into_response();
            }

            let mut headers = HeaderMap::new();
            let plaintext_size = object_read::plaintext_size(&meta);
            headers.insert(
                "content-length",
                plaintext_size.to_string().parse().unwrap(),
            );
            if let Some(ref etag) = meta.etag {
                headers.insert("etag", format!("\"{}\"", etag).parse().unwrap());
            }
            insert_content_type(&mut headers, &key, meta.content_type.as_deref());
            headers.insert(
                "last-modified",
                meta.last_modified
                    .format("%a, %d %b %Y %H:%M:%S GMT")
                    .to_string()
                    .parse()
                    .unwrap(),
            );
            headers.insert("accept-ranges", "bytes".parse().unwrap());
            if let Some(ref enc_info) = enc_info {
                if let Ok(alg) = enc_info.algorithm.as_str().parse() {
                    headers.insert("x-amz-server-side-encryption", alg);
                }
                if let Some(ref kid) = enc_info.kms_key_id {
                    if let Ok(value) = kid.parse() {
                        headers.insert("x-amz-server-side-encryption-aws-kms-key-id", value);
                    }
                }
            }
            apply_stored_response_headers(&mut headers, &meta.internal_metadata);
            if checksum_requested {
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

            (StatusCode::OK, headers).into_response()
        }
        Err(e) => storage_err_response(e),
    }
}
