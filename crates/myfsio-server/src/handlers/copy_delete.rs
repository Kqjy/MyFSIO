use super::*;

pub(super) async fn object_attributes_handler(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    let meta = match version_id {
        Some(version_id) => match state
            .storage
            .head_object_version(bucket, key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.head_object(bucket, key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };

    let requested = headers
        .get("x-amz-object-attributes")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let attrs: std::collections::HashSet<String> = requested
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let all = attrs.is_empty();

    let stored_meta = match version_id {
        Some(version_id) => state
            .storage
            .get_object_version_metadata(bucket, key, version_id)
            .await
            .unwrap_or_default(),
        None => state
            .storage
            .get_object_metadata(bucket, key)
            .await
            .unwrap_or_default(),
    };

    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    xml.push_str("<GetObjectAttributesResponse xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");

    if all || attrs.contains("etag") {
        if let Some(etag) = &meta.etag {
            let trimmed = etag.trim_matches('"');
            xml.push_str(&format!("<ETag>\"{}\"</ETag>", xml_escape(trimmed)));
        }
    }
    if all || attrs.contains("storageclass") {
        let sc = meta.storage_class.as_deref().unwrap_or("STANDARD");
        xml.push_str(&format!("<StorageClass>{}</StorageClass>", xml_escape(sc)));
    }
    if all || attrs.contains("objectsize") {
        xml.push_str(&format!(
            "<ObjectSize>{}</ObjectSize>",
            object_read::plaintext_size(&meta)
        ));
    }
    if all || attrs.contains("checksum") {
        let mut checksum_xml = String::new();
        for (algo, tag) in [
            ("sha256", "ChecksumSHA256"),
            ("sha1", "ChecksumSHA1"),
            ("crc32", "ChecksumCRC32"),
            ("crc32c", "ChecksumCRC32C"),
            ("crc64nvme", "ChecksumCRC64NVME"),
        ] {
            let key_name = format!("__checksum_{}__", algo);
            if let Some(value) = stored_meta.get(&key_name) {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    checksum_xml.push_str(&format!(
                        "<{tag}>{}</{tag}>",
                        xml_escape(trimmed),
                        tag = tag
                    ));
                }
            }
        }
        if !checksum_xml.is_empty() {
            xml.push_str("<Checksum>");
            xml.push_str(&checksum_xml);
            xml.push_str("</Checksum>");
        }
    }
    if attrs.contains("objectparts") {
        xml.push_str("<ObjectParts></ObjectParts>");
    }

    xml.push_str("</GetObjectAttributesResponse>");
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("content-type", "application/xml".parse().unwrap());
    if let Some(version_id) = meta.version_id.as_deref() {
        if let Ok(value) = version_id.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    }
    (StatusCode::OK, resp_headers, xml).into_response()
}

pub(super) async fn copy_object_handler(
    state: &AppState,
    copy_source: &str,
    dst_bucket: &str,
    dst_key: &str,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    principal: Option<&myfsio_common::types::Principal>,
    headers: &HeaderMap,
) -> Response {
    let bypass_governance =
        governance_bypass_allowed(state, principal, dst_bucket, Some(dst_key), headers).await;
    if let Err(response) =
        ensure_object_lock_allows_write(state, dst_bucket, dst_key, bypass_governance).await
    {
        return response;
    }
    if let Err(response) =
        ensure_archived_null_lock_allows_overwrite(state, dst_bucket, dst_key, bypass_governance)
            .await
    {
        return response;
    }
    let mut requested_object_lock_metadata = HashMap::new();
    if let Err(response) = insert_object_lock_metadata(headers, &mut requested_object_lock_metadata)
    {
        return response;
    }

    let (src_bucket, src_key, src_version_id) = match parse_copy_source(copy_source) {
        Ok(parts) => parts,
        Err(response) => return response,
    };

    let source_meta = match src_version_id.as_deref() {
        Some(version_id) => match state
            .storage
            .head_object_version(&src_bucket, &src_key, version_id)
            .await
        {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
        None => match state.storage.head_object(&src_bucket, &src_key).await {
            Ok(m) => m,
            Err(e) => return storage_err_response(e),
        },
    };
    if let Some(resp) = evaluate_copy_preconditions(headers, &source_meta) {
        return resp;
    }

    let metadata_directive = headers
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_uppercase())
        .unwrap_or_else(|| "COPY".to_string());
    let tagging_directive = headers
        .get("x-amz-tagging-directive")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_uppercase())
        .unwrap_or_else(|| "COPY".to_string());
    let replace_metadata = metadata_directive == "REPLACE";
    let replace_tagging = tagging_directive == "REPLACE";

    let same_object = src_bucket == dst_bucket
        && src_key == dst_key
        && src_version_id.as_deref().unwrap_or("").is_empty();
    if same_object && !replace_metadata && !replace_tagging {
        return s3_error_response(S3Error::new(
            S3ErrorCode::InvalidRequest,
            "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
        ));
    }

    let resolved_tags: Option<Vec<myfsio_common::types::Tag>> = if replace_tagging {
        let parsed = match headers
            .get("x-amz-tagging")
            .and_then(|value| value.to_str().ok())
            .map(parse_tagging_header)
            .transpose()
        {
            Ok(tags) => tags,
            Err(response) => return response,
        };
        let tags = parsed.unwrap_or_default();
        if tags.len() > state.config.object_tag_limit {
            return s3_error_response(S3Error::new(
                S3ErrorCode::InvalidTag,
                format!("Maximum {} tags allowed", state.config.object_tag_limit),
            ));
        }
        Some(tags)
    } else {
        let lookup = match src_version_id.as_deref() {
            Some(version_id) => {
                state
                    .storage
                    .get_object_version_tags(&src_bucket, &src_key, version_id)
                    .await
            }
            None => state.storage.get_object_tags(&src_bucket, &src_key).await,
        };
        match lookup {
            Ok(tags) => Some(tags),
            Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => None,
            Err(myfsio_storage::error::StorageError::VersionNotFound { .. }) => None,
            Err(e) => return storage_err_response(e),
        }
    };

    let mut dst_enc_ctx = match resolve_encryption_context(state, dst_bucket, headers).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };

    if dst_enc_ctx.is_none() {
        let src_alg = source_meta
            .internal_metadata
            .get("x-amz-server-side-encryption")
            .map(|s| s.as_str());
        match src_alg {
            Some("AES256") => {
                let is_sse_c = !source_meta
                    .internal_metadata
                    .contains_key("x-amz-encrypted-data-key");
                if !is_sse_c && state.encryption.is_some() {
                    dst_enc_ctx = Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::Aes256,
                        kms_key_id: None,
                        customer_key: None,
                    });
                }
            }
            Some("aws:kms") => {
                let kid = source_meta
                    .internal_metadata
                    .get("x-amz-encryption-key-id")
                    .cloned();
                if state.encryption.is_some() && kid.is_some() {
                    dst_enc_ctx = Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::AwsKms,
                        kms_key_id: kid,
                        customer_key: None,
                    });
                }
            }
            _ => {}
        }
    }

    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
        return storage_err_response(myfsio_storage::error::StorageError::Io(e));
    }

    let src_snap = tmp_dir.join(format!("copy-src-{}", uuid::Uuid::new_v4()));
    let snap_meta = match src_version_id.as_deref() {
        Some(version_id) => {
            state
                .storage
                .snapshot_object_version_to_link(&src_bucket, &src_key, version_id, &src_snap)
                .await
        }
        None => {
            state
                .storage
                .snapshot_object_to_link(&src_bucket, &src_key, &src_snap)
                .await
        }
    };
    let (snap_meta, snap_source) = match snap_meta {
        Ok(m) => m,
        Err(e) => {
            let _ = tokio::fs::remove_file(&src_snap).await;
            return storage_err_response(e);
        }
    };
    let source_path = match snap_source {
        myfsio_storage::traits::SnapshotSource::LinkedFile(_) => src_snap.clone(),
        segments => {
            let dest = tmp_dir.join(format!("copy-mat-{}", uuid::Uuid::new_v4()));
            let mut reader = match segments.into_range_stream(0, None).await {
                Ok(reader) => reader,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&src_snap).await;
                    return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                }
            };
            let mut out = match tokio::fs::File::create(&dest).await {
                Ok(out) => out,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&src_snap).await;
                    return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                }
            };
            if let Err(e) = tokio::io::copy(&mut reader, &mut out).await {
                let _ = tokio::fs::remove_file(&dest).await;
                return storage_err_response(myfsio_storage::error::StorageError::Io(e));
            }
            dest
        }
    };

    let snap_internal = &snap_meta.internal_metadata;

    let dst_metadata = if replace_metadata {
        let mut m: HashMap<String, String> = HashMap::new();
        for (request_header, metadata_key, _) in internal_header_pairs() {
            if let Some(value) = headers.get(*request_header).and_then(|v| v.to_str().ok()) {
                if *request_header == "content-encoding" {
                    if let Some(decoded_encoding) = decoded_content_encoding(value) {
                        m.insert((*metadata_key).to_string(), decoded_encoding);
                    }
                } else {
                    m.insert((*metadata_key).to_string(), value.to_string());
                }
            }
        }
        let content_type = guessed_content_type(
            dst_key,
            headers.get("content-type").and_then(|v| v.to_str().ok()),
        );
        m.insert("__content_type__".to_string(), content_type);
        for (name, value) in headers.iter() {
            let name_str = name.as_str();
            if let Some(meta_key) = name_str.strip_prefix("x-amz-meta-") {
                if myfsio_storage::validation::is_reserved_user_metadata_key(meta_key) {
                    continue;
                }
                if let Ok(val) = value.to_str() {
                    m.insert(meta_key.to_string(), val.to_string());
                }
            }
        }
        if let Some(value) = headers
            .get("x-amz-storage-class")
            .and_then(|v| v.to_str().ok())
        {
            let upper = value.to_ascii_uppercase();
            if !VALID_STORAGE_CLASSES.contains(&upper.as_str()) {
                let _ = tokio::fs::remove_file(&src_snap).await;
                return s3_error_response(S3Error::new(
                    S3ErrorCode::InvalidArgument,
                    "Invalid x-amz-storage-class",
                ));
            }
            m.insert("__storage_class__".to_string(), upper);
        }
        m
    } else {
        let mut m = snap_internal.clone();
        myfsio_crypto::encryption::EncryptionMetadata::clean_metadata(&mut m);
        m
    };

    let src_enc_info = myfsio_crypto::encryption::EncryptionMetadata::from_metadata(snap_internal);

    let plaintext_path = if let Some(enc_info) = src_enc_info.as_ref() {
        let Some(enc_svc) = state.encryption.as_ref() else {
            let _ = tokio::fs::remove_file(&source_path).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "Source object is encrypted but encryption service is disabled",
            ));
        };
        let customer_key = match resolve_copy_source_sse_c_key(headers, snap_internal) {
            Ok(k) => k,
            Err(resp) => {
                let _ = tokio::fs::remove_file(&source_path).await;
                return resp;
            }
        };
        let dec_tmp = tmp_dir.join(format!("copy-dec-{}", uuid::Uuid::new_v4()));
        if let Err(e) = enc_svc
            .decrypt_object(&source_path, &dec_tmp, enc_info, customer_key.as_deref())
            .await
        {
            let _ = tokio::fs::remove_file(&source_path).await;
            let _ = tokio::fs::remove_file(&dec_tmp).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                format!("Source decryption failed: {}", e),
            ));
        }
        let _ = tokio::fs::remove_file(&source_path).await;
        dec_tmp
    } else {
        source_path
    };

    let mut dst_metadata = dst_metadata;
    strip_storage_managed_keys(&mut dst_metadata);
    dst_metadata.remove(myfsio_storage::segments::META_KEY_SEGMENTS);
    dst_metadata.remove("__part_sizes__");
    dst_metadata.extend(requested_object_lock_metadata);
    object_lock::apply_default_retention(state, dst_bucket, &mut dst_metadata).await;

    let (publish_path, publish_metadata, plaintext_etag_override) = if let Some(enc_ctx) =
        dst_enc_ctx
    {
        let Some(enc_svc) = state.encryption.as_ref() else {
            let _ = tokio::fs::remove_file(&plaintext_path).await;
            return s3_error_response(S3Error::new(
                S3ErrorCode::InternalError,
                "Encryption requested but encryption service is disabled",
            ));
        };
        let plaintext_md5 = if enc_ctx.algorithm == myfsio_crypto::encryption::SseAlgorithm::Aes256
        {
            match compute_plaintext_md5(&plaintext_path).await {
                Ok(md5) => Some(md5),
                Err(e) => {
                    let _ = tokio::fs::remove_file(&plaintext_path).await;
                    return storage_err_response(myfsio_storage::error::StorageError::Io(e));
                }
            }
        } else {
            None
        };
        let enc_tmp = tmp_dir.join(format!("copy-enc-{}", uuid::Uuid::new_v4()));
        let enc_meta = match enc_svc
            .encrypt_object(&plaintext_path, &enc_tmp, &enc_ctx)
            .await
        {
            Ok(m) => m,
            Err(e) => {
                let _ = tokio::fs::remove_file(&plaintext_path).await;
                let _ = tokio::fs::remove_file(&enc_tmp).await;
                return encryption_failure_response(e);
            }
        };
        let _ = tokio::fs::remove_file(&plaintext_path).await;
        let mut merged = dst_metadata;
        for (k, v) in enc_meta.to_metadata_map() {
            merged.insert(k, v);
        }
        (enc_tmp, merged, plaintext_md5)
    } else {
        (plaintext_path, dst_metadata, None)
    };

    let publish_file = match tokio::fs::File::open(&publish_path).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(&publish_path).await;
            return storage_err_response(myfsio_storage::error::StorageError::Io(e));
        }
    };
    let reader: myfsio_storage::traits::AsyncReadStream = Box::pin(publish_file);

    let copy_result = state
        .storage
        .put_object_with_commit(
            dst_bucket,
            dst_key,
            reader,
            Some(publish_metadata),
            myfsio_storage::traits::PutCommitOptions {
                etag_override: plaintext_etag_override,
                conditions: Default::default(),
                bypass_governance,
                tags: None,
            },
        )
        .await;

    let _ = tokio::fs::remove_file(&publish_path).await;

    let meta = match copy_result {
        Ok(m) => m,
        Err(e) => return storage_err_response(e),
    };

    if let Some(tags) = resolved_tags.as_deref() {
        if let Err(e) = state
            .storage
            .set_object_tags(dst_bucket, dst_key, tags)
            .await
        {
            return storage_err_response(e);
        }
    }

    let Some(etag) = meta.etag.as_deref() else {
        tracing::error!(
            src_bucket = %src_bucket,
            src_key = %src_key,
            dst_bucket = dst_bucket,
            dst_key = dst_key,
            "copy_object stored object without etag"
        );
        return s3_error_response(S3Error::from_code(S3ErrorCode::InternalError));
    };
    let last_modified = myfsio_xml::response::format_s3_datetime(&meta.last_modified);
    let xml = myfsio_xml::response::copy_object_result_xml(etag, &last_modified);
    trigger_replication_for_request(state, peer_marker, dst_bucket, dst_key, "write", None);

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("content-type", "application/xml".parse().unwrap());
    if let Some(ref vid) = meta.version_id {
        if let Ok(value) = vid.parse() {
            resp_headers.insert("x-amz-version-id", value);
        }
    }
    if let Some(ref src_vid) = src_version_id {
        if let Ok(value) = src_vid.parse() {
            resp_headers.insert("x-amz-copy-source-version-id", value);
        }
    }
    let stored = state
        .storage
        .get_object_metadata(dst_bucket, dst_key)
        .await
        .unwrap_or_default();
    apply_stored_response_headers(&mut resp_headers, &stored);
    apply_stored_checksum_headers(&mut resp_headers, &stored);
    apply_stored_encryption_headers(&mut resp_headers, &stored, headers);

    (StatusCode::OK, resp_headers, xml).into_response()
}

pub(super) async fn delete_objects_handler(
    state: &AppState,
    bucket: &str,
    peer_marker: Option<&crate::middleware::ReplicationPeerRequest>,
    principal: Option<&myfsio_common::types::Principal>,
    bypass_requested: bool,
    body: Body,
) -> Response {
    let body_bytes = match collect_body_limited(body, BULK_XML_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(response) => return response,
    };

    let xml_str = String::from_utf8_lossy(&body_bytes);
    let parsed = match myfsio_xml::request::parse_delete_objects(&xml_str) {
        Ok(p) => p,
        Err(e) => {
            return s3_error_response(S3Error::new(
                myfsio_common::error::S3ErrorCode::MalformedXML,
                e,
            ));
        }
    };

    if parsed.objects.len() > 1000 {
        return s3_error_response(S3Error::new(
            S3ErrorCode::MalformedXML,
            "The request must not contain more than 1000 keys",
        ));
    }

    use futures::stream::{self, StreamExt};

    let results: Vec<(
        String,
        Option<String>,
        Result<myfsio_common::types::DeleteOutcome, (String, String)>,
    )> = stream::iter(parsed.objects.iter().cloned())
        .map(|obj| {
            let state = state.clone();
            let bucket = bucket.to_string();
            let principal = principal.cloned();
            async move {
                let key = obj.key.clone();
                let requested_vid = obj.version_id.clone();
                let version_scoped = obj.version_id.as_deref().is_some_and(|v| !v.is_empty());
                if let Err(err) = crate::middleware::authorize_action(
                    &state,
                    principal.as_ref(),
                    &bucket,
                    "delete",
                    Some(if version_scoped {
                        "s3:DeleteObjectVersion"
                    } else {
                        "s3:DeleteObject"
                    }),
                    Some(&obj.key),
                    Some(true),
                    &crate::middleware::current_request_context(principal.as_ref()),
                )
                .await
                {
                    return (
                        key,
                        requested_vid,
                        Err((err.code.as_str().to_string(), err.message)),
                    );
                }
                let bypass = bypass_requested
                    && governance_bypass_authorized(
                        &state,
                        principal.as_ref(),
                        &bucket,
                        Some(&obj.key),
                    )
                    .await;
                let to_err = |err: myfsio_storage::error::StorageError| -> (String, String) {
                    let s3err = S3Error::from(err);
                    (s3err.code.as_str().to_string(), s3err.message)
                };
                let run_can_delete =
                    |metadata: &HashMap<String, String>| -> Result<(), (String, String)> {
                        object_lock::can_delete_object(metadata, bypass)
                            .map_err(|m| (S3ErrorCode::AccessDenied.as_str().to_string(), m))
                    };
                let lock_check: Result<(), (String, String)> = match obj.version_id.as_deref() {
                    Some(version_id) => {
                        match state
                            .storage
                            .get_object_version_metadata(&bucket, &obj.key, version_id)
                            .await
                        {
                            Ok(metadata) => run_can_delete(&metadata),
                            Err(myfsio_storage::error::StorageError::VersionNotFound {
                                ..
                            }) => Ok(()),
                            Err(err) => Err(to_err(err)),
                        }
                    }
                    None => match state.storage.head_object(&bucket, &obj.key).await {
                        Ok(meta) => run_can_delete(&meta.internal_metadata),
                        Err(myfsio_storage::error::StorageError::ObjectCorrupted { .. }) => {
                            match state.storage.get_object_metadata(&bucket, &obj.key).await {
                                Ok(metadata) => run_can_delete(&metadata),
                                Err(err) => Err(to_err(err)),
                            }
                        }
                        Err(myfsio_storage::error::StorageError::ObjectNotFound { .. }) => Ok(()),
                        Err(myfsio_storage::error::StorageError::DeleteMarker { .. }) => Ok(()),
                        Err(err) => Err(to_err(err)),
                    },
                };

                let result = match lock_check {
                    Err(e) => Err(e),
                    Ok(()) => {
                        let outcome = match obj.version_id.as_deref() {
                            Some(version_id) => {
                                state
                                    .storage
                                    .delete_object_version_checked(
                                        &bucket, &obj.key, version_id, bypass,
                                    )
                                    .await
                            }
                            None => {
                                state
                                    .storage
                                    .delete_object_checked(&bucket, &obj.key, bypass)
                                    .await
                            }
                        };
                        outcome.map_err(|e| {
                            let s3err = S3Error::from(e);
                            (s3err.code.as_str().to_string(), s3err.message)
                        })
                    }
                };
                (key, requested_vid, result)
            }
        })
        .buffer_unordered(32)
        .collect()
        .await;

    let mut deleted: Vec<myfsio_xml::response::DeletedEntry> = Vec::new();
    let mut errors: Vec<(String, Option<String>, String, String)> = Vec::new();
    for (key, requested_vid, result) in results {
        match result {
            Ok(outcome) => {
                notifications::emit_object_removed(state, bucket, &key, "", "", "", "Delete");
                let action = if outcome.is_delete_marker {
                    "delete-marker"
                } else {
                    "delete"
                };
                trigger_replication_for_request(
                    state,
                    peer_marker,
                    bucket,
                    &key,
                    action,
                    outcome.version_id.as_deref().or(requested_vid.as_deref()),
                );
                let delete_marker_version_id = if outcome.is_delete_marker {
                    outcome.version_id.clone()
                } else {
                    None
                };
                deleted.push(myfsio_xml::response::DeletedEntry {
                    key,
                    version_id: requested_vid,
                    delete_marker: outcome.is_delete_marker,
                    delete_marker_version_id,
                });
            }
            Err((code, message)) => {
                errors.push((key, requested_vid, code, message));
            }
        }
    }

    let xml = myfsio_xml::response::delete_result_xml(&deleted, &errors, parsed.quiet);
    (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
}
