pub mod admin;
pub mod admin_peer;
mod checksum_stream;
mod chunked;
pub(crate) mod config;
pub mod kms;
pub(crate) mod object_read;
mod select;
pub mod static_assets;
pub mod ui;
pub mod ui_api;
pub mod ui_pages;

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use serde_json::json;

use myfsio_common::error::{S3Error, S3ErrorCode};
use myfsio_common::types::PartInfo;
use myfsio_storage::traits::StorageEngine;
use tokio_util::io::ReaderStream;

use crate::services::notifications;
use crate::services::object_lock;
use crate::state::AppState;

mod acl_headers;
mod bucket;
mod checksums;
mod common;
mod copy_delete;
mod encryption;
mod multipart;
mod object;
mod object_headers;
mod post_form;
mod preconditions;
mod range;
mod subresource;
#[cfg(test)]
mod tests;

use acl_headers::{apply_object_acl, header_acl_request, VALID_STORAGE_CLASSES};
pub use bucket::{
    create_bucket, delete_bucket, get_bucket, head_bucket, health_check, list_buckets, post_bucket,
    BucketQuery,
};
use checksums::{
    apply_stored_checksum_headers, apply_upload_checksum_verification, aws_chunked_error_response,
    bad_digest_response, checksum_mode_enabled, decode_aws_chunked_body, invalid_digest_response,
    persist_additional_checksums,
};
pub use common::RelayContext;
use common::{
    build_owner_display_map, canonical_default_owner, ensure_archived_null_lock_allows_overwrite,
    ensure_object_lock_allows_write, ensure_object_version_lock_allows_delete,
    error_chain_has_body_timeout, open_self_deleting, parse_max_keys, storage_err_response,
    trigger_replication, trigger_replication_for_request, validate_encoding_type,
};
pub(crate) use common::{
    collect_body_capped, collect_body_limited, s3_error_response, BodyLimitError,
    BULK_XML_BODY_LIMIT, CONFIG_BODY_LIMIT, JSON_API_BODY_LIMIT, POST_FORM_FIELD_LIMIT,
};
use copy_delete::{copy_object_handler, delete_objects_handler, object_attributes_handler};
use encryption::{
    apply_stored_encryption_headers, apply_stored_kms_key_header, apply_stored_response_headers,
    compute_plaintext_md5, constant_time_eq, encryption_failure_response, extract_sse_c_key,
    require_sse_c_key_for_object, require_sse_c_key_match, resolve_copy_source_sse_c_key,
    resolve_encryption_context, sse_c_key_md5, strip_storage_managed_keys, validate_kms_key_usable,
    validate_sse_request, SSE_C_KEY_MD5_META,
};
use multipart::{
    abort_multipart_handler, acquire_disk_read_permit, acquire_disk_write_permit,
    attach_read_permit, build_part_response_headers, complete_multipart_handler, head_mpu_sse_c,
    initiate_multipart_handler, list_multipart_uploads_handler, list_parts_handler, mpu_is_sse_c,
    resolve_part_view, serve_mpu_sse_c, spool_upload_stream, upload_part_copy_handler,
    upload_part_handler_with_chunking,
};
pub use object::{delete_object, get_object, head_object, post_object, put_object};
pub use object_headers::ObjectQuery;
use object_headers::{
    apply_response_overrides, apply_user_metadata, declared_body_length, decoded_content_encoding,
    enforce_declared_length, guessed_content_type, insert_content_type,
    insert_object_lock_metadata, insert_standard_object_metadata, internal_header_pairs,
    is_aws_chunked, normalize_object_key, parse_copy_source, parse_tagging_header,
};
use post_form::post_object_form_handler;
use preconditions::{
    bypass_governance_header, evaluate_copy_preconditions, evaluate_get_preconditions,
    evaluate_put_preconditions, put_conditions_from_headers, xml_escape,
};
pub(crate) use preconditions::{governance_bypass_allowed, governance_bypass_authorized};
use range::{
    object_read_error_response, parse_range, range_get_handler, serve_range_from_snapshot,
};
pub use subresource::{
    ambiguous_subresource_error, bucket_method_default_s3_action, object_method_default_action,
    object_method_default_s3_action, parse_bucket_subresource, parse_object_subresource,
    query_has_version_id, BucketSubresource, ObjectSubresource,
};
use subresource::{
    guard_object_subresource, subresource_method_not_allowed, unsupported_bucket_subresource,
    unsupported_object_subresource,
};
