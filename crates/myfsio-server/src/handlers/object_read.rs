use axum::body::Body;
use axum::http::HeaderMap;
use axum::response::Response;
use md5::{Digest, Md5};
use myfsio_common::types::ObjectMeta;
use myfsio_crypto::encryption::EncryptionMetadata;
use myfsio_storage::error::StorageError;
use myfsio_storage::traits::{AsyncReadStream, RangeHint, SnapshotSource, StorageEngine};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, ReadBuf};
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::io::ReaderStream;

use super::{
    acquire_disk_read_permit, attach_read_permit, extract_sse_c_key, mpu_is_sse_c,
    open_self_deleting, parse_range,
};
use crate::state::AppState;

pub(crate) struct ObjectSnapshot {
    pub meta: ObjectMeta,
    pub source: SnapshotSource,
    pub link: std::path::PathBuf,
}

impl ObjectSnapshot {
    pub(crate) async fn discard(&self) {
        let _ = tokio::fs::remove_file(&self.link).await;
    }
}

pub(crate) struct ServedObject {
    pub meta: ObjectMeta,
    pub body: Body,
    pub content_length: u64,
    pub total_size: u64,
    pub range: Option<(u64, u64)>,
    pub encryption_algorithm: Option<String>,
}

pub(crate) enum ObjectReadError {
    Storage(StorageError),
    Rejected(Response),
    RangeNotSatisfiable(u64),
    Internal(String),
}

struct ReadVerification {
    expected: [u8; 16],
    context: ReadCorruptionContext,
}

struct ReadCorruptionContext {
    integrity: std::sync::Arc<crate::services::integrity::IntegrityService>,
    bucket: String,
    key: String,
    expected_etag: String,
}

struct VerifyOnRead {
    inner: AsyncReadStream,
    hasher: Md5,
    expected: [u8; 16],
    tail: Option<u8>,
    pending_error: Option<std::io::Error>,
    finished: bool,
    failed: bool,
    context: Option<ReadCorruptionContext>,
}

impl VerifyOnRead {
    fn new(inner: AsyncReadStream, verification: ReadVerification) -> Self {
        Self {
            inner,
            hasher: Md5::new(),
            expected: verification.expected,
            tail: None,
            pending_error: None,
            finished: false,
            failed: false,
            context: Some(verification.context),
        }
    }

    fn accept_bytes(&mut self, buf: &mut ReadBuf<'_>, before: usize) -> bool {
        let end = buf.filled().len();
        let last = buf.filled()[end - 1];
        self.hasher.update(&buf.filled()[before..end]);
        if let Some(previous) = self.tail.replace(last) {
            let filled = buf.filled_mut();
            filled.copy_within(before..end - 1, before + 1);
            filled[before] = previous;
        } else {
            buf.set_filled(end - 1);
        }
        buf.filled().len() > before
    }

    fn report_mismatch(&mut self, actual: [u8; 16]) {
        self.failed = true;
        let Some(context) = self.context.take() else {
            return;
        };
        let actual_etag = hex::encode(actual);
        tracing::error!(
            bucket = context.bucket,
            key = context.key,
            expected_etag = context.expected_etag,
            actual_etag,
            "READ_VERIFY_MODE=abort detected object corruption; aborting the response body"
        );
        tokio::spawn(async move {
            context
                .integrity
                .handle_read_corruption(
                    &context.bucket,
                    &context.key,
                    &context.expected_etag,
                    &actual_etag,
                )
                .await;
        });
    }

    fn mismatch_error() -> std::io::Error {
        std::io::Error::other("object checksum mismatch detected during read")
    }
}

impl AsyncRead for VerifyOnRead {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 || this.finished {
            return Poll::Ready(Ok(()));
        }
        if this.failed {
            return Poll::Ready(Err(Self::mismatch_error()));
        }
        if let Some(error) = this.pending_error.take() {
            return Poll::Ready(Err(error));
        }

        loop {
            let before = buf.filled().len();
            match this.inner.as_mut().poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    if buf.filled().len() > before {
                        if this.accept_bytes(buf, before) {
                            return Poll::Ready(Ok(()));
                        }
                        continue;
                    }
                    let actual: [u8; 16] = std::mem::take(&mut this.hasher).finalize().into();
                    if actual != this.expected {
                        this.report_mismatch(actual);
                        return Poll::Ready(Err(Self::mismatch_error()));
                    }
                    this.finished = true;
                    if let Some(tail) = this.tail.take() {
                        buf.put_slice(&[tail]);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    if buf.filled().len() > before {
                        let produced = this.accept_bytes(buf, before);
                        if produced {
                            this.pending_error = Some(error);
                            return Poll::Ready(Ok(()));
                        }
                    }
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {
                    if buf.filled().len() > before && this.accept_bytes(buf, before) {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

pub(crate) fn parse_range_hint(range_str: &str) -> Option<RangeHint> {
    let spec = range_str.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (raw_start, raw_end) = spec.split_once('-')?;
    let start = if raw_start.trim().is_empty() {
        None
    } else {
        Some(raw_start.trim().parse::<u64>().ok()?)
    };
    let end = if raw_end.trim().is_empty() {
        None
    } else {
        Some(raw_end.trim().parse::<u64>().ok()?)
    };
    if start.is_none() && end.is_none() {
        return None;
    }
    Some(RangeHint { start, end })
}

pub(crate) fn plaintext_size(meta: &ObjectMeta) -> u64 {
    EncryptionMetadata::from_metadata(&meta.internal_metadata)
        .and_then(|info| info.plaintext_size)
        .unwrap_or(meta.size)
}

pub(crate) fn requires_customer_key(meta: &ObjectMeta) -> bool {
    if mpu_is_sse_c(&meta.internal_metadata) {
        return true;
    }
    matches!(
        EncryptionMetadata::from_metadata(&meta.internal_metadata),
        Some(info) if info.algorithm == "AES256" && info.encrypted_data_key.is_none()
    )
}

pub(crate) async fn snapshot_object_for_read(
    state: &AppState,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    window: Option<RangeHint>,
) -> Result<ObjectSnapshot, StorageError> {
    let tmp_dir = state.config.storage_root.join(".myfsio.sys").join("tmp");
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;
    let link = tmp_dir.join(format!("src-{}", uuid::Uuid::new_v4()));
    let (meta, source) = match version_id {
        Some(version_id) => {
            state
                .storage
                .snapshot_object_version_to_link_windowed(bucket, key, version_id, &link, window)
                .await?
        }
        None => {
            state
                .storage
                .snapshot_object_to_link_windowed(bucket, key, &link, window)
                .await?
        }
    };
    Ok(ObjectSnapshot { meta, source, link })
}

pub(crate) async fn serve_object_data(
    state: &AppState,
    snapshot: ObjectSnapshot,
    range: Option<&str>,
    sse_c_headers: &HeaderMap,
    verification_target: Option<(&str, &str)>,
) -> Result<ServedObject, ObjectReadError> {
    let ObjectSnapshot { meta, source, link } = snapshot;
    let enc_info = EncryptionMetadata::from_metadata(&meta.internal_metadata);

    match (enc_info, state.encryption.as_ref()) {
        (Some(enc_info), Some(enc_svc)) => {
            let customer_key = match extract_sse_c_key(sse_c_headers) {
                Ok(customer_key) => customer_key,
                Err(response) => {
                    let _ = tokio::fs::remove_file(&link).await;
                    return Err(ObjectReadError::Rejected(response));
                }
            };

            let streamable = enc_info.plaintext_size.is_some()
                && (range.is_none() || enc_info.chunk_size.is_some());
            if streamable {
                let total = enc_info.plaintext_size.unwrap_or(meta.size);
                let window = match resolve_window(range, total) {
                    Ok(window) => window,
                    Err(err) => {
                        let _ = tokio::fs::remove_file(&link).await;
                        return Err(err);
                    }
                };
                let permit = acquire_read_permit(state, &link).await?;
                let stream = match enc_svc
                    .decrypt_object_stream(&link, &enc_info, customer_key.as_deref(), window, true)
                    .await
                {
                    Ok(stream) => stream,
                    Err(e) => {
                        let _ = tokio::fs::remove_file(&link).await;
                        return Err(ObjectReadError::Internal(format!(
                            "Decryption failed: {}",
                            e
                        )));
                    }
                };
                return Ok(served_object(
                    state,
                    stream,
                    permit,
                    meta,
                    total,
                    window,
                    Some(enc_info.algorithm),
                    None,
                ));
            }

            let permit = acquire_read_permit(state, &link).await?;
            let dec_tmp = state
                .config
                .storage_root
                .join(".myfsio.sys")
                .join("tmp")
                .join(format!("dec-{}", uuid::Uuid::new_v4()));
            let decrypted = enc_svc
                .decrypt_object(&link, &dec_tmp, &enc_info, customer_key.as_deref())
                .await;
            let _ = tokio::fs::remove_file(&link).await;
            if let Err(e) = decrypted {
                let _ = tokio::fs::remove_file(&dec_tmp).await;
                return Err(ObjectReadError::Internal(format!(
                    "Decryption failed: {}",
                    e
                )));
            }
            let total = tokio::fs::metadata(&dec_tmp)
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            let window = match resolve_window(range, total) {
                Ok(window) => window,
                Err(err) => {
                    let _ = tokio::fs::remove_file(&dec_tmp).await;
                    return Err(err);
                }
            };
            serve_file_window(
                state,
                dec_tmp,
                meta,
                total,
                window,
                permit,
                Some(enc_info.algorithm),
                None,
            )
            .await
        }
        (Some(_), None) => {
            let _ = tokio::fs::remove_file(&link).await;
            Err(ObjectReadError::Internal(
                "Object is encrypted but encryption service is disabled".to_string(),
            ))
        }
        (None, _) => {
            let total = meta.size;
            let window = match resolve_window(range, total) {
                Ok(window) => window,
                Err(err) => {
                    let _ = tokio::fs::remove_file(&link).await;
                    return Err(err);
                }
            };
            let permit = acquire_read_permit(state, &link).await?;
            let verification = read_verification(state, &meta, window, verification_target);
            match source {
                SnapshotSource::LinkedFile(_) => {
                    serve_file_window(state, link, meta, total, window, permit, None, verification)
                        .await
                }
                segments => {
                    let (start, length) = match window {
                        Some((start, end)) => (start, Some(end - start + 1)),
                        None => (0, None),
                    };
                    let reader = match segments.into_range_stream(start, length).await {
                        Ok(reader) => reader,
                        Err(e) => return Err(ObjectReadError::Storage(StorageError::Io(e))),
                    };
                    Ok(served_object(
                        state,
                        reader,
                        permit,
                        meta,
                        total,
                        window,
                        None,
                        verification,
                    ))
                }
            }
        }
    }
}

fn resolve_window(range: Option<&str>, total: u64) -> Result<Option<(u64, u64)>, ObjectReadError> {
    match range {
        Some(range_str) => match parse_range(range_str, total) {
            Some(window) => Ok(Some(window)),
            None => Err(ObjectReadError::RangeNotSatisfiable(total)),
        },
        None => Ok(None),
    }
}

async fn acquire_read_permit(
    state: &AppState,
    cleanup: &std::path::Path,
) -> Result<Option<OwnedSemaphorePermit>, ObjectReadError> {
    match acquire_disk_read_permit(state).await {
        Ok(permit) => Ok(permit),
        Err(response) => {
            let _ = tokio::fs::remove_file(cleanup).await;
            Err(ObjectReadError::Rejected(response))
        }
    }
}

async fn serve_file_window(
    state: &AppState,
    path: std::path::PathBuf,
    meta: ObjectMeta,
    total: u64,
    window: Option<(u64, u64)>,
    permit: Option<OwnedSemaphorePermit>,
    encryption_algorithm: Option<String>,
    verification: Option<ReadVerification>,
) -> Result<ServedObject, ObjectReadError> {
    let mut file = match open_self_deleting(path.clone()).await {
        Ok(file) => file,
        Err(e) => {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(ObjectReadError::Storage(StorageError::Io(e)));
        }
    };

    let reader: AsyncReadStream = match window {
        Some((start, end)) => {
            if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                return Err(ObjectReadError::Storage(StorageError::Io(e)));
            }
            Box::pin(file.take(end - start + 1))
        }
        None => Box::pin(file),
    };

    Ok(served_object(
        state,
        reader,
        permit,
        meta,
        total,
        window,
        encryption_algorithm,
        verification,
    ))
}

fn served_object(
    state: &AppState,
    reader: AsyncReadStream,
    permit: Option<OwnedSemaphorePermit>,
    meta: ObjectMeta,
    total: u64,
    window: Option<(u64, u64)>,
    encryption_algorithm: Option<String>,
    verification: Option<ReadVerification>,
) -> ServedObject {
    let reader = attach_read_permit(reader, permit);
    let reader = match verification {
        Some(verification) => Box::pin(VerifyOnRead::new(reader, verification)) as AsyncReadStream,
        None => reader,
    };
    let stream_cap = state.config.stream_chunk_size.max(64 * 1024);
    let body = Body::from_stream(ReaderStream::with_capacity(reader, stream_cap));
    let content_length = match window {
        Some((start, end)) => end - start + 1,
        None => total,
    };
    ServedObject {
        meta,
        body,
        content_length,
        total_size: total,
        range: window,
        encryption_algorithm,
    }
}

fn read_verification(
    state: &AppState,
    meta: &ObjectMeta,
    window: Option<(u64, u64)>,
    target: Option<(&str, &str)>,
) -> Option<ReadVerification> {
    if state.config.read_verify_mode != crate::config::ReadVerifyMode::Abort || window.is_some() {
        return None;
    }
    if meta
        .internal_metadata
        .contains_key(myfsio_storage::segments::META_KEY_SEGMENTS)
    {
        return None;
    }
    let (bucket, key) = target?;
    let expected_etag = meta.etag.as_deref()?;
    let mut expected = [0u8; 16];
    if expected_etag.len() != 32 || hex::decode_to_slice(expected_etag, &mut expected).is_err() {
        return None;
    }
    Some(ReadVerification {
        expected,
        context: ReadCorruptionContext {
            integrity: state.read_integrity.as_ref()?.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            expected_etag: expected_etag.to_string(),
        },
    })
}
