use myfsio_common::error::{IncompleteBodyError, S3Error, S3ErrorCode};
use thiserror::Error;

fn find_incomplete_body(err: &std::io::Error) -> Option<&IncompleteBodyError> {
    let mut source: Option<&(dyn std::error::Error + 'static)> = err.get_ref().map(|e| e as _);
    while let Some(err) = source {
        if let Some(incomplete) = err.downcast_ref::<IncompleteBodyError>() {
            return Some(incomplete);
        }
        source = err.source();
    }
    None
}

fn s3_error_from_io(err: &std::io::Error) -> S3Error {
    if let Some(incomplete) = find_incomplete_body(err) {
        return S3Error::new(S3ErrorCode::IncompleteBody, incomplete.to_string());
    }
    S3Error::new(S3ErrorCode::InternalError, err.to_string())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Bucket not found: {0}")]
    BucketNotFound(String),
    #[error("Bucket already exists: {0}")]
    BucketAlreadyExists(String),
    #[error("Bucket not empty: {0}")]
    BucketNotEmpty(String),
    #[error("Object not found: {bucket}/{key}")]
    ObjectNotFound { bucket: String, key: String },
    #[error("Object version not found: {bucket}/{key}?versionId={version_id}")]
    VersionNotFound {
        bucket: String,
        key: String,
        version_id: String,
    },
    #[error("Object is a delete marker: {bucket}/{key}")]
    DeleteMarker {
        bucket: String,
        key: String,
        version_id: String,
    },
    #[error("Object corrupted: {bucket}/{key} ({detail})")]
    ObjectCorrupted {
        bucket: String,
        key: String,
        detail: String,
    },
    #[error("Invalid bucket name: {0}")]
    InvalidBucketName(String),
    #[error("Invalid object key: {0}")]
    InvalidObjectKey(String),
    #[error("Method not allowed: {0}")]
    MethodNotAllowed(String),
    #[error("Upload not found: {0}")]
    UploadNotFound(String),
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("Object locked: {0}")]
    ObjectLocked(String),
    #[error("Invalid range")]
    InvalidRange,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<StorageError> for S3Error {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::BucketNotFound(name) => {
                S3Error::from_code(S3ErrorCode::NoSuchBucket).with_resource(format!("/{}", name))
            }
            StorageError::BucketAlreadyExists(name) => {
                S3Error::from_code(S3ErrorCode::BucketAlreadyOwnedByYou)
                    .with_resource(format!("/{}", name))
            }
            StorageError::BucketNotEmpty(name) => {
                S3Error::from_code(S3ErrorCode::BucketNotEmpty).with_resource(format!("/{}", name))
            }
            StorageError::ObjectNotFound { bucket, key } => {
                S3Error::from_code(S3ErrorCode::NoSuchKey)
                    .with_resource(format!("/{}/{}", bucket, key))
            }
            StorageError::VersionNotFound {
                bucket,
                key,
                version_id,
            } => S3Error::from_code(S3ErrorCode::NoSuchVersion)
                .with_resource(format!("/{}/{}?versionId={}", bucket, key, version_id)),
            StorageError::DeleteMarker {
                bucket,
                key,
                version_id,
            } => S3Error::from_code(S3ErrorCode::MethodNotAllowed)
                .with_resource(format!("/{}/{}?versionId={}", bucket, key, version_id)),
            StorageError::ObjectCorrupted {
                bucket,
                key,
                detail,
            } => S3Error::new(
                S3ErrorCode::ObjectCorrupted,
                format!("Object corrupted: {}", detail),
            )
            .with_resource(format!("/{}/{}", bucket, key)),
            StorageError::InvalidBucketName(msg) => {
                S3Error::new(S3ErrorCode::InvalidBucketName, msg)
            }
            StorageError::InvalidObjectKey(msg) => S3Error::new(S3ErrorCode::InvalidKey, msg),
            StorageError::MethodNotAllowed(msg) => S3Error::new(S3ErrorCode::MethodNotAllowed, msg),
            StorageError::UploadNotFound(id) => S3Error::new(
                S3ErrorCode::NoSuchUpload,
                format!("Upload {} not found", id),
            ),
            StorageError::QuotaExceeded(msg) => S3Error::new(S3ErrorCode::QuotaExceeded, msg),
            StorageError::PreconditionFailed(msg) => {
                S3Error::new(S3ErrorCode::PreconditionFailed, msg)
            }
            StorageError::ObjectLocked(msg) => S3Error::new(S3ErrorCode::AccessDenied, msg),
            StorageError::InvalidRange => S3Error::from_code(S3ErrorCode::InvalidRange),
            StorageError::Io(e) => s3_error_from_io(&e),
            StorageError::Json(e) => S3Error::new(S3ErrorCode::InternalError, e.to_string()),
            StorageError::Internal(msg) => S3Error::new(S3ErrorCode::InternalError, msg),
        }
    }
}
