use myfsio_common::error::{S3Error, S3ErrorCode};
use thiserror::Error;

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
    #[error("Invalid bucket name: {0}")]
    InvalidBucketName(String),
    #[error("Invalid object key: {0}")]
    InvalidObjectKey(String),
    #[error("Upload not found: {0}")]
    UploadNotFound(String),
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
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
                S3Error::from_code(S3ErrorCode::BucketAlreadyExists)
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
            StorageError::InvalidBucketName(msg) => {
                S3Error::new(S3ErrorCode::InvalidBucketName, msg)
            }
            StorageError::InvalidObjectKey(msg) => S3Error::new(S3ErrorCode::InvalidKey, msg),
            StorageError::UploadNotFound(id) => S3Error::new(
                S3ErrorCode::NoSuchUpload,
                format!("Upload {} not found", id),
            ),
            StorageError::QuotaExceeded(msg) => S3Error::new(S3ErrorCode::QuotaExceeded, msg),
            StorageError::InvalidRange => S3Error::from_code(S3ErrorCode::InvalidRange),
            StorageError::Io(e) => S3Error::new(S3ErrorCode::InternalError, e.to_string()),
            StorageError::Json(e) => S3Error::new(S3ErrorCode::InternalError, e.to_string()),
            StorageError::Internal(msg) => S3Error::new(S3ErrorCode::InternalError, msg),
        }
    }
}
