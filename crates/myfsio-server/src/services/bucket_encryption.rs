use myfsio_common::error::{S3Error, S3ErrorCode};

pub(crate) async fn resolve_bucket_default_encryption<S>(
    storage: &S,
    encryption_available: bool,
    bucket: &str,
) -> Result<Option<myfsio_crypto::encryption::EncryptionContext>, S3Error>
where
    S: myfsio_storage::traits::StorageEngine + ?Sized,
{
    if let Ok(config) = storage.get_bucket_config(bucket).await {
        if config.unreadable {
            return Err(S3Error::new(
                S3ErrorCode::InternalError,
                "Bucket configuration is unreadable; refusing to store an object whose encryption \
                 requirements cannot be determined",
            ));
        }
        if let Some(enc_val) = &config.encryption {
            let Some((algorithm, kms_key_id)) =
                crate::handlers::config::parse_encryption_config(enc_val)
            else {
                return Err(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Bucket default encryption configuration could not be parsed",
                ));
            };
            if !encryption_available {
                return Err(S3Error::new(
                    S3ErrorCode::InternalError,
                    "Bucket default encryption is configured but server-side encryption is \
                     unavailable on this server",
                ));
            }
            match algorithm.as_str() {
                "AES256" => {
                    return Ok(Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::Aes256,
                        kms_key_id: None,
                        customer_key: None,
                    }));
                }
                "aws:kms" => {
                    return Ok(Some(myfsio_crypto::encryption::EncryptionContext {
                        algorithm: myfsio_crypto::encryption::SseAlgorithm::AwsKms,
                        kms_key_id,
                        customer_key: None,
                    }));
                }
                _ => {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "Bucket default encryption specifies an unsupported algorithm",
                    ));
                }
            }
        }
    }

    Ok(None)
}
