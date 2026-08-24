use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use aws_sdk_s3::Client;
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use myfsio_storage::fs_backend::{is_multipart_etag, FsStorageBackend};
use myfsio_storage::traits::StorageEngine;

fn looks_like_md5_etag(etag: &str) -> bool {
    !etag.is_empty()
        && !is_multipart_etag(etag)
        && etag.len() == 32
        && etag.chars().all(|c| c.is_ascii_hexdigit())
}

use crate::services::replication::ReplicationManager;
use crate::services::s3_client::{build_client, ClientOptions};
use crate::stores::connections::ConnectionStore;

pub struct PeerFetcher {
    storage: Arc<FsStorageBackend>,
    connections: Arc<ConnectionStore>,
    replication: Arc<ReplicationManager>,
    client_options: ClientOptions,
    encryption: Option<Arc<myfsio_crypto::encryption::EncryptionService>>,
}

#[derive(Debug)]
pub enum HealOutcome {
    Healed { peer_etag: String, bytes: u64 },
    PeerMismatch { stored: String, peer: String },
    PeerUnavailable { error: String },
    NotConfigured,
    VerifyFailed { expected: String, actual: String },
}

impl PeerFetcher {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        connections: Arc<ConnectionStore>,
        replication: Arc<ReplicationManager>,
        client_options: ClientOptions,
        encryption: Option<Arc<myfsio_crypto::encryption::EncryptionService>>,
    ) -> Self {
        Self {
            storage,
            connections,
            replication,
            client_options,
            encryption,
        }
    }

    async fn build_client_for_bucket(&self, bucket: &str) -> Option<(Client, String)> {
        let rule = self.replication.get_rule(bucket)?;
        if !rule.enabled {
            return None;
        }
        let conn = self.connections.get(&rule.target_connection_id)?;
        if let Err(reason) = self.replication.endpoint_allowed(&conn.endpoint_url).await {
            tracing::warn!(
                "Peer fetch blocked for bucket '{}': connection '{}' endpoint rejected ({}). Set ALLOW_INTERNAL_ENDPOINTS=true to allow.",
                bucket,
                conn.name,
                reason
            );
            return None;
        }
        let client = build_client(&conn, &self.client_options, self.replication.http_client());
        Some((client, rule.target_bucket))
    }

    pub async fn fetch_into_storage(
        &self,
        client: &Client,
        remote_bucket: &str,
        local_bucket: &str,
        key: &str,
    ) -> bool {
        let resp = match client
            .get_object()
            .bucket(remote_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::error!("Pull GetObject failed {}/{}: {:?}", local_bucket, key, err);
                return false;
            }
        };

        let expected_etag = resp.e_tag().unwrap_or("").trim_matches('"').to_string();
        let metadata: Option<HashMap<String, String>> = resp.metadata().map(|m| {
            m.iter()
                .filter(|(k, _)| !myfsio_storage::validation::is_reserved_user_metadata_key(k))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        });

        let tmp_dir = self.storage.system_tmp_dir();
        if let Err(err) = tokio::fs::create_dir_all(&tmp_dir).await {
            tracing::error!(
                "Failed to create temp dir for peer fetch {}/{}: {}",
                local_bucket,
                key,
                err
            );
            return false;
        }
        let tmp_path = tmp_dir.join(format!("peer_fetch_{}.tmp", uuid::Uuid::new_v4()));

        let mut tmp_file = match tokio::fs::File::create(&tmp_path).await {
            Ok(f) => f,
            Err(err) => {
                tracing::error!(
                    "Failed to create temp file for peer fetch {}/{}: {}",
                    local_bucket,
                    key,
                    err
                );
                return false;
            }
        };

        let mut reader = resp.body.into_async_read();
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buf[..n]);
                    if let Err(err) = tmp_file.write_all(&buf[..n]).await {
                        tracing::error!(
                            "Failed to spool peer fetch {}/{}: {}",
                            local_bucket,
                            key,
                            err
                        );
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                        return false;
                    }
                }
                Err(err) => {
                    tracing::error!("Pull body read failed {}/{}: {}", local_bucket, key, err);
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return false;
                }
            }
        }
        if let Err(err) = tmp_file.flush().await {
            tracing::error!(
                "Failed to flush peer fetch temp {}/{}: {}",
                local_bucket,
                key,
                err
            );
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return false;
        }
        drop(tmp_file);

        let body_md5 = format!("{:x}", hasher.finalize());
        if looks_like_md5_etag(&expected_etag) && body_md5 != expected_etag {
            tracing::error!(
                "Pull ETag mismatch for {}/{}: expected {}, got {}",
                local_bucket,
                key,
                expected_etag,
                body_md5
            );
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return false;
        }

        let default_encryption = match crate::handlers::resolve_bucket_default_encryption(
            &*self.storage,
            self.encryption.is_some(),
            local_bucket,
        )
        .await
        {
            Ok(context) => context,
            Err(err) => {
                tracing::error!(
                    "Refusing to store pulled object {}/{}: {}",
                    local_bucket,
                    key,
                    err.message
                );
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return false;
            }
        };

        if let Some(enc_ctx) = default_encryption {
            let result = self
                .store_encrypted_pull(local_bucket, key, &tmp_path, body_md5, metadata, &enc_ctx)
                .await;
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return match result {
                Ok(()) => {
                    tracing::debug!(
                        "Pulled object {}/{} from remote under bucket default encryption",
                        local_bucket,
                        key
                    );
                    true
                }
                Err(err) => {
                    tracing::error!(
                        "Store pulled object failed {}/{}: {}",
                        local_bucket,
                        key,
                        err
                    );
                    false
                }
            };
        }

        let opened = match tokio::fs::File::open(&tmp_path).await {
            Ok(f) => f,
            Err(err) => {
                tracing::error!(
                    "Failed to reopen peer fetch temp {}/{}: {}",
                    local_bucket,
                    key,
                    err
                );
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return false;
            }
        };
        let boxed: Pin<Box<dyn AsyncRead + Send>> = Box::pin(opened);

        let result = self
            .storage
            .put_object(local_bucket, key, boxed, metadata)
            .await;
        let _ = tokio::fs::remove_file(&tmp_path).await;

        match result {
            Ok(_) => {
                tracing::debug!("Pulled object {}/{} from remote", local_bucket, key);
                true
            }
            Err(err) => {
                tracing::error!(
                    "Store pulled object failed {}/{}: {}",
                    local_bucket,
                    key,
                    err
                );
                false
            }
        }
    }

    async fn store_encrypted_pull(
        &self,
        local_bucket: &str,
        key: &str,
        plaintext_path: &Path,
        plaintext_md5: String,
        metadata: Option<HashMap<String, String>>,
        enc_ctx: &myfsio_crypto::encryption::EncryptionContext,
    ) -> Result<(), String> {
        let enc_svc = self
            .encryption
            .as_ref()
            .ok_or_else(|| "encryption service is unavailable".to_string())?;
        let prepared = self
            .storage
            .allocate_prepared_tmp_path()
            .map_err(|e| e.to_string())?;
        let enc_meta = match enc_svc
            .encrypt_object(plaintext_path, &prepared, enc_ctx)
            .await
        {
            Ok(meta) => meta,
            Err(err) => {
                let _ = tokio::fs::remove_file(&prepared).await;
                return Err(err.to_string());
            }
        };
        let stored_size = match tokio::fs::metadata(&prepared).await {
            Ok(m) => m.len(),
            Err(err) => {
                let _ = tokio::fs::remove_file(&prepared).await;
                return Err(err.to_string());
            }
        };
        let mut full_metadata = metadata.unwrap_or_default();
        for (k, v) in enc_meta.to_metadata_map() {
            full_metadata.insert(k, v);
        }
        self.storage
            .put_object_prepared(
                local_bucket,
                key,
                &prepared,
                stored_size,
                plaintext_md5,
                Some(full_metadata),
                myfsio_storage::traits::PutCommitOptions::default(),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub async fn fetch_for_heal(
        &self,
        local_bucket: &str,
        key: &str,
        expected_etag: &str,
        dest_path: &Path,
    ) -> HealOutcome {
        let (client, target_bucket) = match self.build_client_for_bucket(local_bucket).await {
            Some(v) => v,
            None => return HealOutcome::NotConfigured,
        };

        let head = match client
            .head_object()
            .bucket(&target_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                return HealOutcome::PeerUnavailable {
                    error: format!("HeadObject: {:?}", err),
                };
            }
        };

        let peer_etag = head.e_tag().unwrap_or("").trim_matches('"').to_string();
        if peer_etag.is_empty() {
            return HealOutcome::PeerUnavailable {
                error: "remote returned empty ETag".into(),
            };
        }
        if peer_etag != expected_etag {
            return HealOutcome::PeerMismatch {
                stored: expected_etag.to_string(),
                peer: peer_etag,
            };
        }

        if is_multipart_etag(expected_etag) {
            return self
                .fetch_multipart_for_heal(&client, &target_bucket, key, expected_etag, dest_path)
                .await;
        }

        let resp = match client
            .get_object()
            .bucket(&target_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                return HealOutcome::PeerUnavailable {
                    error: format!("GetObject: {:?}", err),
                };
            }
        };

        if let Some(parent) = dest_path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return HealOutcome::PeerUnavailable {
                    error: format!("mkdir parent: {}", e),
                };
            }
        }

        let mut file = match tokio::fs::File::create(dest_path).await {
            Ok(f) => f,
            Err(e) => {
                return HealOutcome::PeerUnavailable {
                    error: format!("create temp: {}", e),
                };
            }
        };
        let mut reader = resp.body.into_async_read();
        let mut hasher = Md5::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    drop(file);
                    let _ = tokio::fs::remove_file(dest_path).await;
                    return HealOutcome::PeerUnavailable {
                        error: format!("read body: {}", e),
                    };
                }
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            if let Err(e) = file.write_all(&buf[..n]).await {
                drop(file);
                let _ = tokio::fs::remove_file(dest_path).await;
                return HealOutcome::PeerUnavailable {
                    error: format!("write temp: {}", e),
                };
            }
            total += n as u64;
        }
        if let Err(e) = file.flush().await {
            return HealOutcome::PeerUnavailable {
                error: format!("flush temp: {}", e),
            };
        }
        drop(file);

        let actual = format!("{:x}", hasher.finalize());
        if actual != expected_etag {
            let _ = tokio::fs::remove_file(dest_path).await;
            return HealOutcome::VerifyFailed {
                expected: expected_etag.to_string(),
                actual,
            };
        }

        HealOutcome::Healed {
            peer_etag,
            bytes: total,
        }
    }

    async fn fetch_multipart_for_heal(
        &self,
        client: &Client,
        target_bucket: &str,
        key: &str,
        expected_etag: &str,
        dest_path: &Path,
    ) -> HealOutcome {
        let part_count = match expected_etag
            .split_once('-')
            .and_then(|(_, n)| n.parse::<u32>().ok())
        {
            Some(n) if n >= 1 => n,
            _ => {
                return HealOutcome::VerifyFailed {
                    expected: expected_etag.to_string(),
                    actual: format!("unparseable multipart suffix in {}", expected_etag),
                };
            }
        };

        if let Some(parent) = dest_path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return HealOutcome::PeerUnavailable {
                    error: format!("mkdir parent: {}", e),
                };
            }
        }

        let mut file = match tokio::fs::File::create(dest_path).await {
            Ok(f) => f,
            Err(e) => {
                return HealOutcome::PeerUnavailable {
                    error: format!("create temp: {}", e),
                };
            }
        };

        let mut composite = Md5::new();
        let mut total: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];

        for part_no in 1..=part_count {
            let part_no_i32 = part_no as i32;
            let resp = match client
                .get_object()
                .bucket(target_bucket)
                .key(key)
                .part_number(part_no_i32)
                .send()
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    drop(file);
                    let _ = tokio::fs::remove_file(dest_path).await;
                    return HealOutcome::PeerUnavailable {
                        error: format!("GetObject part {}: {:?}", part_no, err),
                    };
                }
            };

            let mut reader = resp.body.into_async_read();
            let mut part_hasher = Md5::new();
            let mut part_bytes: u64 = 0;
            loop {
                let n = match reader.read(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        drop(file);
                        let _ = tokio::fs::remove_file(dest_path).await;
                        return HealOutcome::PeerUnavailable {
                            error: format!("read part {}: {}", part_no, e),
                        };
                    }
                };
                if n == 0 {
                    break;
                }
                part_hasher.update(&buf[..n]);
                if let Err(e) = file.write_all(&buf[..n]).await {
                    drop(file);
                    let _ = tokio::fs::remove_file(dest_path).await;
                    return HealOutcome::PeerUnavailable {
                        error: format!("write part {}: {}", part_no, e),
                    };
                }
                part_bytes += n as u64;
            }
            if part_bytes == 0 {
                drop(file);
                let _ = tokio::fs::remove_file(dest_path).await;
                return HealOutcome::VerifyFailed {
                    expected: expected_etag.to_string(),
                    actual: format!("part {} returned zero bytes", part_no),
                };
            }
            composite.update(part_hasher.finalize().as_slice());
            total += part_bytes;
        }

        if let Err(e) = file.flush().await {
            return HealOutcome::PeerUnavailable {
                error: format!("flush temp: {}", e),
            };
        }
        drop(file);

        let composite_etag = format!("{:x}-{}", composite.finalize(), part_count);
        if composite_etag != expected_etag {
            let _ = tokio::fs::remove_file(dest_path).await;
            return HealOutcome::VerifyFailed {
                expected: expected_etag.to_string(),
                actual: composite_etag,
            };
        }

        HealOutcome::Healed {
            peer_etag: expected_etag.to_string(),
            bytes: total,
        }
    }
}

#[cfg(test)]
mod tests {
    use myfsio_storage::fs_backend::is_multipart_etag;
    use myfsio_storage::fs_backend::FsStorageBackend;
    use myfsio_storage::traits::StorageEngine;

    async fn backend_with_default_encryption(
        encryption: Option<serde_json::Value>,
    ) -> (FsStorageBackend, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = FsStorageBackend::new(tmp.path().to_path_buf());
        storage.create_bucket("pull").await.expect("create bucket");
        if let Some(encryption) = encryption {
            let mut config = storage
                .get_bucket_config("pull")
                .await
                .expect("read bucket config");
            config.encryption = Some(encryption);
            storage
                .set_bucket_config("pull", &config)
                .await
                .expect("write bucket config");
        }
        (storage, tmp)
    }

    #[tokio::test]
    async fn peer_pull_into_a_default_encrypted_bucket_refuses_without_an_encryption_service() {
        let (storage, _tmp) = backend_with_default_encryption(Some(serde_json::json!({
            "sse_algorithm": "AES256"
        })))
        .await;
        let resolved =
            crate::handlers::resolve_bucket_default_encryption(&storage, false, "pull").await;
        let error = match resolved {
            Ok(_) => panic!("a default-encrypted bucket must not accept a plaintext peer pull"),
            Err(error) => error,
        };
        assert!(
            error.message.contains("server-side encryption is"),
            "unexpected refusal: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn peer_pull_into_a_default_encrypted_bucket_resolves_the_bucket_algorithm() {
        let (storage, _tmp) = backend_with_default_encryption(Some(serde_json::json!({
            "sse_algorithm": "AES256"
        })))
        .await;
        let context = crate::handlers::resolve_bucket_default_encryption(&storage, true, "pull")
            .await
            .expect("bucket default encryption resolves")
            .expect("a default-encrypted bucket yields an encryption context");
        assert_eq!(
            context.algorithm,
            myfsio_crypto::encryption::SseAlgorithm::Aes256
        );
        assert!(context.customer_key.is_none());
    }

    #[tokio::test]
    async fn peer_pull_into_an_unencrypted_bucket_stays_unencrypted() {
        let (storage, _tmp) = backend_with_default_encryption(None).await;
        let context = crate::handlers::resolve_bucket_default_encryption(&storage, true, "pull")
            .await
            .expect("bucket without default encryption resolves");
        assert!(context.is_none());
    }

    #[test]
    fn detects_multipart_etags() {
        assert!(is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e-3"));
        assert!(is_multipart_etag("00000000000000000000000000000000-1"));
        assert!(!is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e-"));
        assert!(!is_multipart_etag("not-hex-at-all-1"));
        assert!(!is_multipart_etag("d41d8cd98f00b204e9800998ecf8427e-abc"));
    }
}
