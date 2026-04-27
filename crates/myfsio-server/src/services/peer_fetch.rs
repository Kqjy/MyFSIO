use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use aws_sdk_s3::Client;
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use myfsio_storage::fs_backend::{is_multipart_etag, FsStorageBackend};
use myfsio_storage::traits::StorageEngine;

use crate::services::replication::ReplicationManager;
use crate::services::s3_client::{build_client, ClientOptions};
use crate::stores::connections::ConnectionStore;

pub struct PeerFetcher {
    storage: Arc<FsStorageBackend>,
    connections: Arc<ConnectionStore>,
    replication: Arc<ReplicationManager>,
    client_options: ClientOptions,
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
    ) -> Self {
        Self {
            storage,
            connections,
            replication,
            client_options,
        }
    }

    fn build_client_for_bucket(&self, bucket: &str) -> Option<(Client, String)> {
        let rule = self.replication.get_rule(bucket)?;
        if !rule.enabled {
            return None;
        }
        let conn = self.connections.get(&rule.target_connection_id)?;
        let client = build_client(&conn, &self.client_options);
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

        let head = match client
            .head_object()
            .bucket(remote_bucket)
            .key(key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                tracing::error!("Pull HeadObject failed {}/{}: {:?}", local_bucket, key, err);
                return false;
            }
        };

        let metadata: Option<HashMap<String, String>> = head
            .metadata()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect());

        let stream = resp.body.into_async_read();
        let boxed: Pin<Box<dyn AsyncRead + Send>> = Box::pin(stream);

        match self
            .storage
            .put_object(local_bucket, key, boxed, metadata)
            .await
        {
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

    pub async fn fetch_for_heal(
        &self,
        local_bucket: &str,
        key: &str,
        expected_etag: &str,
        dest_path: &Path,
    ) -> HealOutcome {
        let (client, target_bucket) = match self.build_client_for_bucket(local_bucket) {
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
