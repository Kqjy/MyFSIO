use super::*;

impl FsStorageBackend {
    pub fn validated_object_path(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        self.require_bucket(bucket)?;
        self.object_path(bucket, key)
    }

    pub(super) fn validated_quarantine_path(&self, relative: &Path) -> StorageResult<PathBuf> {
        if relative.is_absolute() {
            return Err(StorageError::InvalidObjectKey(
                "quarantine path must be relative".to_string(),
            ));
        }
        let normalized = normalize_path(relative).ok_or_else(|| {
            StorageError::InvalidObjectKey("quarantine path escapes storage root".to_string())
        })?;
        let quarantine_root = Path::new(SYSTEM_ROOT).join("quarantine");
        if !normalized.starts_with(&quarantine_root) {
            return Err(StorageError::InvalidObjectKey(
                "quarantine path is outside the quarantine root".to_string(),
            ));
        }
        let full = self.root.join(normalized);
        self.guard_contained(&full, "quarantine")?;
        Ok(full)
    }

    pub async fn quarantine_corrupted_object(
        &self,
        bucket: &str,
        key: &str,
        expected_etag: &str,
        quarantine_relative: &Path,
        detail: &str,
    ) -> StorageResult<IntegrityQuarantineOutcome> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            let live_path = self.object_path(bucket, key)?;
            let quarantine_path = self.validated_quarantine_path(quarantine_relative)?;
            if !live_path.is_file() {
                return Ok(IntegrityQuarantineOutcome::Skipped);
            }

            let mut metadata = self.read_metadata_sync(bucket, key);
            let current_etag = metadata.get("__etag__").map(String::as_str).unwrap_or("");
            if current_etag != expected_etag
                || current_etag.is_empty()
                || metadata_is_corrupted(&metadata)
                || is_multipart_etag(current_etag)
                || myfsio_crypto::encryption::EncryptionMetadata::is_encrypted(&metadata)
            {
                return Ok(IntegrityQuarantineOutcome::Skipped);
            }

            let actual = myfsio_crypto::hashing::md5_file(&live_path)
                .map_err(|error| StorageError::Io(std::io::Error::other(error)))?;
            if actual == current_etag {
                return Ok(IntegrityQuarantineOutcome::Healthy);
            }

            if let Some(parent) = quarantine_path.parent() {
                std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
            }
            std::fs::rename(&live_path, &quarantine_path).map_err(StorageError::Io)?;

            metadata.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
            metadata.insert(META_KEY_CORRUPTED_AT.to_string(), Utc::now().to_rfc3339());
            metadata.insert(META_KEY_CORRUPTION_DETAIL.to_string(), detail.to_string());
            metadata.insert(
                META_KEY_QUARANTINE_PATH.to_string(),
                quarantine_relative.to_string_lossy().replace('\\', "/"),
            );
            metadata.insert(META_KEY_CORRUPTION_RETRY_COUNT.to_string(), "0".to_string());
            metadata.insert(
                META_KEY_CORRUPTION_LAST_RETRY_AT.to_string(),
                Utc::now().to_rfc3339(),
            );

            if let Err(error) = self.write_live_metadata_entry_sync(bucket, key, &metadata) {
                let _ = std::fs::rename(&quarantine_path, &live_path);
                return Err(error);
            }
            if let Some(parent) = live_path.parent() {
                let _ = Self::fsync_dir(parent);
            }
            if let Some(parent) = quarantine_path.parent() {
                let _ = Self::fsync_dir(parent);
            }
            Ok(IntegrityQuarantineOutcome::Quarantined)
        })
    }

    pub async fn install_healed_object_if_still_poisoned(
        &self,
        bucket: &str,
        key: &str,
        expected_etag: &str,
        prepared_path: &Path,
    ) -> StorageResult<bool> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            let live_path = self.object_path(bucket, key)?;
            if !prepared_path.starts_with(&self.root) {
                return Err(StorageError::InvalidObjectKey(
                    "prepared heal path escapes storage root".to_string(),
                ));
            }
            if live_path.exists() || !prepared_path.is_file() {
                return Ok(false);
            }

            let prepared_etag = myfsio_crypto::hashing::md5_file(prepared_path)
                .map_err(|error| StorageError::Io(std::io::Error::other(error)))?;
            if prepared_etag != expected_etag {
                return Err(StorageError::PreconditionFailed(format!(
                    "prepared heal checksum {} does not match expected {}",
                    prepared_etag, expected_etag
                )));
            }

            let mut metadata = self.read_metadata_sync(bucket, key);
            if !metadata_is_corrupted(&metadata)
                || metadata.get("__etag__").map(String::as_str) != Some(expected_etag)
            {
                return Ok(false);
            }

            if let Some(parent) = live_path.parent() {
                std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
            }
            std::fs::rename(prepared_path, &live_path).map_err(StorageError::Io)?;
            metadata.remove(META_KEY_CORRUPTED);
            metadata.remove(META_KEY_CORRUPTED_AT);
            metadata.remove(META_KEY_CORRUPTION_DETAIL);
            metadata.remove(META_KEY_QUARANTINE_PATH);
            metadata.remove(META_KEY_CORRUPTION_RETRY_COUNT);
            metadata.remove(META_KEY_CORRUPTION_LAST_RETRY_AT);
            if let Err(error) = self.write_live_metadata_entry_sync(bucket, key, &metadata) {
                let _ = std::fs::rename(&live_path, prepared_path);
                return Err(error);
            }
            if let Some(parent) = live_path.parent() {
                let _ = Self::fsync_dir(parent);
            }
            Ok(true)
        })
    }

    pub async fn record_poisoned_recovery_failure(
        &self,
        bucket: &str,
        key: &str,
        expected_etag: &str,
        detail: &str,
    ) -> StorageResult<bool> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            let live_path = self.object_path(bucket, key)?;
            if live_path.exists() {
                return Ok(false);
            }
            let mut metadata = self.read_metadata_sync(bucket, key);
            if !metadata_is_corrupted(&metadata)
                || metadata.get("__etag__").map(String::as_str) != Some(expected_etag)
            {
                return Ok(false);
            }
            let retries = metadata
                .get(META_KEY_CORRUPTION_RETRY_COUNT)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_add(1);
            metadata.insert(META_KEY_CORRUPTION_DETAIL.to_string(), detail.to_string());
            metadata.insert(
                META_KEY_CORRUPTION_RETRY_COUNT.to_string(),
                retries.to_string(),
            );
            metadata.insert(
                META_KEY_CORRUPTION_LAST_RETRY_AT.to_string(),
                Utc::now().to_rfc3339(),
            );
            self.write_live_metadata_entry_sync(bucket, key, &metadata)?;
            Ok(true)
        })
    }

    pub async fn delete_phantom_metadata_if_still_missing(
        &self,
        bucket: &str,
        key: &str,
        expected_etag: Option<&str>,
    ) -> StorageResult<bool> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            let live_path = self.object_path(bucket, key)?;
            if live_path.is_file() {
                return Ok(false);
            }
            let metadata = self.read_metadata_sync(bucket, key);
            if metadata_is_corrupted(&metadata)
                || expected_etag.is_some()
                    && metadata.get("__etag__").map(String::as_str) != expected_etag
            {
                return Ok(false);
            }
            self.delete_metadata_sync(bucket, key)
                .map_err(StorageError::Io)?;
            self.invalidate_bucket_caches(bucket);
            self.update_listing_index_after_commit(bucket, key);
            Ok(true)
        })
    }
}
