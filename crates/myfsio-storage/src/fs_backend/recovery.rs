use super::*;

pub(super) enum StagedCommitOutcome {
    Published {
        bucket: String,
        key: String,
        etag: String,
    },
    Discarded {
        reason: &'static str,
    },
    Poisoned {
        bucket: String,
        key: String,
        detail: String,
    },
}

impl FsStorageBackend {
    pub(super) fn rollback_failed_commit_sync(
        &self,
        bucket_name: &str,
        key: &str,
        previous_metadata: &HashMap<String, String>,
        archived_version_id: Option<&str>,
    ) {
        if let Err(err) = self.write_metadata_sync(bucket_name, key, previous_metadata) {
            tracing::error!(
                bucket = bucket_name,
                key = key,
                error = %err,
                "failed to restore the previous object metadata after an aborted commit"
            );
        }
        if let Some(version_id) = archived_version_id {
            let (manifest_path, data_path) =
                self.version_record_paths(bucket_name, key, version_id);
            for path in [&manifest_path, &data_path] {
                if path.is_file() {
                    if let Err(err) = Self::safe_unlink(path) {
                        tracing::error!(
                            bucket = bucket_name,
                            key = key,
                            version_id = version_id,
                            error = %err,
                            "failed to remove an archived version after an aborted commit"
                        );
                    }
                }
            }
            self.cleanup_empty_parents(&manifest_path, &self.bucket_versions_root(bucket_name));
        }
        self.invalidate_bucket_caches(bucket_name);
        self.update_listing_index_after_commit(bucket_name, key);
    }

    pub fn recover_staged_commits_sync(&self) -> std::io::Result<StagedCommitRecovery> {
        let mut summary = StagedCommitRecovery::default();
        let entries = match std::fs::read_dir(self.tmp_dir()) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(summary),
            Err(err) => return Err(err),
        };
        for entry in entries {
            let entry = entry.map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!(
                        "commit recovery could not enumerate the staged-commit directory: {}",
                        err
                    ),
                )
            })?;
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".sidecar-stage")
            {
                continue;
            }
            let staged_path = entry.path();
            match self.recover_one_staged_commit_sync(&staged_path) {
                Ok(StagedCommitOutcome::Published { bucket, key, etag }) => {
                    tracing::warn!(
                        bucket,
                        key,
                        etag,
                        "recovered an interrupted object commit: the data file was already \
                         renamed into place, so its staged metadata sidecar has been published; \
                         the intent is retained until replication is enqueued"
                    );
                    summary.published.push(RecoveredCommit {
                        bucket,
                        key,
                        staged_path,
                    });
                }
                Ok(StagedCommitOutcome::Discarded { reason }) => {
                    summary.discarded += 1;
                    tracing::info!(
                        staged = %staged_path.display(),
                        reason,
                        "discarded a staged sidecar left by an interrupted commit; the previous \
                         object state remains authoritative"
                    );
                }
                Ok(StagedCommitOutcome::Poisoned {
                    bucket,
                    key,
                    detail,
                }) => {
                    summary.poisoned += 1;
                    tracing::error!(
                        bucket,
                        key,
                        detail,
                        "an interrupted commit could not be attributed to either write; the \
                         object has been marked corrupted so reads fail closed until it is \
                         overwritten or repaired, and the staged sidecar remains in tmp for \
                         inspection"
                    );
                }
                Err(err) => {
                    return Err(std::io::Error::new(
                        err.kind(),
                        format!(
                            "commit recovery could not process staged sidecar {}: {}; refusing \
                             to serve until the staged commits can be examined",
                            staged_path.display(),
                            err
                        ),
                    ));
                }
            }
        }
        Ok(summary)
    }

    pub(super) fn recover_one_staged_commit_sync(
        &self,
        staged_path: &Path,
    ) -> std::io::Result<StagedCommitOutcome> {
        let discard = |reason: &'static str| -> std::io::Result<StagedCommitOutcome> {
            std::fs::remove_file(staged_path)?;
            Ok(StagedCommitOutcome::Discarded { reason })
        };
        let content = std::fs::read_to_string(staged_path)?;
        let Ok(entry) = serde_json::from_str::<HashMap<String, Value>>(&content) else {
            return discard("the staged sidecar is not valid JSON");
        };
        let bucket = entry
            .get(SIDECAR_COMMIT_BUCKET_FIELD)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let key = entry
            .get(SIDECAR_COMMIT_KEY_FIELD)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let (Some(bucket), Some(key)) = (bucket, key) else {
            return discard(
                "the staged sidecar predates commit recovery and records no destination",
            );
        };
        if validation::validate_bucket_name(&bucket).is_some() {
            return discard("the staged sidecar records an invalid bucket name");
        }
        if self.validate_key(&key).is_err() {
            return discard("the staged sidecar records an invalid object key");
        }
        if !self.bucket_path(&bucket).is_dir() {
            return discard("the destination bucket no longer exists");
        }
        let Some(metadata) = entry.get("metadata").and_then(Value::as_object) else {
            return discard("the staged sidecar has no metadata object");
        };
        let staged_meta_str = |field: &str| -> Option<String> {
            metadata
                .get(field)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let etag = staged_meta_str("__etag__").unwrap_or_default();
        let (Some(expected_size), Some(expected_mtime)) = (
            staged_meta_str("__size__").and_then(|s| s.parse::<u64>().ok()),
            staged_meta_str("__last_modified__").and_then(|s| s.parse::<f64>().ok()),
        ) else {
            return discard("the staged sidecar records no size or modification time");
        };

        let staged_mtime_ns =
            staged_meta_str(META_KEY_COMMIT_MTIME_NS).and_then(|s| s.parse::<u128>().ok());

        let live = self.object_live_path(&bucket, &key);
        let live_meta = match std::fs::metadata(&live) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return discard("the data file was never renamed into place");
            }
            Err(err) => {
                return Err(std::io::Error::new(
                    err.kind(),
                    format!(
                        "commit recovery could not inspect the live data for {}/{}: {}",
                        bucket, key, err
                    ),
                ));
            }
        };
        let live_mtime_duration = live_meta
            .modified()
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map_err(std::io::Error::other)
            })
            .map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!(
                        "commit recovery could not read the live data's timestamp for {}/{}: {}",
                        bucket, key, err
                    ),
                )
            })?;
        let existing = self.read_index_entry_sync(&bucket, &key);
        let existing_commit_ns = existing
            .as_ref()
            .and_then(|e| e.get("metadata"))
            .and_then(Value::as_object)
            .and_then(|m| m.get(META_KEY_COMMIT_MTIME_NS))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u128>().ok());
        let precise_identity = match staged_mtime_ns {
            Some(staged_ns) => {
                if staged_ns != live_mtime_duration.as_nanos() {
                    return discard("the live data does not carry the staged commit's timestamp");
                }
                match (&existing, existing_commit_ns) {
                    (None, _) => true,
                    (Some(_), Some(previous_ns)) => previous_ns != staged_ns,
                    (Some(_), None) => false,
                }
            }
            None => {
                let live_mtime = live_mtime_duration.as_secs_f64();
                if (live_mtime - expected_mtime).abs() >= 1e-3 {
                    return discard("the live data does not carry the staged commit's timestamp");
                }
                false
            }
        };
        if live_meta.len() != expected_size {
            return self.poison_torn_commit(
                bucket,
                key,
                format!(
                    "interrupted commit: the live data carries the staged commit's timestamp \
                     but its size ({}) does not match the staged size ({})",
                    live_meta.len(),
                    expected_size
                ),
            );
        }
        if let Some(seg_id) = metadata
            .get(crate::segments::META_KEY_SEGMENTS)
            .and_then(Value::as_str)
        {
            let stub_matches = matches!(
                crate::segments::read_stub_header(&live),
                Ok(Some(ref header)) if header.segment_id == seg_id && header.etag == etag
            );
            if !stub_matches {
                return self.poison_torn_commit(
                    bucket,
                    key,
                    "interrupted commit: the live data matches the staged commit's timestamp \
                     and size but is not the expected segment stub"
                        .to_string(),
                );
            }
            return self.publish_recovered_commit(bucket, key, etag, &entry, existing);
        }
        let existing_meta = existing
            .as_ref()
            .and_then(|e| e.get("metadata"))
            .and_then(Value::as_object);
        let existing_mtime = existing_meta
            .and_then(|m| m.get("__last_modified__"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<f64>().ok());
        let existing_size = existing_meta
            .and_then(|m| m.get("__size__"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok());
        let existing_etag = existing_meta
            .and_then(|m| m.get("__etag__"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let indistinguishable = existing_mtime
            .is_some_and(|mtime| (mtime - expected_mtime).abs() < 1e-3)
            && existing_size == Some(expected_size);
        if indistinguishable && !precise_identity {
            let etag_is_stored_digest =
                |candidate: &str, meta: Option<&serde_json::Map<String, Value>>| {
                    !candidate.contains('-')
                        && !meta.is_some_and(|m| m.contains_key("x-amz-server-side-encryption"))
                };
            let hashable = etag_is_stored_digest(&etag, Some(metadata))
                && existing_etag
                    .as_deref()
                    .is_some_and(|e| etag_is_stored_digest(e, existing_meta));
            if !hashable {
                return self.poison_torn_commit(
                    bucket,
                    key,
                    "interrupted commit: the live data cannot be attributed to either write \
                     (no filesystem identity recorded and the etags are not stored-byte \
                     digests)"
                        .to_string(),
                );
            }
            let actual = myfsio_crypto::hashing::md5_file(&live)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if actual == etag {
                return self.publish_recovered_commit(bucket, key, etag, &entry, existing);
            }
            if existing_etag.as_deref() == Some(actual.as_str()) {
                return discard("the live data hashes to the previously published object");
            }
            return self.poison_torn_commit(
                bucket,
                key,
                "interrupted commit: the live data hashes to neither the staged commit nor \
                 the previously published metadata"
                    .to_string(),
            );
        }
        self.publish_recovered_commit(bucket, key, etag, &entry, existing)
    }

    pub(super) fn publish_recovered_commit(
        &self,
        bucket: String,
        key: String,
        etag: String,
        entry: &HashMap<String, Value>,
        existing: Option<HashMap<String, Value>>,
    ) -> std::io::Result<StagedCommitOutcome> {
        let staged_metadata = entry
            .get("metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let bucket_config = self.read_bucket_config_sync(&bucket);
        if bucket_config.unreadable {
            return Err(std::io::Error::other(format!(
                "the configuration for bucket '{}' is unreadable, so the interrupted commit's \
                 versioning behaviour cannot be replayed",
                bucket
            )));
        }
        let versioning_status = bucket_config.versioning_status();
        let existing_meta = existing
            .as_ref()
            .and_then(|e| e.get("metadata"))
            .and_then(Value::as_object);
        let old_segments = existing_meta
            .and_then(|m| m.get(crate::segments::META_KEY_SEGMENTS))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let old_version_id = existing_meta
            .and_then(|m| m.get("__version_id__"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        {
            let (sidecar_path, entry_name) = self.sidecar_file_for_key(&bucket, &key);
            let mut sidecar_entry = entry.clone();
            sidecar_entry.insert(
                SIDECAR_ENTRY_NAME_FIELD.to_string(),
                Value::String(entry_name),
            );
            let json_val = serde_json::to_value(&sidecar_entry).map_err(std::io::Error::other)?;
            let lock = self.get_meta_index_lock(&sidecar_path.to_string_lossy());
            let _guard = lock.lock();
            Self::atomic_write_json_sync(&sidecar_path, &json_val, true)?;
        }
        let old_meta = self
            .bucket_meta_root(&bucket)
            .join(format!("{}.meta.json", key));
        if old_meta.exists() {
            let _ = std::fs::remove_file(&old_meta);
        }
        self.meta_read_cache
            .lock()
            .pop(&(bucket.clone(), key.clone()));
        if matches!(versioning_status, VersioningStatus::Suspended) {
            self.purge_archived_null_version_sync(&bucket, &key)?;
        }
        let release_old = match versioning_status {
            VersioningStatus::Disabled => true,
            VersioningStatus::Suspended => old_version_id.is_empty() || old_version_id == "null",
            VersioningStatus::Enabled => false,
        };
        if release_old {
            if let Some(old_seg) = old_segments {
                let staged_seg = staged_metadata
                    .get(crate::segments::META_KEY_SEGMENTS)
                    .and_then(Value::as_str);
                if staged_seg != Some(old_seg.as_str()) {
                    self.release_segment_dir(&bucket, &old_seg);
                }
            }
        }
        self.invalidate_bucket_caches(&bucket);
        if versioning_status.is_active() {
            self.clear_delete_marker_sync(&bucket, &key);
        }
        Ok(StagedCommitOutcome::Published { bucket, key, etag })
    }

    pub fn finish_recovered_commit_sync(&self, staged_path: &Path) -> std::io::Result<()> {
        if staged_path.parent() != Some(self.tmp_dir().as_path()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "a recovered commit intent must live in the storage tmp directory",
            ));
        }
        match std::fs::remove_file(staged_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(super) fn poison_object_metadata_sync(
        &self,
        bucket: &str,
        key: &str,
        detail: &str,
    ) -> std::io::Result<()> {
        let mut metadata = self.read_metadata_sync(bucket, key);
        metadata.insert(META_KEY_CORRUPTED.to_string(), "true".to_string());
        metadata.insert(META_KEY_CORRUPTED_AT.to_string(), Utc::now().to_rfc3339());
        metadata.insert(META_KEY_CORRUPTION_DETAIL.to_string(), detail.to_string());
        self.write_live_metadata_entry_sync(bucket, key, &metadata)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        self.meta_read_cache
            .lock()
            .pop(&(bucket.to_string(), key.to_string()));
        self.invalidate_bucket_caches(bucket);
        Ok(())
    }

    pub(super) fn poison_torn_commit(
        &self,
        bucket: String,
        key: String,
        detail: String,
    ) -> std::io::Result<StagedCommitOutcome> {
        self.poison_object_metadata_sync(&bucket, &key, &detail)?;
        Ok(StagedCommitOutcome::Poisoned {
            bucket,
            key,
            detail,
        })
    }

    pub async fn poison_object_if_version_matches(
        &self,
        bucket: &str,
        key: &str,
        expected_version_id: Option<&str>,
        detail: &str,
    ) -> StorageResult<bool> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            let current = self.read_metadata_sync(bucket, key);
            if current.is_empty() {
                return Ok(false);
            }
            let current_version = current.get("__version_id__").map(String::as_str);
            if current_version != expected_version_id {
                return Ok(false);
            }
            self.poison_object_metadata_sync(bucket, key, detail)
                .map_err(StorageError::Io)?;
            Ok(true)
        })
    }

    pub(super) fn handle_torn_runtime_commit(
        &self,
        bucket: &str,
        key: &str,
        staged: &Path,
        cause: &str,
    ) {
        let detail = format!(
            "interrupted commit: metadata publication failed after the data rename ({})",
            cause
        );
        match self.poison_object_metadata_sync(bucket, key, &detail) {
            Ok(()) => {
                tracing::error!(
                    bucket,
                    key,
                    staged = %staged.display(),
                    cause,
                    "object data was committed but its metadata could not be published; the \
                     object is marked corrupted so reads fail closed, and the retained commit \
                     intent will be reconciled at the next startup"
                );
            }
            Err(poison_err) => {
                tracing::error!(
                    bucket,
                    key,
                    staged = %staged.display(),
                    cause,
                    error = %poison_err,
                    "object data was committed but its metadata can neither be published nor \
                     poisoned; terminating to preserve old-or-new atomicity — the retained \
                     commit intent will be reconciled at the next startup"
                );
                std::process::exit(1);
            }
        }
    }
}
