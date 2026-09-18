use super::*;

impl crate::traits::StorageEngine for FsStorageBackend {
    async fn list_buckets(&self) -> StorageResult<Vec<BucketMeta>> {
        let root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            let mut buckets = Vec::new();
            let entries = std::fs::read_dir(&root).map_err(StorageError::Io)?;
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();
                if let Some(reason) = validation::bucket_name_rejection(&name_str) {
                    if !validation::is_reserved_bucket_name(&name_str) {
                        tracing::warn!(
                            directory = name_str,
                            "skipping directory in the storage root that is not a valid bucket \
                             name ({}); it is not served as a bucket. Remove it from the \
                             filesystem if it is not wanted.",
                            reason
                        );
                    }
                    continue;
                }
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if !ft.is_dir() {
                    continue;
                }
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let created = meta
                    .created()
                    .or_else(|_| meta.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        Utc.timestamp_opt(d.as_secs() as i64, d.subsec_nanos())
                            .single()
                            .unwrap_or_else(Utc::now)
                    })
                    .unwrap_or_else(Utc::now);
                buckets.push(BucketMeta {
                    name: name_str,
                    creation_date: created,
                });
            }
            buckets.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(buckets)
        })
        .await
        .map_err(|e| StorageError::Internal(e.to_string()))?
    }

    async fn create_bucket(&self, name: &str) -> StorageResult<()> {
        run_blocking(|| {
            Self::guard_bucket_name(name)?;
            let bucket_path = self.bucket_path(name);
            self.guard_contained(&bucket_path, name)?;
            if let Some(parent) = bucket_path.parent() {
                std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
            }
            let rebuild_lock = self.get_list_rebuild_lock(name);
            let _rebuild_guard = rebuild_lock.lock();

            if bucket_path.exists() {
                return Err(StorageError::BucketAlreadyExists(name.to_string()));
            }

            self.discard_listing_index_locked_sync(name);
            Self::remove_tree(&self.system_bucket_root(name)).map_err(StorageError::Io)?;
            Self::remove_tree(&self.multipart_bucket_root(name)).map_err(StorageError::Io)?;
            self.remove_legacy_bucket_policy_sync(name)
                .map_err(StorageError::Io)?;
            self.bucket_config_cache.remove(name);
            self.invalidate_bucket_caches(name);
            self.purge_meta_read_cache_for_bucket(name);

            match std::fs::create_dir(&bucket_path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(StorageError::BucketAlreadyExists(name.to_string()));
                }
                Err(err) => return Err(StorageError::Io(err)),
            }
            if let Err(err) = std::fs::create_dir_all(self.system_bucket_root(name)) {
                let _ = std::fs::remove_dir(&bucket_path);
                return Err(StorageError::Io(err));
            }
            Ok(())
        })
    }

    async fn delete_bucket(&self, name: &str) -> StorageResult<()> {
        run_blocking(|| {
            let bucket_path = self.require_bucket(name)?;
            let (has_objects, has_versions, has_multipart) = self
                .check_bucket_contents_sync(&bucket_path)
                .map_err(StorageError::Io)?;
            if has_objects {
                return Err(StorageError::BucketNotEmpty(name.to_string()));
            }
            if has_versions {
                return Err(StorageError::BucketNotEmpty(
                    "Bucket contains archived object versions".to_string(),
                ));
            }
            if has_multipart {
                return Err(StorageError::BucketNotEmpty(
                    "Bucket has active multipart uploads".to_string(),
                ));
            }

            let rebuild_lock = self.get_list_rebuild_lock(name);
            let _rebuild_guard = rebuild_lock.lock();
            self.discard_listing_index_locked_sync(name);
            Self::remove_tree(&bucket_path).map_err(StorageError::Io)?;
            Self::remove_tree(&self.system_bucket_root(name)).map_err(StorageError::Io)?;
            Self::remove_tree(&self.multipart_bucket_root(name)).map_err(StorageError::Io)?;
            self.remove_legacy_bucket_policy_sync(name)
                .map_err(StorageError::Io)?;

            self.bucket_config_cache.remove(name);
            self.invalidate_bucket_caches(name);
            self.purge_meta_read_cache_for_bucket(name);

            Ok(())
        })
    }

    async fn bucket_exists(&self, name: &str) -> StorageResult<bool> {
        run_blocking(|| {
            if validation::bucket_name_rejection(name).is_some() {
                return Ok(false);
            }
            let path = self.bucket_path(name);
            if self.guard_contained(&path, name).is_err() {
                return Ok(false);
            }
            Ok(path.exists())
        })
    }

    async fn bucket_stats(&self, name: &str) -> StorageResult<BucketStats> {
        run_blocking(|| self.bucket_stats_sync(name))
    }

    async fn put_object(
        &self,
        bucket: &str,
        key: &str,
        stream: AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<ObjectMeta> {
        self.put_object_with_etag_override(bucket, key, stream, metadata, None)
            .await
    }

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let link = self.tmp_dir().join(format!("read-{}", Uuid::new_v4()));
        let (obj, source) = self.snapshot_object_to_link(bucket, key, &link).await?;
        let stream = source
            .into_range_stream(0, None)
            .await
            .map_err(StorageError::Io)?;
        Ok((obj, stream))
    }

    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        len: Option<u64>,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let hint = crate::traits::RangeHint {
            start: Some(start),
            end: len
                .and_then(|l| l.checked_sub(1))
                .and_then(|l| start.checked_add(l)),
        };
        let link = self.tmp_dir().join(format!("read-{}", Uuid::new_v4()));
        let (obj, source) = self
            .snapshot_object_to_link_windowed(bucket, key, &link, Some(hint))
            .await?;
        if start > obj.size {
            return Err(StorageError::InvalidRange);
        }
        let stream = source
            .into_range_stream(start, len)
            .await
            .map_err(StorageError::Io)?;
        Ok((obj, stream))
    }

    async fn get_object_snapshot(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<(ObjectMeta, tokio::fs::File)> {
        let (obj, content) = run_blocking(|| self.open_object_for_read_sync(bucket, key, None))?;
        match content {
            OpenedObjectContent::Single(file) => Ok((obj, tokio::fs::File::from_std(file))),
            OpenedObjectContent::Segmented { .. } => Err(StorageError::Internal(
                "get_object_snapshot is not supported for segmented objects".to_string(),
            )),
        }
    }

    async fn get_object_version_snapshot(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, tokio::fs::File)> {
        let (obj, content) =
            run_blocking(|| self.open_version_for_read_sync(bucket, key, version_id, None))?;
        match content {
            OpenedObjectContent::Single(file) => Ok((obj, tokio::fs::File::from_std(file))),
            OpenedObjectContent::Segmented { .. } => Err(StorageError::Internal(
                "get_object_version_snapshot is not supported for segmented objects".to_string(),
            )),
        }
    }

    async fn snapshot_object_to_link_windowed(
        &self,
        bucket: &str,
        key: &str,
        link_path: &std::path::Path,
        window: Option<crate::traits::RangeHint>,
    ) -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
        let link_owned = link_path.to_owned();
        run_blocking(
            || -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
                let _guard = self.get_object_lock(bucket, key).read();
                let (obj, content) = self.open_object_for_read_locked_sync(bucket, key, window)?;
                match content {
                    OpenedObjectContent::Single(_) => {
                        let path = self.object_live_path(bucket, key);
                        if let Some(parent) = link_owned.parent() {
                            std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
                        }
                        let _ = std::fs::remove_file(&link_owned);
                        std::fs::hard_link(&path, &link_owned).map_err(StorageError::Io)?;
                        Ok((obj, crate::traits::SnapshotSource::LinkedFile(link_owned)))
                    }
                    OpenedObjectContent::Segmented {
                        source,
                        total,
                        base_offset,
                    } => {
                        let path = self.object_live_path(bucket, key);
                        let snapshot = self.snapshot_segmented_content_sync(
                            &path,
                            &link_owned,
                            source,
                            total,
                            base_offset,
                        )?;
                        Ok((obj, snapshot))
                    }
                }
            },
        )
    }

    async fn snapshot_object_version_to_link_windowed(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        link_path: &std::path::Path,
        window: Option<crate::traits::RangeHint>,
    ) -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
        let link_owned = link_path.to_owned();
        run_blocking(
            || -> StorageResult<(ObjectMeta, crate::traits::SnapshotSource)> {
                let _guard = self.get_object_lock(bucket, key).read();
                let (obj, content) =
                    self.open_version_for_read_locked_sync(bucket, key, version_id, window)?;
                match content {
                    OpenedObjectContent::Single(_) => {
                        let (_, data_path) =
                            self.read_version_record_sync(bucket, key, version_id)?;
                        if let Some(parent) = link_owned.parent() {
                            std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
                        }
                        let _ = std::fs::remove_file(&link_owned);
                        std::fs::hard_link(&data_path, &link_owned).map_err(StorageError::Io)?;
                        Ok((obj, crate::traits::SnapshotSource::LinkedFile(link_owned)))
                    }
                    OpenedObjectContent::Segmented {
                        source,
                        total,
                        base_offset,
                    } => {
                        let (_, data_path) =
                            self.read_version_record_sync(bucket, key, version_id)?;
                        let snapshot = self.snapshot_segmented_content_sync(
                            &data_path,
                            &link_owned,
                            source,
                            total,
                            base_offset,
                        )?;
                        Ok((obj, snapshot))
                    }
                }
            },
        )
    }

    async fn materialize_object_to_tmp(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let dest = tmp_dir.join(format!("mat-{}", Uuid::new_v4()));
        let dest_owned = dest.clone();
        let result = run_blocking(move || -> StorageResult<()> {
            let _guard = self.get_object_lock(bucket, key).read();
            let (_, content) = self.open_object_for_read_locked_sync(bucket, key, None)?;
            match content {
                OpenedObjectContent::Single(_) => {
                    let path = self.object_live_path(bucket, key);
                    if std::fs::hard_link(&path, &dest_owned).is_err() {
                        std::fs::copy(&path, &dest_owned).map_err(StorageError::Io)?;
                    }
                    Ok(())
                }
                OpenedObjectContent::Segmented { source, .. } => {
                    let mut out = std::fs::File::create(&dest_owned).map_err(StorageError::Io)?;
                    let expected = source.paths().total();
                    let mut reader = crate::segments::LazyOpenSegmentsRead::new(source);
                    let copied = std::io::copy(&mut reader, &mut out).map_err(StorageError::Io)?;
                    if copied != expected {
                        return Err(StorageError::Internal(
                            "segment changed while materializing object".to_string(),
                        ));
                    }
                    Ok(())
                }
            }
        });
        if result.is_err() {
            let _ = tokio::fs::remove_file(&dest).await;
        }
        result?;
        Ok(dest)
    }

    async fn get_object_path(&self, bucket: &str, key: &str) -> StorageResult<PathBuf> {
        run_blocking(|| {
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                let stored_meta = self.read_metadata_sync(bucket, key);
                if metadata_is_corrupted(&stored_meta) {
                    return Err(StorageError::ObjectCorrupted {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                        detail: metadata_corruption_detail(&stored_meta),
                    });
                }
                if self.read_bucket_config_sync(bucket).versioning_enabled {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }
            Ok(path)
        })
    }

    async fn head_object(&self, bucket: &str, key: &str) -> StorageResult<ObjectMeta> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            if !path.is_file() {
                let stored_meta = self.read_metadata_sync(bucket, key);
                if metadata_is_corrupted(&stored_meta) {
                    return Err(StorageError::ObjectCorrupted {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                        detail: metadata_corruption_detail(&stored_meta),
                    });
                }
                if self
                    .read_bucket_config_sync(bucket)
                    .versioning_status()
                    .is_active()
                {
                    if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                        return Err(StorageError::DeleteMarker {
                            bucket: bucket.to_string(),
                            key: key.to_string(),
                            version_id: dm_version_id,
                        });
                    }
                }
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }

            let meta = std::fs::metadata(&path).map_err(StorageError::Io)?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let lm = Utc
                .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
                .single()
                .unwrap_or_else(Utc::now);

            let stored_meta = self.read_metadata_sync(bucket, key);
            if metadata_is_corrupted(&stored_meta) {
                return Err(StorageError::ObjectCorrupted {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    detail: metadata_corruption_detail(&stored_meta),
                });
            }
            let mut obj = ObjectMeta::new(key.to_string(), meta.len(), lm);
            obj.etag = stored_meta.get("__etag__").cloned();
            obj.content_type = stored_meta.get("__content_type__").cloned();
            obj.storage_class = stored_meta
                .get("__storage_class__")
                .cloned()
                .or_else(|| Some("STANDARD".to_string()));
            obj.version_id = stored_meta.get("__version_id__").cloned();
            obj.metadata = stored_meta
                .iter()
                .filter(|(k, _)| !k.starts_with("__"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            obj.internal_metadata = stored_meta;
            Ok(obj)
        })
    }

    async fn get_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let link = self.tmp_dir().join(format!("read-{}", Uuid::new_v4()));
        let (obj, source) = self
            .snapshot_object_version_to_link(bucket, key, version_id, &link)
            .await?;
        let stream = source
            .into_range_stream(0, None)
            .await
            .map_err(StorageError::Io)?;
        Ok((obj, stream))
    }

    async fn get_object_version_range(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        start: u64,
        len: Option<u64>,
    ) -> StorageResult<(ObjectMeta, AsyncReadStream)> {
        let hint = crate::traits::RangeHint {
            start: Some(start),
            end: len
                .and_then(|l| l.checked_sub(1))
                .and_then(|l| start.checked_add(l)),
        };
        let link = self.tmp_dir().join(format!("read-{}", Uuid::new_v4()));
        let (obj, source) = self
            .snapshot_object_version_to_link_windowed(bucket, key, version_id, &link, Some(hint))
            .await?;
        if start > obj.size {
            return Err(StorageError::InvalidRange);
        }
        let stream = source
            .into_range_stream(start, len)
            .await
            .map_err(StorageError::Io)?;
        Ok((obj, stream))
    }

    async fn get_object_version_path(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<PathBuf> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            Ok(data_path)
        })
    }

    async fn head_object_version(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<ObjectMeta> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            self.object_meta_from_version_record(key, &record, &data_path)
        })
    }

    async fn get_object_version_metadata(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<HashMap<String, String>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, _data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            Ok(Self::version_metadata_from_record(&record))
        })
    }

    async fn get_archived_null_version_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<Option<HashMap<String, String>>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            self.validate_key(key)?;
            self.guard_versioned_key_casing(bucket, key)?;
            let (manifest_path, _) = self.version_record_paths(bucket, key, "null");
            if !manifest_path.is_file() {
                return Ok(None);
            }
            let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
            let record: Value = serde_json::from_str(&content).map_err(StorageError::Json)?;
            Ok(Some(Self::version_metadata_from_record(&record)))
        })
    }

    async fn delete_object_checked(
        &self,
        bucket: &str,
        key: &str,
        bypass_governance: bool,
    ) -> StorageResult<DeleteOutcome> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            let bucket_path = self.require_bucket(bucket)?;
            let path = self.object_path(bucket, key)?;
            let bucket_config = self.read_bucket_config_sync(bucket);
            if bucket_config.unreadable {
                return Err(StorageError::Internal(format!(
                    "Bucket configuration for '{}' is unreadable or corrupt; refusing to delete, \
                     because versioning settings cannot be determined",
                    bucket
                )));
            }
            let versioning_status = bucket_config.versioning_status();

            if path.exists() {
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&self.root, "delete:data-remove")
                    .map_err(StorageError::Io)?;
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&self.root, "delete:metadata-remove")
                    .map_err(StorageError::Io)?;
            }
            if versioning_status.is_active() {
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&self.root, "delete:marker-write")
                    .map_err(StorageError::Io)?;
            }

            if versioning_status.is_active() {
                let mut version_mutations = Vec::new();
                if path.exists() {
                    let existing_meta = self.read_metadata_sync(bucket, key);
                    let existing_vid = existing_meta
                        .get("__version_id__")
                        .map(String::as_str)
                        .unwrap_or("");
                    let should_archive = match versioning_status {
                        VersioningStatus::Enabled => true,
                        VersioningStatus::Suspended => {
                            !existing_vid.is_empty() && existing_vid != "null"
                        }
                        VersioningStatus::Disabled => false,
                    };
                    if should_archive {
                        if let Some(mutation) = self
                            .archive_current_version_sync(bucket, key, "delete")
                            .map_err(StorageError::Io)?
                        {
                            version_mutations.push(mutation);
                        }
                    } else {
                        if let Err(message) = myfsio_common::object_lock::can_delete_object(
                            &existing_meta,
                            bypass_governance,
                        ) {
                            return Err(StorageError::ObjectLocked(message));
                        }
                        if let Some(seg_id) = existing_meta.get(crate::segments::META_KEY_SEGMENTS)
                        {
                            self.release_segment_dir(bucket, seg_id);
                        }
                    }
                    Self::safe_unlink(&path).map_err(StorageError::Io)?;
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    self.cleanup_empty_parents(&path, &bucket_path);
                } else {
                    let stored_meta = self.read_metadata_sync(bucket, key);
                    if !stored_meta.is_empty() {
                        self.delete_metadata_sync(bucket, key)
                            .map_err(StorageError::Io)?;
                    }
                }
                let dm_version_id = self
                    .write_delete_marker_sync(bucket, key)
                    .map_err(StorageError::Io)?;
                version_mutations.push(VersionMutation {
                    version_id: dm_version_id.clone(),
                    kind: VersionMutationKind::DeleteMarkerCreate,
                    logical_size: 0,
                    delete_marker: true,
                });
                self.invalidate_bucket_caches(bucket);
                self.update_listing_index_after_commit_with_versions(
                    bucket,
                    key,
                    &version_mutations,
                );
                return Ok(DeleteOutcome {
                    version_id: Some(dm_version_id),
                    is_delete_marker: true,
                    existed: true,
                });
            }

            if !path.exists() {
                let stored_meta = self.read_metadata_sync(bucket, key);
                if !stored_meta.is_empty() {
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    self.invalidate_bucket_caches(bucket);
                    self.update_listing_index_after_commit(bucket, key);
                    return Ok(DeleteOutcome {
                        version_id: None,
                        is_delete_marker: false,
                        existed: true,
                    });
                }
                return Ok(DeleteOutcome::default());
            }

            let stored_meta = self.read_metadata_sync(bucket, key);
            if let Err(message) =
                myfsio_common::object_lock::can_delete_object(&stored_meta, bypass_governance)
            {
                return Err(StorageError::ObjectLocked(message));
            }
            if let Some(seg_id) = stored_meta.get(crate::segments::META_KEY_SEGMENTS) {
                self.release_segment_dir(bucket, seg_id);
            }
            Self::safe_unlink(&path).map_err(StorageError::Io)?;
            #[cfg(any(test, feature = "failpoints"))]
            if let Err(err) = crate::failpoints::hit(&self.root, "delete:before-meta-remove") {
                return Err(StorageError::Io(err));
            }
            self.delete_metadata_sync(bucket, key)
                .map_err(StorageError::Io)?;

            self.cleanup_empty_parents(&path, &bucket_path);
            self.invalidate_bucket_caches(bucket);
            self.update_listing_index_after_commit(bucket, key);
            Ok(DeleteOutcome {
                version_id: None,
                is_delete_marker: false,
                existed: true,
            })
        })
    }

    async fn delete_object_version_checked(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        bypass_governance: bool,
    ) -> StorageResult<DeleteOutcome> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            let bucket_path = self.require_bucket(bucket)?;
            self.validate_key(key)?;
            self.guard_versioned_key_casing(bucket, key)?;
            Self::validate_version_id(bucket, key, version_id)?;

            let live_path = self.object_live_path(bucket, key);
            if live_path.is_file() {
                let metadata = self.read_metadata_sync(bucket, key);
                let stored_version = metadata.get("__version_id__").map(String::as_str);
                let live_matches = if version_id == "null" {
                    stored_version.is_none_or(|v| v.is_empty() || v == "null")
                } else {
                    stored_version == Some(version_id)
                };
                if live_matches {
                    if let Err(message) =
                        myfsio_common::object_lock::can_delete_object(&metadata, bypass_governance)
                    {
                        return Err(StorageError::ObjectLocked(message));
                    }
                    #[cfg(any(test, feature = "failpoints"))]
                    crate::failpoints::hit(&self.root, "delete-version:data-remove")
                        .map_err(StorageError::Io)?;
                    #[cfg(any(test, feature = "failpoints"))]
                    crate::failpoints::hit(&self.root, "delete-version:metadata-remove")
                        .map_err(StorageError::Io)?;
                    if let Some(seg_id) = metadata.get(crate::segments::META_KEY_SEGMENTS) {
                        self.release_segment_dir(bucket, seg_id);
                    }
                    Self::safe_unlink(&live_path).map_err(StorageError::Io)?;
                    self.delete_metadata_sync(bucket, key)
                        .map_err(StorageError::Io)?;
                    self.cleanup_empty_parents(&live_path, &bucket_path);
                    let version_mutations = self
                        .promote_latest_archived_to_live_sync(bucket, key)
                        .map_err(StorageError::Io)?
                        .into_iter()
                        .collect::<Vec<_>>();
                    self.invalidate_bucket_caches(bucket);
                    self.update_listing_index_after_commit_with_versions(
                        bucket,
                        key,
                        &version_mutations,
                    );
                    return Ok(DeleteOutcome {
                        version_id: Some(version_id.to_string()),
                        is_delete_marker: false,
                        existed: true,
                    });
                }
            }

            let (manifest_path, data_path) = self.version_record_paths(bucket, key, version_id);
            if !manifest_path.is_file() && !data_path.is_file() {
                return Err(StorageError::VersionNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: version_id.to_string(),
                });
            }

            let version_record = if manifest_path.is_file() {
                std::fs::read_to_string(&manifest_path)
                    .ok()
                    .and_then(|content| serde_json::from_str::<Value>(&content).ok())
            } else {
                None
            };
            let is_delete_marker = version_record
                .as_ref()
                .and_then(|record| record.get("is_delete_marker").and_then(Value::as_bool))
                .unwrap_or(false);
            let logical_size = if is_delete_marker {
                0
            } else {
                version_record
                    .as_ref()
                    .and_then(|record| record.get("size").and_then(Value::as_u64))
                    .or_else(|| {
                        std::fs::metadata(&data_path)
                            .ok()
                            .map(|metadata| metadata.len())
                    })
                    .unwrap_or(0)
            };
            let mut version_mutations = vec![VersionMutation {
                version_id: version_id.to_string(),
                kind: if is_delete_marker {
                    VersionMutationKind::DeleteMarkerRemove
                } else {
                    VersionMutationKind::Purge
                },
                logical_size,
                delete_marker: is_delete_marker,
            }];
            if !is_delete_marker {
                if let Some(record) = version_record.as_ref() {
                    let version_meta = Self::version_metadata_from_record(record);
                    if let Err(message) = myfsio_common::object_lock::can_delete_object(
                        &version_meta,
                        bypass_governance,
                    ) {
                        return Err(StorageError::ObjectLocked(message));
                    }
                }
            }
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "delete-version:data-remove")
                .map_err(StorageError::Io)?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "delete-version:metadata-remove")
                .map_err(StorageError::Io)?;
            if let Some(seg_id) = version_record
                .as_ref()
                .and_then(|record| record.get("segment_id").and_then(Value::as_str))
            {
                self.release_segment_dir(bucket, seg_id);
            }
            Self::safe_unlink(&data_path).map_err(StorageError::Io)?;
            Self::safe_unlink(&manifest_path).map_err(StorageError::Io)?;
            let versions_root = self.bucket_versions_root(bucket);
            self.cleanup_empty_parents(&manifest_path, &versions_root);

            let mut was_active_dm = false;
            if is_delete_marker {
                if let Some((dm_version_id, _)) = self.read_delete_marker_sync(bucket, key) {
                    if dm_version_id == version_id {
                        self.clear_delete_marker_sync(bucket, key);
                        was_active_dm = true;
                    }
                }
            }

            if was_active_dm && !live_path.is_file() {
                if let Some(mutation) = self
                    .promote_latest_archived_to_live_sync(bucket, key)
                    .map_err(StorageError::Io)?
                {
                    version_mutations.push(mutation);
                }
            }

            self.invalidate_bucket_caches(bucket);
            self.update_listing_index_after_commit_with_versions(bucket, key, &version_mutations);
            Ok(DeleteOutcome {
                version_id: Some(version_id.to_string()),
                is_delete_marker,
                existed: true,
            })
        })
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(dst_key)?;
        let chunk_size = self.stream_chunk_size;
        let tmp_dir = self.tmp_dir();
        run_blocking(|| -> StorageResult<()> {
            std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
            self.require_bucket(dst_bucket)?;
            Ok(())
        })?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));
        let new_segment_id = Uuid::new_v4().simple().to_string();
        let new_segment_dir = self.segments_bucket_root(dst_bucket).join(&new_segment_id);

        let copy_res = run_blocking(
            || -> StorageResult<(String, u64, HashMap<String, String>, bool)> {
                let _src_guard = self.get_object_lock(src_bucket, src_key).read();
                let (obj, content) =
                    self.open_object_for_read_locked_sync(src_bucket, src_key, None)?;

                use std::io::{BufReader, BufWriter, Read, Write};
                let mut src_metadata = obj.internal_metadata;
                let mut reader: Box<dyn Read> = match content {
                    OpenedObjectContent::Single(file) => {
                        Box::new(BufReader::with_capacity(chunk_size, file))
                    }
                    OpenedObjectContent::Segmented { source, .. } => {
                        let source_etag = obj.etag.clone().filter(|etag| is_multipart_etag(etag));
                        let can_link = source_etag.is_some()
                            && !myfsio_crypto::encryption::EncryptionMetadata::is_encrypted(
                                &src_metadata,
                            );
                        if can_link {
                            #[cfg(any(test, feature = "failpoints"))]
                            crate::failpoints::hit(&self.root, "put:stage-data-write")
                                .map_err(StorageError::Io)?;
                            std::fs::create_dir_all(&new_segment_dir).map_err(StorageError::Io)?;
                            let mut link_error = None;
                            for (ordinal, (path, _)) in source.paths().entries().iter().enumerate()
                            {
                                let target = new_segment_dir
                                    .join(crate::segments::SegmentSet::seg_file_name(ordinal));
                                if let Err(error) = std::fs::hard_link(path, target) {
                                    link_error = Some(error);
                                    break;
                                }
                            }
                            if let Some(error) = link_error {
                                let _ = std::fs::remove_dir_all(&new_segment_dir);
                                tracing::warn!(
                                    src_bucket,
                                    src_key,
                                    dst_bucket,
                                    dst_key,
                                    error = %error,
                                    "hard-linking segmented CopyObject data failed; streaming fallback selected"
                                );
                            } else {
                                let sizes: Vec<u64> = source
                                    .paths()
                                    .entries()
                                    .iter()
                                    .map(|(_, size)| *size)
                                    .collect();
                                let etag = source_etag.expect("link path requires an etag");
                                let header = crate::segments::StubHeader::new(
                                    new_segment_id.clone(),
                                    sizes.clone(),
                                    etag.clone(),
                                );
                                if let Err(error) = crate::segments::write_stub(&tmp_path, &header)
                                {
                                    let _ = std::fs::remove_dir_all(&new_segment_dir);
                                    return Err(StorageError::Io(error));
                                }
                                let fsync_result = (|| -> std::io::Result<()> {
                                    Self::fsync_dir(&new_segment_dir)?;
                                    if let Some(parent) = new_segment_dir.parent() {
                                        Self::fsync_dir(parent)?;
                                        if let Some(grandparent) = parent.parent() {
                                            Self::fsync_dir(grandparent)?;
                                        }
                                    }
                                    Ok(())
                                })();
                                if let Err(error) = fsync_result {
                                    let _ = std::fs::remove_file(&tmp_path);
                                    let _ = std::fs::remove_dir_all(&new_segment_dir);
                                    return Err(StorageError::Io(error));
                                }
                                src_metadata.insert(
                                    crate::segments::META_KEY_SEGMENTS.to_string(),
                                    new_segment_id.clone(),
                                );
                                src_metadata.insert(
                                    META_KEY_PART_SIZES.to_string(),
                                    encode_part_sizes(&sizes),
                                );
                                return Ok((etag, obj.size, src_metadata, true));
                            }
                        }
                        Box::new(crate::segments::LazyOpenSegmentsRead::new(source))
                    }
                };
                let tmp_file = std::fs::File::create(&tmp_path).map_err(StorageError::Io)?;
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&self.root, "put:stage-data-write")
                    .map_err(StorageError::Io)?;
                let mut writer = BufWriter::with_capacity(chunk_size * 4, tmp_file);
                let mut hasher = Md5::new();
                let mut buf = vec![0u8; chunk_size];
                let mut total: u64 = 0;
                loop {
                    let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    writer.write_all(&buf[..n]).map_err(StorageError::Io)?;
                    total += n as u64;
                }
                writer.flush().map_err(StorageError::Io)?;
                let file = writer
                    .into_inner()
                    .map_err(|error| StorageError::Io(error.into_error()))?;
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&self.root, "put:stage-data-sync")
                    .map_err(StorageError::Io)?;
                file.sync_all().map_err(StorageError::Io)?;

                src_metadata.remove(crate::segments::META_KEY_SEGMENTS);
                src_metadata.remove(META_KEY_PART_SIZES);
                Ok((
                    format!("{:x}", hasher.finalize()),
                    total,
                    src_metadata,
                    false,
                ))
            },
        );

        let (etag, new_size, src_metadata, linked_segments) = match copy_res {
            Ok(v) => v,
            Err(e) => {
                run_blocking(|| {
                    let _ = std::fs::remove_file(&tmp_path);
                    let _ = std::fs::remove_dir_all(&new_segment_dir);
                });
                return Err(e);
            }
        };

        let finalize = run_blocking(|| {
            let quota_lock = self.quota_lock_if_configured(dst_bucket);
            let _quota_guard = quota_lock.as_ref().map(|lock| lock.lock());
            let _dst_guard = self.get_object_lock(dst_bucket, dst_key).write();
            self.finalize_put_sync(
                dst_bucket,
                dst_key,
                &tmp_path,
                etag,
                new_size,
                Some(src_metadata),
                &crate::traits::PutCommitOptions::default(),
            )
        });

        if finalize.is_err() {
            run_blocking(|| {
                let _ = std::fs::remove_file(&tmp_path);
                if linked_segments {
                    let live_owns_segments = crate::segments::read_stub_header(
                        &self.object_live_path(dst_bucket, dst_key),
                    )
                    .ok()
                    .flatten()
                    .is_some_and(|header| header.segment_id == new_segment_id);
                    if !live_owns_segments {
                        let _ = std::fs::remove_dir_all(&new_segment_dir);
                    }
                }
            });
        }
        finalize
    }

    async fn get_object_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<HashMap<String, String>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.guard_object_casing(bucket, key)?;
            Ok(self.read_metadata_sync(bucket, key))
        })
    }

    async fn put_object_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.guard_object_casing(bucket, key)?;
            let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
            let meta_map: serde_json::Map<String, Value> = metadata
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            entry.insert("metadata".to_string(), Value::Object(meta_map));
            self.write_index_entry_sync(bucket, key, &entry)
                .map_err(StorageError::Io)?;
            self.invalidate_bucket_caches(bucket);
            self.update_listing_index_after_commit(bucket, key);
            Ok(())
        })
    }

    async fn put_object_version_metadata(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            self.validate_key(key)?;
            self.guard_versioned_key_casing(bucket, key)?;
            Self::validate_version_id(bucket, key, version_id)?;

            if self
                .try_live_version_record_sync(bucket, key, version_id)
                .is_some()
            {
                let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
                let meta_map: serde_json::Map<String, Value> = metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                entry.insert("metadata".to_string(), Value::Object(meta_map));
                self.write_index_entry_sync(bucket, key, &entry)
                    .map_err(StorageError::Io)?;
                self.invalidate_bucket_caches(bucket);
                self.update_listing_index_after_commit(bucket, key);
                return Ok(());
            }

            let (manifest_path, _data_path) = self.version_record_paths(bucket, key, version_id);
            if !manifest_path.is_file() {
                return Err(StorageError::VersionNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                    version_id: version_id.to_string(),
                });
            }
            let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
            let mut record: Value = serde_json::from_str(&content).map_err(StorageError::Json)?;
            let meta_map: serde_json::Map<String, Value> = metadata
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            match record {
                Value::Object(ref mut map) => {
                    map.insert("metadata".to_string(), Value::Object(meta_map));
                }
                _ => {
                    return Err(StorageError::Internal(
                        "Invalid version manifest".to_string(),
                    ));
                }
            }
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "metadata:version-rewrite")
                .map_err(StorageError::Io)?;
            Self::atomic_write_json_sync(&manifest_path, &record, true)
                .map_err(StorageError::Io)?;
            self.invalidate_bucket_caches(bucket);
            Ok(())
        })
    }

    async fn update_object_retention(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        retention: &myfsio_common::object_lock::ObjectLockRetention,
        bypass_governance: bool,
    ) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.mutate_object_metadata_locked_sync(bucket, key, version_id, |metadata| {
                myfsio_common::object_lock::ensure_retention_update_allowed(
                    metadata,
                    retention,
                    bypass_governance,
                )
                .map_err(StorageError::ObjectLocked)?;
                myfsio_common::object_lock::set_object_retention(metadata, retention)
                    .map_err(StorageError::InvalidArgument)
            })
        })
    }

    async fn update_object_legal_hold(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        enabled: bool,
    ) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.mutate_object_metadata_locked_sync(bucket, key, version_id, |metadata| {
                myfsio_common::object_lock::set_legal_hold(metadata, enabled);
                Ok(())
            })
        })
    }

    async fn list_objects(
        &self,
        bucket: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        run_blocking(|| self.list_objects_sync(bucket, params))
    }

    async fn list_objects_shallow(
        &self,
        bucket: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult> {
        run_blocking(|| self.list_objects_shallow_sync(bucket, params))
    }

    async fn initiate_multipart(
        &self,
        bucket: &str,
        key: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> StorageResult<String> {
        run_blocking(|| {
            self.require_bucket(bucket)?;
            self.validate_key(key)?;

            let upload_id = Uuid::new_v4().to_string().replace('-', "");
            let upload_dir = self.multipart_bucket_root(bucket).join(&upload_id);
            std::fs::create_dir_all(&upload_dir).map_err(StorageError::Io)?;

            let manifest = serde_json::json!({
                "upload_id": upload_id,
                "object_key": key,
                "metadata": metadata.unwrap_or_default(),
                "created_at": Utc::now().to_rfc3339(),
                "parts": {}
            });

            let manifest_path = upload_dir.join(MANIFEST_FILE);
            #[cfg(any(test, feature = "failpoints"))]
            let write_result = crate::failpoints::hit(&self.root, "mpu:manifest-write")
                .and_then(|()| Self::atomic_write_json_sync(&manifest_path, &manifest, true));
            #[cfg(not(any(test, feature = "failpoints")))]
            let write_result = Self::atomic_write_json_sync(&manifest_path, &manifest, true);
            if let Err(error) = write_result {
                let _ = std::fs::remove_dir_all(&upload_dir);
                return Err(StorageError::Io(error));
            }

            Ok(upload_id)
        })
    }

    async fn upload_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        stream: AsyncReadStream,
    ) -> StorageResult<String> {
        let upload_dir = run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            if !upload_dir.join(MANIFEST_FILE).exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }
            Ok(upload_dir)
        })?;

        let part_file = Self::part_data_path(&upload_dir, part_number);
        let tmp_file = upload_dir.join(format!("part-{:05}.{}.tmp", part_number, Uuid::new_v4()));

        let chunk_size = self.stream_chunk_size;
        let tmp_file_owned = tmp_file.clone();
        #[cfg(any(test, feature = "failpoints"))]
        let fp_root = self.root.clone();
        let drain_res = tokio::task::spawn_blocking(move || -> StorageResult<(String, u64)> {
            use std::io::{BufWriter, Read, Write};
            let mut reader = tokio_util::io::SyncIoBridge::new(stream);
            let file = std::fs::File::create(&tmp_file_owned).map_err(StorageError::Io)?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&fp_root, "mpu:part-write").map_err(StorageError::Io)?;
            let mut writer = BufWriter::with_capacity(chunk_size * 4, file);
            let mut hasher = Md5::new();
            let mut part_size: u64 = 0;
            let mut buf = vec![0u8; chunk_size];
            loop {
                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                writer.write_all(&buf[..n]).map_err(StorageError::Io)?;
                part_size += n as u64;
            }
            let file = writer
                .into_inner()
                .map_err(|e| StorageError::Io(e.into_error()))?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&fp_root, "mpu:part-sync").map_err(StorageError::Io)?;
            file.sync_all().map_err(StorageError::Io)?;
            Ok((format!("{:x}", hasher.finalize()), part_size))
        })
        .await;

        let (etag, part_size) = match drain_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_file).await;
                return Err(e);
            }
            Err(join) => {
                let _ = tokio::fs::remove_file(&tmp_file).await;
                return Err(StorageError::Io(std::io::Error::other(join)));
            }
        };

        run_blocking(|| -> StorageResult<()> {
            let lock_path = upload_dir.join(".manifest.lock");
            let lock = self.get_meta_index_lock(&lock_path.to_string_lossy());
            let _guard = lock.lock();
            #[cfg(any(test, feature = "failpoints"))]
            if let Err(error) = crate::failpoints::hit(&self.root, "mpu:part-publish") {
                let _ = std::fs::remove_file(&tmp_file);
                return Err(StorageError::Io(error));
            }
            let displaced_record = Self::read_part_record_sync(&upload_dir, part_number);
            if let Err(error) = Self::retract_part_record_sync(&self.root, &upload_dir, part_number)
            {
                let _ = std::fs::remove_file(&tmp_file);
                Self::restore_displaced_part_record(&upload_dir, part_number, displaced_record);
                return Err(StorageError::Io(error));
            }
            if let Err(error) = std::fs::rename(&tmp_file, &part_file) {
                let _ = std::fs::remove_file(&tmp_file);
                Self::restore_displaced_part_record(&upload_dir, part_number, displaced_record);
                return Err(StorageError::Io(error));
            }
            self.publish_part_record_sync(&upload_dir, part_number, &etag, part_size)
                .map_err(StorageError::Io)
        })?;

        Ok(etag)
    }

    async fn upload_part_copy(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        src_bucket: &str,
        src_key: &str,
        src_version_id: Option<&str>,
        range: Option<(u64, u64)>,
    ) -> StorageResult<(String, DateTime<Utc>)> {
        let upload_dir = run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            if !upload_dir.join(MANIFEST_FILE).exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }
            Ok(upload_dir)
        })?;

        let part_file = Self::part_data_path(&upload_dir, part_number);
        let tmp_file = upload_dir.join(format!("part-{:05}.{}.tmp", part_number, Uuid::new_v4()));
        let chunk_size = self.stream_chunk_size;
        let src_version_id = src_version_id.map(str::to_string);

        let copy_res = run_blocking(|| -> StorageResult<(String, u64, DateTime<Utc>)> {
            let _guard = self.get_object_lock(src_bucket, src_key).read();

            let copy_hint = range.map(|(s, e)| crate::traits::RangeHint {
                start: Some(s),
                end: Some(e),
            });
            let (obj, content) = match src_version_id.as_deref() {
                Some(version_id) => self.open_version_for_read_locked_sync(
                    src_bucket, src_key, version_id, copy_hint,
                )?,
                None => self.open_object_for_read_locked_sync(src_bucket, src_key, copy_hint)?,
            };
            let src_size = obj.size;
            let last_modified = obj.last_modified;

            let (start, end) = match range {
                Some((s, e)) => {
                    if s >= src_size || e >= src_size || s > e {
                        return Err(StorageError::InvalidRange);
                    }
                    (s, e)
                }
                None => {
                    if src_size == 0 {
                        (0u64, 0u64)
                    } else {
                        (0u64, src_size - 1)
                    }
                }
            };
            let length = if src_size == 0 { 0 } else { end - start + 1 };

            use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
            let mut src: Box<dyn Read> = match content {
                OpenedObjectContent::Single(mut file) => {
                    if start > 0 {
                        file.seek(SeekFrom::Start(start))
                            .map_err(StorageError::Io)?;
                    }
                    Box::new(std::io::BufReader::with_capacity(chunk_size, file))
                }
                OpenedObjectContent::Segmented {
                    source,
                    base_offset,
                    ..
                } => {
                    let rel_start = start.checked_sub(base_offset).ok_or_else(|| {
                        StorageError::Internal(
                            "copy range precedes the opened segment window".to_string(),
                        )
                    })?;
                    Box::new(
                        crate::segments::LazyOpenSegmentsRead::with_window(
                            source, rel_start, length,
                        )
                        .map_err(StorageError::Io)?,
                    )
                }
            };
            let dst = std::fs::File::create(&tmp_file).map_err(StorageError::Io)?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "mpu:part-write").map_err(StorageError::Io)?;
            let mut dst = BufWriter::with_capacity(chunk_size * 4, dst);
            let mut hasher = Md5::new();
            let mut remaining = length;
            let mut buf = vec![0u8; chunk_size];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining as usize, buf.len());
                let n = src.read(&mut buf[..to_read]).map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                dst.write_all(&buf[..n]).map_err(StorageError::Io)?;
                remaining -= n as u64;
            }
            if remaining > 0 {
                return Err(StorageError::Internal(
                    "source object ended before the requested copy range was fully read"
                        .to_string(),
                ));
            }
            let dst = dst
                .into_inner()
                .map_err(|e| StorageError::Io(e.into_error()))?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "mpu:part-sync").map_err(StorageError::Io)?;
            dst.sync_all().map_err(StorageError::Io)?;
            Ok((format!("{:x}", hasher.finalize()), length, last_modified))
        });

        let (etag, length, last_modified) = match copy_res {
            Ok(v) => v,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp_file).await;
                return Err(e);
            }
        };

        run_blocking(|| -> StorageResult<()> {
            let lock_path = upload_dir.join(".manifest.lock");
            let lock = self.get_meta_index_lock(&lock_path.to_string_lossy());
            let _guard = lock.lock();
            #[cfg(any(test, feature = "failpoints"))]
            if let Err(error) = crate::failpoints::hit(&self.root, "mpu:part-publish") {
                let _ = std::fs::remove_file(&tmp_file);
                return Err(StorageError::Io(error));
            }
            let displaced_record = Self::read_part_record_sync(&upload_dir, part_number);
            if let Err(error) = Self::retract_part_record_sync(&self.root, &upload_dir, part_number)
            {
                let _ = std::fs::remove_file(&tmp_file);
                Self::restore_displaced_part_record(&upload_dir, part_number, displaced_record);
                return Err(StorageError::Io(error));
            }
            if let Err(error) = std::fs::rename(&tmp_file, &part_file) {
                let _ = std::fs::remove_file(&tmp_file);
                Self::restore_displaced_part_record(&upload_dir, part_number, displaced_record);
                return Err(StorageError::Io(error));
            }
            self.publish_part_record_sync(&upload_dir, part_number, &etag, length)
                .map_err(StorageError::Io)
        })?;

        Ok((etag, last_modified))
    }

    async fn complete_multipart_checked(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[PartInfo],
        options: crate::traits::PutCommitOptions,
    ) -> StorageResult<ObjectMeta> {
        let (upload_dir, manifest, tmp_dir) = run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            let manifest_path = upload_dir.join(MANIFEST_FILE);
            if !manifest_path.exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }

            let manifest = MultipartManifest::read_sync(&manifest_path)?;
            if metadata_has_pending_sse(&manifest.metadata) {
                return Err(StorageError::InvalidArgument(
                    "pending-SSE multipart uploads require transformed completion".to_string(),
                ));
            }

            let tmp_dir = self.tmp_dir();
            std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
            Ok((upload_dir, manifest, tmp_dir))
        })?;

        let object_key = manifest.object_key.clone();
        let metadata: HashMap<String, String> = manifest.metadata.clone();
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let chunk_size = self.stream_chunk_size;
        let part_infos: Vec<PartInfo> = parts.to_vec();
        let upload_dir_owned = upload_dir.clone();
        let tmp_path_owned = tmp_path.clone();
        let manifest_parts = manifest.parts.clone();

        let segments_allowed = self.multipart_layout == MultipartLayout::Segments
            && part_infos.len() >= 2
            && !metadata.contains_key(MULTIPART_PENDING_SSE_ALG)
            && !metadata.contains_key(MULTIPART_PENDING_SSE_KMS_KEY)
            && !metadata.contains_key(MULTIPART_PENDING_SSE_C_KEY)
            && !metadata.contains_key(MPU_SSE_C_MARKER);
        let segment_dir = self.segments_bucket_root(bucket).join(upload_id);
        let segment_dir_after = segment_dir.clone();
        let segment_id = upload_id.to_string();
        let upload_lock =
            self.get_meta_index_lock(&upload_dir.join(".manifest.lock").to_string_lossy());
        #[cfg(any(test, feature = "failpoints"))]
        let fp_root = self.root.clone();

        let assemble_res = tokio::task::spawn_blocking(
            move || -> StorageResult<(String, u64, Vec<u64>, Option<String>)> {
                use std::io::Read;
                let mut md5_digest_concat = Vec::with_capacity(part_infos.len() * 16);
                let mut total_size: u64 = 0;
                let mut part_sizes: Vec<u64> = Vec::with_capacity(part_infos.len());

                for (ordinal, part_info) in part_infos.iter().enumerate() {
                    let part_file =
                        upload_dir_owned.join(format!("part-{:05}.part", part_info.part_number));
                    let seg_file =
                        segment_dir.join(crate::segments::SegmentSet::seg_file_name(ordinal));
                    let source_file = if part_file.exists() {
                        part_file
                    } else if segments_allowed && seg_file.is_file() {
                        seg_file
                    } else {
                        return Err(StorageError::InvalidObjectKey(format!(
                            "Part {} not found",
                            part_info.part_number
                        )));
                    };
                    let file_size = std::fs::metadata(&source_file)
                        .map_err(StorageError::Io)?
                        .len();
                    let proven_digest = manifest_parts
                        .get(&part_info.part_number)
                        .filter(|record| {
                            FsStorageBackend::part_record_describes_file(
                                record,
                                &source_file,
                                file_size,
                            )
                        })
                        .and_then(|record| parse_md5_hex(&record.etag));
                    match proven_digest {
                        Some(digest) => {
                            md5_digest_concat.extend_from_slice(&digest);
                        }
                        None => {
                            let reader =
                                std::fs::File::open(&source_file).map_err(StorageError::Io)?;
                            let mut reader = std::io::BufReader::with_capacity(chunk_size, reader);
                            let mut part_hasher = Md5::new();
                            let mut buf = vec![0u8; chunk_size];
                            loop {
                                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                                if n == 0 {
                                    break;
                                }
                                part_hasher.update(&buf[..n]);
                            }
                            md5_digest_concat.extend_from_slice(&part_hasher.finalize());
                        }
                    }
                    part_sizes.push(file_size);
                    total_size += file_size;
                }

                let mut composite_hasher = Md5::new();
                composite_hasher.update(&md5_digest_concat);
                let etag = format!("{:x}-{}", composite_hasher.finalize(), part_infos.len());

                if part_infos.len() == 1 {
                    let part_file = upload_dir_owned
                        .join(format!("part-{:05}.part", part_infos[0].part_number));
                    #[cfg(any(test, feature = "failpoints"))]
                    crate::failpoints::hit(&fp_root, "mpu:assembly-move")
                        .map_err(StorageError::Io)?;
                    if std::fs::rename(&part_file, &tmp_path_owned).is_err() {
                        std::fs::copy(&part_file, &tmp_path_owned).map_err(StorageError::Io)?;
                    }
                    return Ok((etag, total_size, part_sizes, None));
                }

                if segments_allowed && total_size >= crate::segments::SEGMENT_MIN_TOTAL {
                    let _guard = upload_lock.lock();
                    std::fs::create_dir_all(&segment_dir).map_err(StorageError::Io)?;
                    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(part_infos.len());
                    let mut move_err: Option<std::io::Error> = None;
                    for (ordinal, part_info) in part_infos.iter().enumerate() {
                        let part_file = upload_dir_owned
                            .join(format!("part-{:05}.part", part_info.part_number));
                        let seg_file =
                            segment_dir.join(crate::segments::SegmentSet::seg_file_name(ordinal));
                        #[cfg(any(test, feature = "failpoints"))]
                        if let Err(error) = crate::failpoints::hit(&fp_root, "mpu:segment-move") {
                            move_err = Some(error);
                            break;
                        }
                        match std::fs::rename(&part_file, &seg_file) {
                            Ok(()) => moved.push((seg_file, part_file)),
                            Err(e) => {
                                if seg_file.is_file() && !part_file.exists() {
                                    continue;
                                }
                                move_err = Some(e);
                                break;
                            }
                        }
                    }
                    if let Some(e) = move_err {
                        for (seg_file, part_file) in moved.into_iter().rev() {
                            let _ = std::fs::rename(&seg_file, &part_file);
                        }
                        let _ = std::fs::remove_dir(&segment_dir);
                        return Err(StorageError::Io(e));
                    }

                    let header = crate::segments::StubHeader::new(
                        segment_id.clone(),
                        part_sizes.clone(),
                        etag.clone(),
                    );
                    #[cfg(any(test, feature = "failpoints"))]
                    let stub_result = crate::failpoints::hit(&fp_root, "mpu:segment-stub-write")
                        .and_then(|()| crate::segments::write_stub(&tmp_path_owned, &header));
                    #[cfg(not(any(test, feature = "failpoints")))]
                    let stub_result = crate::segments::write_stub(&tmp_path_owned, &header);
                    if let Err(e) = stub_result {
                        for (seg_file, part_file) in moved.into_iter().rev() {
                            let _ = std::fs::rename(&seg_file, &part_file);
                        }
                        let _ = std::fs::remove_dir(&segment_dir);
                        return Err(StorageError::Io(e));
                    }
                    let fsync_result = (|| -> std::io::Result<()> {
                        #[cfg(any(test, feature = "failpoints"))]
                        crate::failpoints::hit(&fp_root, "mpu:segment-dir-fsync")?;
                        Self::fsync_dir(&segment_dir)?;
                        if let Some(parent) = segment_dir.parent() {
                            Self::fsync_dir(parent)?;
                            if let Some(grandparent) = parent.parent() {
                                Self::fsync_dir(grandparent)?;
                            }
                        }
                        Ok(())
                    })();
                    if let Err(e) = fsync_result {
                        let _ = std::fs::remove_file(&tmp_path_owned);
                        for (seg_file, part_file) in moved.into_iter().rev() {
                            let _ = std::fs::rename(&seg_file, &part_file);
                        }
                        let _ = std::fs::remove_dir(&segment_dir);
                        return Err(StorageError::Io(e));
                    }
                    return Ok((etag, total_size, part_sizes, Some(segment_id)));
                }

                let mut out_file =
                    std::fs::File::create(&tmp_path_owned).map_err(StorageError::Io)?;
                for (ordinal, (part_info, expected)) in
                    part_infos.iter().zip(&part_sizes).enumerate()
                {
                    let part_file =
                        upload_dir_owned.join(format!("part-{:05}.part", part_info.part_number));
                    let seg_file =
                        segment_dir.join(crate::segments::SegmentSet::seg_file_name(ordinal));
                    let source_file = if part_file.exists() {
                        part_file
                    } else {
                        seg_file
                    };
                    let mut src = std::fs::File::open(&source_file).map_err(StorageError::Io)?;
                    #[cfg(any(test, feature = "failpoints"))]
                    crate::failpoints::hit(&fp_root, "mpu:during-assembly")
                        .map_err(StorageError::Io)?;
                    let copied =
                        std::io::copy(&mut src, &mut out_file).map_err(StorageError::Io)?;
                    if copied != *expected {
                        return Err(StorageError::Internal(format!(
                            "Part {} changed while completing the multipart upload",
                            part_info.part_number
                        )));
                    }
                }
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&fp_root, "mpu:assembly-sync").map_err(StorageError::Io)?;
                out_file.sync_all().map_err(StorageError::Io)?;
                Ok((etag, total_size, part_sizes, None))
            },
        )
        .await;

        let (etag, total_size, part_sizes, segmented_as) = match assemble_res {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(e);
            }
            Err(join) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(StorageError::Io(std::io::Error::other(join)));
            }
        };

        let mut metadata = metadata;
        metadata.insert(
            META_KEY_PART_SIZES.to_string(),
            encode_part_sizes(&part_sizes),
        );
        if let Some(ref seg_id) = segmented_as {
            metadata.insert(
                crate::segments::META_KEY_SEGMENTS.to_string(),
                seg_id.clone(),
            );
        }

        #[cfg(any(test, feature = "failpoints"))]
        run_blocking(|| -> StorageResult<()> {
            if let Err(err) = crate::failpoints::hit(&self.root, "mpu:before-finalize") {
                let _ = std::fs::remove_file(&tmp_path);
                if let Some(ref seg_id) = segmented_as {
                    let seg_dir = self.segments_bucket_root(bucket).join(seg_id);
                    for (ordinal, part_info) in parts.iter().enumerate() {
                        let seg_file =
                            seg_dir.join(crate::segments::SegmentSet::seg_file_name(ordinal));
                        let part_file =
                            upload_dir.join(format!("part-{:05}.part", part_info.part_number));
                        let _ = std::fs::rename(&seg_file, &part_file);
                    }
                    let _ = std::fs::remove_dir(&seg_dir);
                }
                return Err(StorageError::Io(err));
            }
            Ok(())
        })?;

        run_blocking(|| {
            let result = {
                let quota_lock = self.quota_lock_if_configured(bucket);
                let _quota_guard = quota_lock.as_ref().map(|lock| lock.lock());
                let _guard = self.get_object_lock(bucket, &object_key).write();
                self.finalize_put_sync(
                    bucket,
                    &object_key,
                    &tmp_path,
                    etag,
                    total_size,
                    Some(metadata),
                    &options,
                )
            };

            match result {
                Ok(obj) => {
                    let _ = std::fs::remove_dir_all(&upload_dir);
                    if segmented_as.is_none() {
                        let _ = std::fs::remove_dir_all(&segment_dir_after);
                    }
                    Ok(obj)
                }
                Err(e) => {
                    if parts.len() == 1 && tmp_path.exists() {
                        let part_file =
                            upload_dir.join(format!("part-{:05}.part", parts[0].part_number));
                        if std::fs::rename(&tmp_path, &part_file).is_err() {
                            let _ = std::fs::remove_file(&tmp_path);
                        }
                    } else {
                        let _ = std::fs::remove_file(&tmp_path);
                        if let Some(ref seg_id) = segmented_as {
                            let seg_dir = self.segments_bucket_root(bucket).join(seg_id);
                            for (ordinal, part_info) in parts.iter().enumerate() {
                                let seg_file = seg_dir
                                    .join(crate::segments::SegmentSet::seg_file_name(ordinal));
                                let part_file = upload_dir
                                    .join(format!("part-{:05}.part", part_info.part_number));
                                let _ = std::fs::rename(&seg_file, &part_file);
                            }
                            let _ = std::fs::remove_dir(&seg_dir);
                        }
                    }
                    Err(e)
                }
            }
        })
    }

    async fn abort_multipart(&self, bucket: &str, upload_id: &str) -> StorageResult<()> {
        run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            let upload_lock =
                self.get_meta_index_lock(&upload_dir.join(".manifest.lock").to_string_lossy());
            let _guard = upload_lock.lock();
            if upload_dir.exists() {
                std::fs::remove_dir_all(&upload_dir).map_err(StorageError::Io)?;
            }
            Ok(())
        })
    }

    async fn list_parts(&self, bucket: &str, upload_id: &str) -> StorageResult<Vec<PartMeta>> {
        run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            let manifest_path = upload_dir.join(MANIFEST_FILE);
            if !manifest_path.exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }

            let manifest = MultipartManifest::read_sync(&manifest_path)?;

            let parts = manifest
                .parts
                .into_iter()
                .map(|(part_number, info)| PartMeta {
                    part_number,
                    etag: info.etag,
                    size: info.size,
                    last_modified: None,
                })
                .collect();

            Ok(parts)
        })
    }

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> StorageResult<Vec<MultipartUploadInfo>> {
        run_blocking(|| {
            Self::guard_bucket_name(bucket)?;
            let uploads_root = self.multipart_bucket_root(bucket);
            if !uploads_root.exists() {
                return Ok(Vec::new());
            }

            let mut uploads = Vec::new();
            let entries = std::fs::read_dir(&uploads_root).map_err(StorageError::Io)?;
            for entry in entries.flatten() {
                if !entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    continue;
                }
                let upload_id = entry.file_name().to_string_lossy().to_string();
                let manifest_path = entry.path().join(MANIFEST_FILE);
                if !manifest_path.exists() {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                    if let Ok(manifest) = serde_json::from_str::<Value>(&content) {
                        let key = manifest
                            .get("object_key")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let created = manifest
                            .get("created_at")
                            .and_then(|v| v.as_str())
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .map(|d| d.with_timezone(&Utc))
                            .unwrap_or_else(Utc::now);
                        uploads.push(MultipartUploadInfo {
                            upload_id,
                            key,
                            initiated: created,
                        });
                    }
                }
            }

            Ok(uploads)
        })
    }

    async fn get_multipart_metadata(
        &self,
        bucket: &str,
        upload_id: &str,
    ) -> StorageResult<HashMap<String, String>> {
        run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            let manifest_path = upload_dir.join(MANIFEST_FILE);
            if !manifest_path.exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }
            let manifest = MultipartManifest::read_sync(&manifest_path)?;
            Ok(manifest.metadata)
        })
    }

    async fn get_multipart_part_path(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
    ) -> StorageResult<PathBuf> {
        run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            let manifest_path = upload_dir.join(MANIFEST_FILE);
            if !manifest_path.exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }
            let part_file = upload_dir.join(format!("part-{:05}.part", part_number));
            if !part_file.is_file() {
                return Err(StorageError::InvalidObjectKey(format!(
                    "Part {} not found",
                    part_number
                )));
            }
            Ok(part_file)
        })
    }

    async fn get_bucket_config(&self, bucket: &str) -> StorageResult<BucketConfig> {
        run_blocking(|| {
            self.require_bucket(bucket)?;
            Ok(self.read_bucket_config_sync(bucket))
        })
    }

    async fn set_bucket_config(&self, bucket: &str, config: &BucketConfig) -> StorageResult<()> {
        run_blocking(|| {
            self.require_bucket(bucket)?;
            self.write_bucket_config_sync(bucket, config)
                .map_err(StorageError::Io)
        })
    }

    async fn is_versioning_enabled(&self, bucket: &str) -> StorageResult<bool> {
        run_blocking(|| {
            Self::guard_bucket_name(bucket)?;
            Ok(self.read_bucket_config_sync(bucket).versioning_enabled)
        })
    }

    async fn set_versioning(&self, bucket: &str, enabled: bool) -> StorageResult<()> {
        self.mutate_bucket_config(bucket, |config| {
            let new_status = if enabled {
                VersioningStatus::Enabled
            } else if config.versioning_enabled || config.versioning_suspended {
                VersioningStatus::Suspended
            } else {
                VersioningStatus::Disabled
            };
            config.set_versioning_status(new_status);
        })
        .await
        .map(|_| ())
    }

    async fn get_versioning_status(&self, bucket: &str) -> StorageResult<VersioningStatus> {
        run_blocking(|| {
            Self::guard_bucket_name(bucket)?;
            Ok(self.read_bucket_config_sync(bucket).versioning_status())
        })
    }

    async fn set_versioning_status(
        &self,
        bucket: &str,
        status: VersioningStatus,
    ) -> StorageResult<()> {
        self.mutate_bucket_config(bucket, |config| config.set_versioning_status(status))
            .await
            .map(|_| ())
    }

    async fn list_object_versions(
        &self,
        bucket: &str,
        key: &str,
    ) -> StorageResult<Vec<VersionInfo>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            self.validate_key(key)?;
            self.guard_versioned_key_casing(bucket, key)?;
            let version_dir = self.version_dir(bucket, key);

            let mut versions = Vec::new();
            let entries = match std::fs::read_dir(&version_dir) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(error) if Self::directory_may_be_vanishing(&error) => {
                    if version_dir.exists() {
                        return Err(StorageError::Io(error));
                    }
                    return Ok(Vec::new());
                }
                Err(error) => return Err(StorageError::Io(error)),
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.ends_with(".json") {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Ok(record) = serde_json::from_str::<Value>(&content) {
                        versions.push(self.version_info_from_record(key, &record));
                    }
                }
            }

            versions.sort_by(|a, b| b.last_modified.cmp(&a.last_modified));

            Ok(versions)
        })
    }

    async fn list_bucket_object_versions(
        &self,
        bucket: &str,
        prefix: Option<&str>,
    ) -> StorageResult<Vec<VersionInfo>> {
        run_blocking(|| {
            self.require_bucket(bucket)?;
            let root = self.bucket_versions_root(bucket);
            if !root.exists() {
                return Ok(Vec::new());
            }

            let mut versions = Vec::new();
            let mut stack = vec![root.clone()];
            while let Some(current) = stack.pop() {
                let entries = match std::fs::read_dir(&current) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if ft.is_dir() {
                        stack.push(path);
                        continue;
                    }
                    if !ft.is_file()
                        || path.extension().and_then(|ext| ext.to_str()) != Some("json")
                    {
                        continue;
                    }
                    let content = match std::fs::read_to_string(&path) {
                        Ok(content) => content,
                        Err(_) => continue,
                    };
                    let record = match serde_json::from_str::<Value>(&content) {
                        Ok(record) => record,
                        Err(_) => continue,
                    };
                    let fallback_key = path
                        .parent()
                        .and_then(|parent| parent.strip_prefix(&root).ok())
                        .map(|rel| {
                            let s = rel.to_string_lossy().into_owned();
                            #[cfg(windows)]
                            let s = s.replace('\\', "/");
                            fs_decode_key(&s)
                        })
                        .unwrap_or_default();
                    let info = self.version_info_from_record(&fallback_key, &record);
                    if prefix.is_some_and(|value| !info.key.starts_with(value)) {
                        continue;
                    }
                    versions.push(info);
                }
            }

            versions.sort_by(|a, b| {
                a.key
                    .cmp(&b.key)
                    .then_with(|| b.last_modified.cmp(&a.last_modified))
            });
            Ok(versions)
        })
    }

    async fn get_object_tags(&self, bucket: &str, key: &str) -> StorageResult<Vec<Tag>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            self.require_bucket(bucket)?;
            let obj_path = self.object_path(bucket, key)?;
            if !obj_path.exists() {
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }
            let entry = self.read_index_entry_sync(bucket, key);
            if let Some(entry) = entry {
                if let Some(tags_val) = entry.get("tags") {
                    if let Ok(tags) = serde_json::from_value::<Vec<Tag>>(tags_val.clone()) {
                        return Ok(tags);
                    }
                }
            }
            Ok(Vec::new())
        })
    }

    async fn set_object_tags(&self, bucket: &str, key: &str, tags: &[Tag]) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.require_bucket(bucket)?;
            let obj_path = self.object_path(bucket, key)?;
            if !obj_path.exists() {
                return Err(StorageError::ObjectNotFound {
                    bucket: bucket.to_string(),
                    key: key.to_string(),
                });
            }
            let mut entry = self.read_index_entry_sync(bucket, key).unwrap_or_default();
            if tags.is_empty() {
                entry.remove("tags");
            } else {
                entry.insert(
                    "tags".to_string(),
                    serde_json::to_value(tags).unwrap_or(Value::Null),
                );
            }
            self.write_index_entry_sync(bucket, key, &entry)
                .map_err(StorageError::Io)?;
            self.invalidate_bucket_caches(bucket);
            Ok(())
        })
    }

    async fn delete_object_tags(&self, bucket: &str, key: &str) -> StorageResult<()> {
        self.set_object_tags(bucket, key, &[]).await
    }

    async fn get_object_version_tags(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<Vec<Tag>> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).read();
            let (record, _data_path) = self.read_version_record_sync(bucket, key, version_id)?;
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                return Err(StorageError::MethodNotAllowed(
                    "The specified method is not allowed against a delete marker".to_string(),
                ));
            }
            let tags = record
                .get("tags")
                .and_then(|v| serde_json::from_value::<Vec<Tag>>(v.clone()).ok())
                .unwrap_or_default();
            Ok(tags)
        })
    }
}
