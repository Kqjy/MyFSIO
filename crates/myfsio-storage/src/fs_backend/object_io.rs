use super::*;

impl FsStorageBackend {
    pub(super) fn open_object_for_read_sync(
        &self,
        bucket: &str,
        key: &str,
        window: Option<crate::traits::RangeHint>,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
        let _guard = self.get_object_lock(bucket, key).read();
        self.open_object_for_read_locked_sync(bucket, key, window)
    }

    pub(super) fn open_object_for_read_locked_sync(
        &self,
        bucket: &str,
        key: &str,
        window: Option<crate::traits::RangeHint>,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
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

        let file = std::fs::File::open(&path).map_err(StorageError::Io)?;
        let meta = file.metadata().map_err(StorageError::Io)?;
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
        if metadata_has_pending_sse(&stored_meta) {
            return Err(StorageError::ObjectCorrupted {
                bucket: bucket.to_string(),
                key: key.to_string(),
                detail: "server-side encryption was requested for this multipart upload but \
                         never finalized; the stored bytes cannot be served safely because \
                         their encryption state is unknown"
                    .to_string(),
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
        let resolved = window.and_then(|hint| hint.resolve(obj.size));
        let content =
            self.open_content_for_read_sync(bucket, key, file, &obj.internal_metadata, resolved)?;
        Ok((obj, content))
    }

    pub(super) fn open_version_for_read_sync(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        window: Option<crate::traits::RangeHint>,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
        let _guard = self.get_object_lock(bucket, key).read();
        self.open_version_for_read_locked_sync(bucket, key, version_id, window)
    }

    pub(super) fn open_version_for_read_locked_sync(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        window: Option<crate::traits::RangeHint>,
    ) -> StorageResult<(ObjectMeta, OpenedObjectContent)> {
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
        let file = std::fs::File::open(&data_path).map_err(StorageError::Io)?;
        let obj = self.object_meta_from_version_record(key, &record, &data_path)?;
        let record_meta = Self::version_metadata_from_record(&record);
        let resolved = window.and_then(|hint| hint.resolve(obj.size));
        let content = self.open_content_for_read_sync(bucket, key, file, &record_meta, resolved)?;
        Ok((obj, content))
    }

    pub(super) fn open_content_for_read_sync(
        &self,
        bucket: &str,
        key: &str,
        mut file: std::fs::File,
        stored_meta: &HashMap<String, String>,
        window: Option<(u64, u64)>,
    ) -> StorageResult<OpenedObjectContent> {
        let Some(seg_id) = stored_meta.get(crate::segments::META_KEY_SEGMENTS) else {
            return Ok(OpenedObjectContent::Single(file));
        };
        let corrupted = |detail: String| StorageError::ObjectCorrupted {
            bucket: bucket.to_string(),
            key: key.to_string(),
            detail,
        };
        if !validation::is_valid_multipart_id(seg_id) {
            return Err(corrupted(format!(
                "object references a segment set with a non-canonical id: {}",
                seg_id
            )));
        }
        let header = crate::segments::read_stub_header_from(&mut file)
            .map_err(StorageError::Io)?
            .ok_or_else(|| {
                corrupted("segmented object data file is missing its stub header".to_string())
            })?;
        if &header.segment_id != seg_id {
            return Err(corrupted(format!(
                "stub references segment set {} but metadata says {}",
                header.segment_id, seg_id
            )));
        }
        let meta_sizes = stored_meta
            .get(META_KEY_PART_SIZES)
            .and_then(|raw| parse_part_sizes(raw));
        if let Some(ref sizes) = meta_sizes {
            if *sizes != header.sizes {
                return Err(corrupted(
                    "part size manifest does not match the segment stub".to_string(),
                ));
            }
        }
        let set = self.segment_set_for(bucket, seg_id, header.sizes.clone());

        let ordinal_window = window
            .filter(|(start, _)| *start < header.total)
            .map(|(start, len)| {
                let len = len.min(header.total - start);
                let mut first = 0usize;
                let mut last = set.sizes.len().saturating_sub(1);
                let mut offset = 0u64;
                let mut base_offset = 0u64;
                let end_exclusive = start + len;
                for (i, size) in set.sizes.iter().copied().enumerate() {
                    let seg_end = offset + size;
                    if start >= seg_end {
                        first = i + 1;
                        base_offset = seg_end;
                    }
                    if offset < end_exclusive {
                        last = i;
                    }
                    offset = seg_end;
                }
                (first, last, base_offset)
            })
            .filter(|(first, last, _)| *first <= *last && *last < set.sizes.len());

        let (first, last, base_offset) = match ordinal_window {
            Some(w) => w,
            None => (0, set.sizes.len().saturating_sub(1), 0),
        };

        let mut paths = Vec::with_capacity(last.saturating_sub(first) + 1);
        if !set.sizes.is_empty() {
            for i in first..=last {
                let size = set.sizes[i];
                let seg_path = set.seg_path(i);
                paths.push((seg_path, size));
            }
        }
        let source = crate::segments::LazySegmentSource::open_first(
            crate::segments::SegmentPaths::new(paths),
        )
        .map_err(|error| corrupted(error.to_string()))?;
        Ok(OpenedObjectContent::Segmented {
            source,
            total: header.total,
            base_offset,
        })
    }

    pub(super) fn snapshot_segmented_content_sync(
        &self,
        stub_path: &Path,
        link_path: &Path,
        source: crate::segments::LazySegmentSource,
        total: u64,
        base_offset: u64,
    ) -> StorageResult<crate::traits::SnapshotSource> {
        let _ = std::fs::remove_file(link_path);
        let _ = std::fs::remove_dir_all(link_path);
        let link_result = (|| -> std::io::Result<Vec<(PathBuf, u64)>> {
            std::fs::create_dir_all(link_path)?;
            std::fs::hard_link(stub_path, link_path.join("stub"))?;
            let segment_dir = link_path.join("segments");
            std::fs::create_dir(&segment_dir)?;
            let mut linked = Vec::with_capacity(source.paths().entries().len());
            for (ordinal, (path, size)) in source.paths().entries().iter().enumerate() {
                let target = segment_dir.join(crate::segments::SegmentSet::seg_file_name(ordinal));
                std::fs::hard_link(path, &target)?;
                linked.push((target, *size));
            }
            Ok(linked)
        })();
        match link_result {
            Ok(linked) => {
                let (_, eager) = source.into_parts();
                let paths =
                    crate::segments::SegmentPaths::with_cleanup(linked, link_path.to_path_buf());
                Ok(crate::traits::SnapshotSource::Segments {
                    source: crate::segments::LazySegmentSource::from_parts(paths, eager),
                    total,
                    base_offset,
                })
            }
            Err(error) => {
                let _ = std::fs::remove_dir_all(link_path);
                tracing::warn!(
                    path = %link_path.display(),
                    error = %error,
                    "hard-linking a segmented snapshot failed; retaining eager handles"
                );
                let files = source.into_eager_files().map_err(StorageError::Io)?;
                Ok(crate::traits::SnapshotSource::EagerSegments {
                    files,
                    total,
                    base_offset,
                })
            }
        }
    }

    pub(super) fn release_segment_dir(&self, bucket: &str, segment_id: &str) {
        if !validation::is_safe_path_segment(bucket) {
            tracing::warn!(
                bucket = bucket,
                "refusing to release a segment directory for a non-canonical bucket name"
            );
            return;
        }
        if !validation::is_valid_multipart_id(segment_id) {
            if !segment_id.is_empty() {
                tracing::warn!(
                    bucket = bucket,
                    segment_id = segment_id,
                    "refusing to release a segment directory with a non-canonical id"
                );
            }
            return;
        }
        let seg_dir = self.segments_bucket_root(bucket).join(segment_id);
        if let Err(e) = std::fs::remove_dir_all(&seg_dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    bucket = bucket,
                    segment_id = segment_id,
                    error = %e,
                    "failed to remove segment directory; GC will sweep it"
                );
            }
        }
    }

    pub async fn put_object_with_etag_override(
        &self,
        bucket: &str,
        key: &str,
        stream: crate::traits::AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
        etag_override: Option<String>,
    ) -> StorageResult<ObjectMeta> {
        self.put_object_with_commit(
            bucket,
            key,
            stream,
            metadata,
            crate::traits::PutCommitOptions {
                etag_override,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn put_object_with_commit(
        &self,
        bucket: &str,
        key: &str,
        stream: crate::traits::AsyncReadStream,
        metadata: Option<HashMap<String, String>>,
        options: crate::traits::PutCommitOptions,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(key)?;

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let tmp_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));

        let chunk_size = self.stream_chunk_size;
        let drain_tmp = tmp_path.clone();
        #[cfg(any(test, feature = "failpoints"))]
        let fp_root = self.root.clone();

        let drain_result = tokio::task::spawn_blocking(move || -> StorageResult<(String, u64)> {
            use std::io::{BufWriter, Read, Write};
            let mut reader = tokio_util::io::SyncIoBridge::new(stream);
            let file = std::fs::File::create(&drain_tmp).map_err(StorageError::Io)?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&fp_root, "put:stage-data-write").map_err(StorageError::Io)?;
            let mut writer = BufWriter::with_capacity(chunk_size * 4, file);
            let mut hasher = Md5::new();
            let mut total: u64 = 0;
            let mut buf = vec![0u8; chunk_size];
            loop {
                let n = reader.read(&mut buf).map_err(StorageError::Io)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                writer.write_all(&buf[..n]).map_err(StorageError::Io)?;
                total += n as u64;
            }
            let file = writer
                .into_inner()
                .map_err(|e| StorageError::Io(e.into_error()))?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&fp_root, "put:stage-data-sync").map_err(StorageError::Io)?;
            file.sync_all().map_err(StorageError::Io)?;
            Ok((format!("{:x}", hasher.finalize()), total))
        })
        .await;

        let (etag, total_size) = match drain_result {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(e);
            }
            Err(join_err) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(StorageError::Io(std::io::Error::other(join_err)));
            }
        };

        let result = run_blocking(|| {
            let quota_lock = self.quota_lock_if_configured(bucket);
            let _quota_guard = quota_lock.as_ref().map(|lock| lock.lock());
            let _guard = self.get_object_lock(bucket, key).write();
            self.finalize_put_sync(bucket, key, &tmp_path, etag, total_size, metadata, &options)
        });

        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp_path).await;
        }
        result
    }

    pub fn allocate_prepared_tmp_path(&self) -> StorageResult<PathBuf> {
        let tmp_dir = self.tmp_dir();
        std::fs::create_dir_all(&tmp_dir).map_err(StorageError::Io)?;
        Ok(tmp_dir.join(format!("{}.tmp", Uuid::new_v4())))
    }

    pub async fn put_object_prepared(
        &self,
        bucket: &str,
        key: &str,
        prepared_tmp: &Path,
        stored_size: u64,
        etag: String,
        metadata: Option<HashMap<String, String>>,
        options: crate::traits::PutCommitOptions,
    ) -> StorageResult<ObjectMeta> {
        self.validate_key(key)?;
        if prepared_tmp.parent() != Some(self.tmp_dir().as_path()) {
            let _ = tokio::fs::remove_file(prepared_tmp).await;
            return Err(StorageError::Internal(
                "prepared upload must live in the storage tmp directory".to_string(),
            ));
        }
        let result = run_blocking(|| {
            let quota_lock = self.quota_lock_if_configured(bucket);
            let _quota_guard = quota_lock.as_ref().map(|lock| lock.lock());
            let _guard = self.get_object_lock(bucket, key).write();
            self.finalize_put_sync(
                bucket,
                key,
                prepared_tmp,
                etag,
                stored_size,
                metadata,
                &options,
            )
        });
        if result.is_err() {
            let _ = tokio::fs::remove_file(prepared_tmp).await;
        }
        result
    }

    pub(super) fn finalize_put_sync(
        &self,
        bucket_name: &str,
        key: &str,
        tmp_path: &Path,
        etag: String,
        new_size: u64,
        metadata: Option<HashMap<String, String>>,
        options: &crate::traits::PutCommitOptions,
    ) -> StorageResult<ObjectMeta> {
        let etag = options.etag_override.clone().unwrap_or(etag);
        self.require_bucket(bucket_name)?;
        let bucket_root = self.bucket_path(bucket_name);
        if !self.verify_disk_casing(&self.object_live_path(bucket_name, key))? {
            return Err(StorageError::InvalidObjectKey(format!(
                "Object key '{}' collides with existing content whose path differs only by \
                 letter case; the storage filesystem is case-insensitive and cannot hold both",
                key
            )));
        }
        let destination = self.object_live_path(bucket_name, key);
        let _publish_guard = destination
            .parent()
            .map(|parent| self.directory_publish_guard(parent));
        self.ensure_writable_parents_sync(&bucket_root, key)
            .map_err(StorageError::Io)?;
        if let Some(parent) = destination.parent() {
            Self::create_publish_dir_sync(parent).map_err(StorageError::Io)?;
        }

        let is_overwrite = destination.exists();
        let existing_size = if is_overwrite {
            std::fs::metadata(&destination)
                .map(|m| m.len())
                .unwrap_or(0)
        } else {
            0
        };
        let existing_meta = if is_overwrite {
            if self
                .read_index_entry_sync(bucket_name, key)
                .as_ref()
                .is_some_and(Self::entry_marks_unreadable_metadata)
            {
                return Err(StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "refusing to overwrite {}/{}: the existing metadata record is unreadable; repair or delete the object first",
                        bucket_name, key
                    ),
                )));
            }
            self.read_metadata_sync(bucket_name, key)
        } else {
            HashMap::new()
        };

        if !options.conditions.is_empty() {
            Self::evaluate_put_conditions_sync(
                &options.conditions,
                is_overwrite.then_some(&existing_meta),
            )?;
        }

        let bucket_config = self.read_bucket_config_sync(bucket_name);
        if bucket_config.unreadable {
            return Err(StorageError::Internal(format!(
                "Bucket configuration for '{}' is unreadable or corrupt; refusing to write, \
                 because versioning and quota settings cannot be determined",
                bucket_name
            )));
        }
        let versioning_status = bucket_config.versioning_status();

        if is_overwrite {
            let destructive_overwrite = match versioning_status {
                VersioningStatus::Enabled => false,
                VersioningStatus::Suspended => {
                    let vid = existing_meta
                        .get("__version_id__")
                        .map(String::as_str)
                        .unwrap_or("");
                    vid.is_empty() || vid == "null"
                }
                VersioningStatus::Disabled => true,
            };
            if destructive_overwrite {
                myfsio_common::object_lock::can_delete_object(
                    &existing_meta,
                    options.bypass_governance,
                )
                .map_err(StorageError::ObjectLocked)?;
            }
        }
        if matches!(versioning_status, VersioningStatus::Suspended) {
            if let Ok((record, _)) = self.read_version_record_sync(bucket_name, key, "null") {
                let is_delete_marker = record
                    .get("is_delete_marker")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !is_delete_marker {
                    let null_meta = Self::version_metadata_from_record(&record);
                    myfsio_common::object_lock::can_delete_object(
                        &null_meta,
                        options.bypass_governance,
                    )
                    .map_err(StorageError::ObjectLocked)?;
                }
            }
        }

        if let Some(quota) = bucket_config.quota.as_ref() {
            let stats = self.bucket_stats_for_quota_sync(bucket_name)?;
            let existing_version_id = existing_meta
                .get("__version_id__")
                .map(String::as_str)
                .unwrap_or("");
            let current_is_retained = is_overwrite
                && match versioning_status {
                    VersioningStatus::Enabled => true,
                    VersioningStatus::Suspended => {
                        !existing_version_id.is_empty() && existing_version_id != "null"
                    }
                    VersioningStatus::Disabled => false,
                };
            let removed_current_bytes = if is_overwrite && !current_is_retained {
                existing_size
            } else {
                0
            };
            let removed_current_objects = u64::from(is_overwrite && !current_is_retained);
            let (removed_null_bytes, removed_null_objects) =
                if matches!(versioning_status, VersioningStatus::Suspended) {
                    let (_, null_data_path) = self.version_record_paths(bucket_name, key, "null");
                    if null_data_path.is_file() {
                        (
                            std::fs::metadata(null_data_path)
                                .map(|metadata| metadata.len())
                                .unwrap_or(0),
                            1,
                        )
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                };
            let projected_bytes = stats
                .total_bytes()
                .saturating_sub(removed_current_bytes.saturating_add(removed_null_bytes))
                .saturating_add(new_size);
            let projected_objects = stats
                .total_objects()
                .saturating_sub(removed_current_objects.saturating_add(removed_null_objects))
                .saturating_add(1);
            let added_bytes = projected_bytes.saturating_sub(stats.total_bytes());
            let added_objects = projected_objects.saturating_sub(stats.total_objects());
            if let Some(max_bytes) = quota.max_bytes {
                if projected_bytes > max_bytes {
                    return Err(StorageError::QuotaExceeded(format!(
                        "Quota exceeded: adding {} bytes would result in {} bytes, exceeding limit of {} bytes",
                        added_bytes, projected_bytes, max_bytes
                    )));
                }
            }
            if let Some(max_objects) = quota.max_objects {
                if projected_objects > max_objects {
                    return Err(StorageError::QuotaExceeded(format!(
                        "Quota exceeded: adding {} objects would result in {} objects, exceeding limit of {} objects",
                        added_objects, projected_objects, max_objects
                    )));
                }
            }
        }

        let lock_dir = self.system_bucket_root(bucket_name).join("locks");
        std::fs::create_dir_all(&lock_dir).map_err(StorageError::Io)?;

        let mut release_old_segments: Option<String> = None;
        let mut version_mutations = Vec::new();
        let mut archived_version_id: Option<String> = None;
        if is_overwrite {
            let old_segments = existing_meta
                .get(crate::segments::META_KEY_SEGMENTS)
                .cloned();
            match versioning_status {
                VersioningStatus::Enabled => {
                    if let Some(mutation) = self
                        .archive_current_version_sync(bucket_name, key, "overwrite")
                        .map_err(StorageError::Io)?
                    {
                        archived_version_id = Some(mutation.version_id.clone());
                        version_mutations.push(mutation);
                    }
                }
                VersioningStatus::Suspended => {
                    let existing_vid = existing_meta
                        .get("__version_id__")
                        .map(String::as_str)
                        .unwrap_or("");
                    if !existing_vid.is_empty() && existing_vid != "null" {
                        if let Some(mutation) = self
                            .archive_current_version_sync(bucket_name, key, "overwrite")
                            .map_err(StorageError::Io)?
                        {
                            archived_version_id = Some(mutation.version_id.clone());
                            version_mutations.push(mutation);
                        }
                    } else {
                        release_old_segments = old_segments;
                    }
                }
                VersioningStatus::Disabled => {
                    release_old_segments = old_segments;
                }
            }
        }

        let abort_commit = |e: std::io::Error| {
            self.rollback_failed_commit_sync(
                bucket_name,
                key,
                &existing_meta,
                archived_version_id.as_deref(),
            );
            StorageError::Io(e)
        };

        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "put:after-archive").map_err(abort_commit)?;

        let file_meta = std::fs::metadata(tmp_path).map_err(abort_commit)?;
        let mtime_duration = file_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
        let mtime = mtime_duration.map(|d| d.as_secs_f64()).unwrap_or(0.0);
        let mtime_ns = mtime_duration.map(|d| d.as_nanos());

        let new_version_id = match versioning_status {
            VersioningStatus::Enabled => Some(Self::new_version_id_sync()),
            VersioningStatus::Suspended => Some("null".to_string()),
            VersioningStatus::Disabled => None,
        };

        let mut internal_meta = HashMap::new();
        if let Some(ref user_meta) = metadata {
            for (k, v) in user_meta {
                if STORAGE_MANAGED_METADATA_KEYS.contains(&k.as_str()) {
                    continue;
                }
                internal_meta.insert(k.clone(), v.clone());
            }
        }
        internal_meta.insert("__etag__".to_string(), etag.clone());
        internal_meta.insert("__size__".to_string(), new_size.to_string());
        internal_meta.insert("__last_modified__".to_string(), mtime.to_string());
        if let Some(ns) = mtime_ns {
            internal_meta.insert(META_KEY_COMMIT_MTIME_NS.to_string(), ns.to_string());
        }
        if let Some(ref vid) = new_version_id {
            internal_meta.insert("__version_id__".to_string(), vid.clone());
        }

        match self.metadata_layout {
            MetadataLayout::Sidecar => {
                let staged = self
                    .stage_live_metadata_sync(
                        bucket_name,
                        key,
                        &internal_meta,
                        options.tags.as_deref(),
                    )
                    .map_err(abort_commit)?;
                #[cfg(any(test, feature = "failpoints"))]
                if let Err(err) = crate::failpoints::hit(&self.root, "put:before-data-rename") {
                    let _ = std::fs::remove_file(&staged);
                    return Err(abort_commit(err));
                }
                if let Err(err) = self.publish_by_rename_sync(tmp_path, &destination) {
                    let _ = std::fs::remove_file(&staged);
                    return Err(abort_commit(err));
                }
                if let Some(parent) = destination.parent() {
                    if let Err(err) = Self::fsync_dir(parent) {
                        if self
                            .publish_staged_metadata_sync(bucket_name, key, &staged)
                            .is_err()
                        {
                            self.handle_torn_runtime_commit(
                                bucket_name,
                                key,
                                &staged,
                                "the data directory fsync and the sidecar publish both failed",
                            );
                        }
                        return Err(StorageError::Io(err));
                    }
                }
                #[cfg(any(test, feature = "failpoints"))]
                if let Err(err) = crate::failpoints::hit(&self.root, "put:before-publish-sidecar") {
                    self.handle_torn_runtime_commit(
                        bucket_name,
                        key,
                        &staged,
                        "an injected publish failure",
                    );
                    return Err(StorageError::Io(err));
                }
                if let Err(err) = self.publish_staged_metadata_sync(bucket_name, key, &staged) {
                    self.handle_torn_runtime_commit(bucket_name, key, &staged, &err.to_string());
                    return Err(StorageError::Io(err));
                }
            }
            MetadataLayout::Index => {
                let mut entry = HashMap::new();
                entry.insert(
                    "metadata".to_string(),
                    serde_json::to_value(&internal_meta)
                        .map_err(std::io::Error::other)
                        .map_err(abort_commit)?,
                );
                if let Some(tags) = options.tags.as_deref() {
                    if !tags.is_empty() {
                        entry.insert(
                            "tags".to_string(),
                            serde_json::to_value(tags)
                                .map_err(std::io::Error::other)
                                .map_err(abort_commit)?,
                        );
                    }
                }
                self.write_index_entry_sync(bucket_name, key, &entry)
                    .map_err(abort_commit)?;
                self.publish_by_rename_sync(tmp_path, &destination)
                    .map_err(abort_commit)?;
                if let Some(parent) = destination.parent() {
                    Self::fsync_dir(parent).map_err(StorageError::Io)?;
                }
            }
        }

        if matches!(versioning_status, VersioningStatus::Suspended) {
            if let Some(mutation) = self
                .purge_archived_null_version_sync(bucket_name, key)
                .map_err(StorageError::Io)?
            {
                version_mutations.push(mutation);
            }
        }

        if let Some(seg_id) = release_old_segments {
            self.release_segment_dir(bucket_name, &seg_id);
        }

        self.invalidate_bucket_caches(bucket_name);

        if versioning_status.is_active() {
            self.clear_delete_marker_sync(bucket_name, key);
        }
        self.update_listing_index_after_commit_with_versions(bucket_name, key, &version_mutations);

        let lm = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);

        let mut obj = ObjectMeta::new(key.to_string(), new_size, lm);
        obj.etag = Some(etag);
        obj.metadata = metadata.unwrap_or_default();
        obj.version_id = new_version_id;
        obj.internal_metadata = internal_meta;
        Ok(obj)
    }
}
