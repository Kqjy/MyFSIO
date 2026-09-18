use super::*;

impl FsStorageBackend {
    pub(super) fn invalidate_bucket_caches(&self, bucket_name: &str) {
        self.stats_cache.remove(bucket_name);
        self.list_cache.remove(bucket_name);
        self.shallow_cache.retain(|(b, _, _), _| b != bucket_name);
    }

    pub(super) fn get_list_rebuild_lock(&self, bucket_name: &str) -> Arc<Mutex<()>> {
        self.list_rebuild_locks
            .entry(bucket_name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub(super) fn build_full_listing_entries_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<Vec<ListCacheEntry>> {
        #[cfg(test)]
        self.listing_full_builds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bucket_path = self.require_bucket(bucket_name)?;

        let mut all_keys: Vec<ListCacheEntry> = Vec::new();
        let mut dir_idx_cache: HashMap<
            PathBuf,
            HashMap<String, (Option<String>, Option<String>, Option<String>)>,
        > = HashMap::new();
        let internal = INTERNAL_FOLDERS;
        let bucket_str = bucket_path.to_string_lossy().to_string();
        let bucket_prefix_len = bucket_str.len() + 1;
        let mut stack = vec![bucket_str.clone()];

        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(&current) {
                Ok(e) => e,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if current == bucket_str && internal.contains(&name_str.as_ref()) {
                    continue;
                }
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if ft.is_dir() {
                    stack.push(entry.path().to_string_lossy().to_string());
                } else if ft.is_file() {
                    let full_path = entry.path().to_string_lossy().to_string();
                    let mut fs_rel = full_path[bucket_prefix_len..].to_string();
                    #[cfg(windows)]
                    {
                        fs_rel = fs_rel.replace('\\', "/");
                    }
                    let is_dir_marker = name_str.as_ref() == DIR_MARKER_FILE;
                    let is_keydata_marker = name_str.as_ref() == KEY_DATA_MARKER_FILE;
                    if is_dir_marker {
                        fs_rel = fs_rel
                            .strip_suffix(DIR_MARKER_FILE)
                            .unwrap_or(&fs_rel)
                            .to_string();
                    } else if is_keydata_marker {
                        fs_rel = fs_rel
                            .strip_suffix(KEY_DATA_MARKER_FILE)
                            .unwrap_or(&fs_rel)
                            .trim_end_matches('/')
                            .to_string();
                    }
                    if let Ok(meta) = entry.metadata() {
                        let mtime = meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);

                        let lookup_path = if is_keydata_marker {
                            Path::new(&fs_rel).to_path_buf()
                        } else {
                            Path::new(&fs_rel)
                                .parent()
                                .map(|p| p.to_path_buf())
                                .unwrap_or_default()
                        };
                        let lookup_name = if is_keydata_marker {
                            Path::new(&fs_rel)
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| name_str.to_string())
                        } else {
                            name_str.to_string()
                        };
                        let rel_dir = if is_keydata_marker {
                            Path::new(&fs_rel)
                                .parent()
                                .map(|p| p.to_path_buf())
                                .unwrap_or_default()
                        } else {
                            lookup_path
                        };
                        let idx = dir_idx_cache.entry(rel_dir.clone()).or_insert_with(|| {
                            self.load_dir_index_full_sync(bucket_name, &rel_dir)
                        });
                        let (etag, version_id, owner) = if is_dir_marker {
                            (None, None, None)
                        } else {
                            idx.get(lookup_name.as_str())
                                .cloned()
                                .unwrap_or((None, None, None))
                        };

                        let key = fs_decode_key(&fs_rel);
                        all_keys.push((key, meta.len(), mtime, etag, version_id, owner));
                    }
                }
            }
        }

        all_keys.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(all_keys)
    }

    pub(super) fn build_full_listing_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<Arc<Vec<ListCacheEntry>>> {
        self.build_full_listing_entries_sync(bucket_name)
            .map(Arc::new)
    }

    pub(super) fn listing_records(entries: Vec<ListCacheEntry>) -> Vec<ListingRecord> {
        entries
            .into_iter()
            .map(|(key, size, mtime, etag, version_id, owner)| {
                ListingRecord::new(key, size, mtime, etag, version_id, owner)
            })
            .collect()
    }

    pub(super) fn build_listing_records_and_counters_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<(Vec<ListingRecord>, ListingCounters)> {
        let entries = self.build_full_listing_entries_sync(bucket_name)?;
        let records = Self::listing_records(entries);
        let mut counters = self.build_version_counters_sync(bucket_name);
        counters.live_objects = records.len() as u64;
        counters.live_logical_bytes = records
            .iter()
            .fold(0u64, |total, record| total.saturating_add(record.size));
        Ok((records, counters))
    }

    pub(super) fn current_listing_record_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<Option<ListingRecord>> {
        let path = self.object_live_path(bucket_name, key);
        let meta = match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => meta,
            Ok(_) => return Ok(None),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs_f64())
            .unwrap_or(0.0);
        let (etag, version_id, owner) = if key.ends_with('/') {
            (None, None, None)
        } else {
            let entry = self.read_index_entry_sync(bucket_name, key);
            Self::listing_fields_from_meta(
                entry
                    .as_ref()
                    .and_then(|entry| entry.get("metadata"))
                    .and_then(Value::as_object),
            )
        };
        Ok(Some(ListingRecord::new(
            key.to_string(),
            meta.len(),
            mtime,
            etag,
            version_id,
            owner,
        )))
    }

    pub(super) fn load_listing_index_locked_sync(
        &self,
        bucket_name: &str,
    ) -> std::io::Result<Option<Arc<Mutex<BucketListingIndex>>>> {
        let listing_dir = self.bucket_listing_dir(bucket_name);
        if !listing_dir.join("snapshot.json").is_file() {
            return Ok(None);
        }
        let index = BucketListingIndex::load(listing_dir, self.listing_index_compact_min_ops)?;
        let index = Arc::new(Mutex::new(index));
        self.listing_indexes
            .insert(bucket_name.to_string(), index.clone());
        let compact_pending = index.lock().mark_compact_pending_if_needed();
        if compact_pending {
            self.enqueue_listing_compaction(
                bucket_name,
                index.clone(),
                self.get_list_rebuild_lock(bucket_name),
            );
        }
        Ok(Some(index))
    }

    pub(super) fn discard_listing_index_locked_sync(&self, bucket_name: &str) {
        if let Some(index) = self
            .listing_indexes
            .get(bucket_name)
            .map(|entry| entry.value().clone())
        {
            wait_for_listing_compaction_install(&index);
            index.lock().invalidate();
        }
        let removed = self.listing_indexes.remove(bucket_name);
        drop(removed);
        if let Err(err) = crate::listing_index::discard(&self.bucket_listing_dir(bucket_name)) {
            tracing::warn!(
                bucket = bucket_name,
                error = %err,
                "failed to discard listing index"
            );
        }
    }

    pub(super) fn discard_listing_index_if_same_locked_sync(
        &self,
        bucket_name: &str,
        expected: &Arc<Mutex<BucketListingIndex>>,
    ) {
        let current = self
            .listing_indexes
            .get(bucket_name)
            .map(|entry| entry.value().clone());
        if current
            .as_ref()
            .is_some_and(|index| Arc::ptr_eq(index, expected))
        {
            self.discard_listing_index_locked_sync(bucket_name);
        }
    }

    pub(super) fn mark_listing_index_dirty_sync(
        &self,
        bucket_name: &str,
        error: &dyn std::fmt::Display,
    ) {
        if !self.listing_index_enabled {
            return;
        }
        tracing::warn!(
            bucket = bucket_name,
            error = %error,
            "listing index marked dirty"
        );
        let lock = self.get_list_rebuild_lock(bucket_name);
        let _guard = lock.lock();
        self.discard_listing_index_locked_sync(bucket_name);
    }

    pub(super) fn update_listing_index_after_commit(&self, bucket_name: &str, key: &str) {
        self.update_listing_index_after_commit_with_versions(bucket_name, key, &[]);
    }

    pub(super) fn update_listing_index_after_commit_with_versions(
        &self,
        bucket_name: &str,
        key: &str,
        version_mutations: &[VersionMutation],
    ) {
        if !self.listing_index_enabled {
            return;
        }
        let record = match self.current_listing_record_sync(bucket_name, key) {
            Ok(record) => record,
            Err(err) => {
                self.mark_listing_index_dirty_sync(bucket_name, &err);
                return;
            }
        };
        let rebuild_lock = self.get_list_rebuild_lock(bucket_name);
        let _rebuild_guard = rebuild_lock.lock();
        let index = match self
            .listing_indexes
            .get(bucket_name)
            .map(|entry| entry.value().clone())
        {
            Some(index) => index,
            None => match self.load_listing_index_locked_sync(bucket_name) {
                Ok(Some(index)) => index,
                Ok(None) => {
                    if self.bucket_listing_dir(bucket_name).exists() {
                        self.discard_listing_index_locked_sync(bucket_name);
                    }
                    return;
                }
                Err(err) => {
                    tracing::warn!(
                        bucket = bucket_name,
                        error = %err,
                        "failed to load listing index for a committed mutation"
                    );
                    self.discard_listing_index_locked_sync(bucket_name);
                    return;
                }
            },
        };
        let (result, compact_pending) = {
            let mut index_guard = index.lock();
            let result = if !index_guard.is_valid() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "listing index is invalid",
                ))
            } else {
                let state_result = match record {
                    Some(record) => index_guard.apply_put(record),
                    None => index_guard.apply_del(key),
                };
                state_result.and_then(|()| {
                    for mutation in version_mutations {
                        index_guard.apply_version_mutation(mutation)?;
                    }
                    Ok(())
                })
            };
            if result.is_err() {
                index_guard.invalidate();
            }
            let compact_pending = result.is_ok() && index_guard.mark_compact_pending_if_needed();
            (result, compact_pending)
        };
        if let Err(err) = result {
            tracing::warn!(
                bucket = bucket_name,
                key = key,
                error = %err,
                "failed to update listing index after commit"
            );
            self.discard_listing_index_if_same_locked_sync(bucket_name, &index);
        } else if compact_pending {
            self.enqueue_listing_compaction(bucket_name, index, rebuild_lock.clone());
        }
    }

    pub(super) fn get_listing_index_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<Arc<Mutex<BucketListingIndex>>> {
        if let Some(index) = self
            .listing_indexes
            .get(bucket_name)
            .map(|entry| entry.value().clone())
        {
            return Ok(index);
        }

        let rebuild_lock = self.get_list_rebuild_lock(bucket_name);
        let _rebuild_guard = rebuild_lock.lock();
        if let Some(index) = self
            .listing_indexes
            .get(bucket_name)
            .map(|entry| entry.value().clone())
        {
            return Ok(index);
        }

        match self.load_listing_index_locked_sync(bucket_name) {
            Ok(Some(index)) => return Ok(index),
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(
                    bucket = bucket_name,
                    error = %err,
                    "failed to load listing index; rebuilding from object sidecars"
                );
            }
        }
        self.discard_listing_index_locked_sync(bucket_name);

        let (records, counters) = self.build_listing_records_and_counters_sync(bucket_name)?;
        let mut index = BucketListingIndex::from_records_with_counters(
            self.bucket_listing_dir(bucket_name),
            records,
            counters,
            self.listing_index_compact_min_ops,
        );
        if let Err(err) = index.persist_rebuilt() {
            tracing::warn!(
                bucket = bucket_name,
                error = %err,
                "failed to persist rebuilt listing index; serving the in-memory rebuild"
            );
            let _ = crate::listing_index::discard(&self.bucket_listing_dir(bucket_name));
            return Ok(Arc::new(Mutex::new(index)));
        }
        let index = Arc::new(Mutex::new(index));
        self.listing_indexes
            .insert(bucket_name.to_string(), index.clone());
        Ok(index)
    }

    pub fn rebuild_listing_index_sync(&self, bucket: &str) -> StorageResult<usize> {
        self.require_bucket(bucket)?;
        let rebuild_lock = self.get_list_rebuild_lock(bucket);
        let _rebuild_guard = rebuild_lock.lock();
        let (records, counters) = self.build_listing_records_and_counters_sync(bucket)?;
        let mut index = BucketListingIndex::from_records_with_counters(
            self.bucket_listing_dir(bucket),
            records,
            counters,
            self.listing_index_compact_min_ops,
        );
        let count = index.len();
        self.discard_listing_index_locked_sync(bucket);
        if let Err(err) = index.persist_rebuilt() {
            let _ = crate::listing_index::discard(&self.bucket_listing_dir(bucket));
            return Err(StorageError::Io(err));
        }
        self.listing_indexes
            .insert(bucket.to_string(), Arc::new(Mutex::new(index)));
        Ok(count)
    }

    pub fn invalidate_all_listing_indexes_sync(&self) -> StorageResult<usize> {
        let entries = std::fs::read_dir(&self.root).map_err(StorageError::Io)?;
        let mut buckets = Vec::new();
        for entry in entries {
            let entry = entry.map_err(StorageError::Io)?;
            if !entry.file_type().map_err(StorageError::Io)?.is_dir() {
                continue;
            }
            let bucket = entry.file_name().to_string_lossy().to_string();
            if bucket == SYSTEM_ROOT {
                continue;
            }
            buckets.push(bucket);
        }
        buckets.sort();

        for bucket in &buckets {
            let rebuild_lock = self.get_list_rebuild_lock(bucket);
            let _rebuild_guard = rebuild_lock.lock();
            if let Some(index) = self
                .listing_indexes
                .get(bucket)
                .map(|entry| entry.value().clone())
            {
                wait_for_listing_compaction_install(&index);
                index.lock().invalidate();
            }
            let removed = self.listing_indexes.remove(bucket);
            drop(removed);
            crate::listing_index::discard(&self.bucket_listing_dir(bucket))
                .map_err(StorageError::Io)?;
            self.invalidate_bucket_caches(bucket);
        }

        Ok(buckets.len())
    }

    pub(super) fn get_full_listing_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<Arc<Vec<ListCacheEntry>>> {
        if let Some(entry) = self.list_cache.get(bucket_name) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let lock = self.get_list_rebuild_lock(bucket_name);
        let _guard = lock.lock();

        if let Some(entry) = self.list_cache.get(bucket_name) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let listing = self.build_full_listing_sync(bucket_name)?;
        self.list_cache
            .insert(bucket_name.to_string(), (listing.clone(), Instant::now()));
        Ok(listing)
    }

    pub(super) fn list_objects_legacy_sync(
        &self,
        bucket_name: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        self.require_bucket(bucket_name)?;
        let prefix = params
            .prefix
            .as_deref()
            .map(|p| p.trim_start_matches(['/', '\\']));
        if let Some(prefix) = prefix {
            if !prefix.is_empty() {
                validate_list_prefix(prefix)?;
            }
        }

        let listing = self.get_full_listing_sync(bucket_name)?;

        let (slice_start, slice_end) = match prefix {
            Some(p) if !p.is_empty() => slice_range_for_prefix(&listing[..], |e| &e.0, p),
            _ => (0, listing.len()),
        };
        let prefix_filter = &listing[slice_start..slice_end];

        let start_idx = if let Some(ref token) = params.continuation_token {
            prefix_filter.partition_point(|k| k.0.as_str() <= token.as_str())
        } else if let Some(ref start_after) = params.start_after {
            prefix_filter.partition_point(|k| k.0.as_str() <= start_after.as_str())
        } else {
            0
        };

        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        let end_idx = std::cmp::min(start_idx + max_keys, prefix_filter.len());
        let is_truncated = end_idx < prefix_filter.len();

        let objects: Vec<ObjectMeta> = prefix_filter[start_idx..end_idx]
            .iter()
            .map(|(key, size, mtime, etag, version_id, owner)| {
                let lm = Utc
                    .timestamp_opt(*mtime as i64, ((*mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
                    .unwrap_or_else(Utc::now);
                let mut obj = ObjectMeta::new(key.clone(), *size, lm);
                obj.etag = etag.clone();
                obj.version_id = version_id.clone();
                obj.owner = owner.clone();
                obj
            })
            .collect();

        let next_token = if is_truncated {
            objects.last().map(|o| o.key.clone())
        } else {
            None
        };

        Ok(ListObjectsResult {
            objects,
            is_truncated,
            next_continuation_token: next_token,
        })
    }

    pub(super) fn list_objects_indexed_sync(
        &self,
        bucket_name: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        self.require_bucket(bucket_name)?;
        let prefix = params
            .prefix
            .as_deref()
            .map(|prefix| prefix.trim_start_matches(['/', '\\']))
            .unwrap_or_default();
        if !prefix.is_empty() {
            validate_list_prefix(prefix)?;
        }
        let marker = params
            .continuation_token
            .as_deref()
            .or(params.start_after.as_deref());
        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        loop {
            let index = self.get_listing_index_sync(bucket_name)?;
            let index_guard = index.lock();
            if index_guard.is_valid() {
                let (records, is_truncated, next_continuation_token) =
                    index_guard.page(prefix, marker, max_keys);
                drop(index_guard);
                let objects = records
                    .into_iter()
                    .map(|record| {
                        let lm = Utc
                            .timestamp_opt(
                                record.mtime as i64,
                                ((record.mtime % 1.0) * 1_000_000_000.0) as u32,
                            )
                            .single()
                            .unwrap_or_else(Utc::now);
                        let mut object = ObjectMeta::new(record.key, record.size, lm);
                        object.etag = record.etag;
                        object.version_id = record.version_id;
                        object.owner = record.owner;
                        object
                    })
                    .collect();
                return Ok(ListObjectsResult {
                    objects,
                    is_truncated,
                    next_continuation_token,
                });
            }
            drop(index_guard);
            let rebuild_lock = self.get_list_rebuild_lock(bucket_name);
            let _rebuild_guard = rebuild_lock.lock();
            self.discard_listing_index_if_same_locked_sync(bucket_name, &index);
        }
    }

    pub(super) fn list_objects_sync(
        &self,
        bucket_name: &str,
        params: &ListParams,
    ) -> StorageResult<ListObjectsResult> {
        if self.listing_index_enabled {
            self.list_objects_indexed_sync(bucket_name, params)
        } else {
            self.list_objects_legacy_sync(bucket_name, params)
        }
    }

    pub(super) fn build_shallow_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
        delimiter: &str,
    ) -> StorageResult<Arc<ShallowCacheEntry>> {
        let bucket_path = self.require_bucket(bucket_name)?;
        let target_dir = bucket_path.join(rel_dir);

        if !path_is_within(&target_dir, &bucket_path) {
            return Err(StorageError::InvalidObjectKey(
                "prefix escapes bucket root".to_string(),
            ));
        }

        if !target_dir.exists() {
            return Ok(Arc::new(ShallowCacheEntry::default()));
        }

        let dir_index = self.load_dir_index_full_sync(bucket_name, rel_dir);

        let mut files = Vec::new();
        let mut dirs = Vec::new();

        let rel_dir_prefix = if rel_dir.as_os_str().is_empty() {
            String::new()
        } else {
            let s = rel_dir.to_string_lossy().into_owned();
            #[cfg(windows)]
            let s = s.replace('\\', "/");
            let mut decoded = fs_decode_key(&s);
            if !decoded.ends_with('/') {
                decoded.push('/');
            }
            decoded
        };

        let entries = std::fs::read_dir(&target_dir).map_err(StorageError::Io)?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();

            if target_dir == bucket_path && INTERNAL_FOLDERS.contains(&name_str.as_str()) {
                continue;
            }

            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            let display_name = fs_decode_key(&name_str);
            if ft.is_dir() {
                dirs.push(format!("{}{}{}", rel_dir_prefix, display_name, delimiter));
                let marker_path = entry.path().join(KEY_DATA_MARKER_FILE);
                if let Ok(marker_meta) = std::fs::metadata(&marker_path) {
                    if marker_meta.is_file() {
                        let mtime = marker_meta
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);
                        let lm = Utc
                            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
                            .single()
                            .unwrap_or_else(Utc::now);
                        let rel = format!("{}{}", rel_dir_prefix, display_name);
                        let mut obj = ObjectMeta::new(rel, marker_meta.len(), lm);
                        let (etag, _vid, owner) = dir_index
                            .get(&name_str)
                            .cloned()
                            .unwrap_or((None, None, None));
                        obj.etag = etag;
                        obj.owner = owner;
                        files.push(obj);
                    }
                }
            } else if ft.is_file() {
                if name_str == KEY_DATA_MARKER_FILE {
                    continue;
                }
                if name_str == DIR_MARKER_FILE {
                    if !rel_dir_prefix.is_empty() {
                        if let Ok(meta) = entry.metadata() {
                            let mtime = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                                .map(|d| d.as_secs_f64())
                                .unwrap_or(0.0);
                            let lm = Utc
                                .timestamp_opt(
                                    mtime as i64,
                                    ((mtime % 1.0) * 1_000_000_000.0) as u32,
                                )
                                .single()
                                .unwrap_or_else(Utc::now);
                            let mut obj = ObjectMeta::new(rel_dir_prefix.clone(), meta.len(), lm);
                            obj.etag = None;
                            files.push(obj);
                        }
                    }
                    continue;
                }
                let rel = format!("{}{}", rel_dir_prefix, display_name);
                if let Ok(meta) = entry.metadata() {
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
                    let (etag, _vid, owner) = dir_index
                        .get(&name_str)
                        .cloned()
                        .unwrap_or((None, None, None));
                    let mut obj = ObjectMeta::new(rel, meta.len(), lm);
                    obj.etag = etag;
                    obj.owner = owner;
                    files.push(obj);
                }
            }
        }

        files.sort_by(|a, b| a.key.cmp(&b.key));
        dirs.sort();
        Ok(Arc::new(ShallowCacheEntry { files, dirs }))
    }

    pub(super) fn get_shallow_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
        delimiter: &str,
    ) -> StorageResult<Arc<ShallowCacheEntry>> {
        let cache_key = (
            bucket_name.to_string(),
            rel_dir.to_path_buf(),
            delimiter.to_string(),
        );
        if let Some(entry) = self.shallow_cache.get(&cache_key) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let lock = self
            .shallow_rebuild_locks
            .entry(cache_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock();

        if let Some(entry) = self.shallow_cache.get(&cache_key) {
            let (cached, cached_at) = entry.value();
            if cached_at.elapsed() < self.list_cache_ttl {
                return Ok(cached.clone());
            }
        }

        let built = self.build_shallow_sync(bucket_name, rel_dir, delimiter)?;
        self.shallow_cache
            .insert(cache_key, (built.clone(), Instant::now()));
        Ok(built)
    }

    pub(super) fn list_objects_shallow_sync(
        &self,
        bucket_name: &str,
        params: &ShallowListParams,
    ) -> StorageResult<ShallowListResult> {
        self.require_bucket(bucket_name)?;

        let prefix = params.prefix.trim_start_matches(['/', '\\']);

        let rel_dir: PathBuf = if prefix.is_empty() {
            PathBuf::new()
        } else {
            validate_list_prefix(prefix)?;
            let encoded_prefix = fs_encode_key(prefix);
            let prefix_path = Path::new(&encoded_prefix);
            if prefix.ends_with(&params.delimiter) {
                prefix_path.to_path_buf()
            } else {
                prefix_path.parent().unwrap_or(Path::new("")).to_path_buf()
            }
        };

        if !rel_dir.as_os_str().is_empty()
            && !self.verify_disk_casing(&self.bucket_path(bucket_name).join(&rel_dir))?
        {
            return Ok(ShallowListResult {
                objects: Vec::new(),
                common_prefixes: Vec::new(),
                is_truncated: false,
                next_continuation_token: None,
            });
        }

        let cached = self.get_shallow_sync(bucket_name, &rel_dir, &params.delimiter)?;

        let (file_start, file_end) = slice_range_for_prefix(&cached.files, |o| &o.key, prefix);
        let (dir_start, dir_end) = slice_range_for_prefix(&cached.dirs, |s| s, prefix);
        let files = &cached.files[file_start..file_end];
        let dirs = &cached.dirs[dir_start..dir_end];

        let max_keys = if params.max_keys == 0 {
            DEFAULT_MAX_KEYS
        } else {
            params.max_keys
        };

        let token_filter = |key: &str| -> bool {
            params
                .continuation_token
                .as_deref()
                .map(|t| key > t)
                .unwrap_or(true)
        };

        let file_skip = params
            .continuation_token
            .as_deref()
            .map(|t| files.partition_point(|o| o.key.as_str() <= t))
            .unwrap_or(0);
        let dir_skip = params
            .continuation_token
            .as_deref()
            .map(|t| dirs.partition_point(|d| d.as_str() <= t))
            .unwrap_or(0);

        let mut fi = file_skip;
        let mut di = dir_skip;
        let mut result_objects: Vec<ObjectMeta> = Vec::new();
        let mut result_prefixes: Vec<String> = Vec::new();
        let mut last_key: Option<String> = None;
        let mut total = 0usize;

        while total < max_keys && (fi < files.len() || di < dirs.len()) {
            let take_file = match (fi < files.len(), di < dirs.len()) {
                (true, true) => files[fi].key.as_str() < dirs[di].as_str(),
                (true, false) => true,
                (false, true) => false,
                _ => break,
            };
            if take_file {
                if token_filter(&files[fi].key) {
                    last_key = Some(files[fi].key.clone());
                    result_objects.push(files[fi].clone());
                    total += 1;
                }
                fi += 1;
            } else {
                if token_filter(&dirs[di]) {
                    last_key = Some(dirs[di].clone());
                    result_prefixes.push(dirs[di].clone());
                    total += 1;
                }
                di += 1;
            }
        }

        let remaining = fi < files.len() || di < dirs.len();
        let is_truncated = remaining;
        let next_token = if is_truncated { last_key } else { None };

        Ok(ShallowListResult {
            objects: result_objects,
            common_prefixes: result_prefixes,
            is_truncated,
            next_continuation_token: next_token,
        })
    }
}
