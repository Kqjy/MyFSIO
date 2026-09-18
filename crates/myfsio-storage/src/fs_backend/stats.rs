use super::*;

impl FsStorageBackend {
    pub(super) fn bucket_stats_sync(&self, bucket_name: &str) -> StorageResult<BucketStats> {
        self.require_bucket(bucket_name)?;
        if let Some(counters) = self.live_listing_counters_sync(bucket_name) {
            return Ok(Self::bucket_stats_from_counters(counters));
        }

        if let Some(entry) = self.stats_cache.get(bucket_name) {
            let (stats, cached_at) = entry.value();
            if cached_at.elapsed() < self.stats_cache_ttl {
                return Ok(stats.clone());
            }
        }

        let stats = self.bucket_stats_walk_sync(bucket_name)?;
        self.stats_cache
            .insert(bucket_name.to_string(), (stats.clone(), Instant::now()));
        Ok(stats)
    }

    pub(super) fn bucket_stats_for_quota_sync(
        &self,
        bucket_name: &str,
    ) -> StorageResult<BucketStats> {
        self.require_bucket(bucket_name)?;
        if let Some(counters) = self.live_listing_counters_sync(bucket_name) {
            return Ok(Self::bucket_stats_from_counters(counters));
        }
        let stats = self.bucket_stats_walk_sync(bucket_name)?;
        self.stats_cache
            .insert(bucket_name.to_string(), (stats.clone(), Instant::now()));
        Ok(stats)
    }

    pub(super) fn bucket_stats_from_counters(counters: ListingCounters) -> BucketStats {
        BucketStats {
            objects: counters.live_objects,
            bytes: counters.live_logical_bytes,
            version_count: counters.version_count,
            version_bytes: counters.version_logical_bytes,
        }
    }

    pub(super) fn live_listing_counters_sync(&self, bucket_name: &str) -> Option<ListingCounters> {
        if !self.listing_index_enabled {
            return None;
        }
        let rebuild_lock = self.get_list_rebuild_lock(bucket_name);
        let _rebuild_guard = rebuild_lock.try_lock()?;
        let index = match self
            .listing_indexes
            .get(bucket_name)
            .map(|entry| entry.value().clone())
        {
            Some(index) => index,
            None => match self.load_listing_index_locked_sync(bucket_name) {
                Ok(Some(index)) => index,
                Ok(None) => return None,
                Err(err) => {
                    tracing::warn!(
                        bucket = bucket_name,
                        error = %err,
                        "failed to load listing counters"
                    );
                    self.discard_listing_index_locked_sync(bucket_name);
                    return None;
                }
            },
        };
        let index = index.lock();
        index.is_valid().then(|| index.counters())
    }

    pub(super) fn bucket_stats_walk_sync(&self, bucket_name: &str) -> StorageResult<BucketStats> {
        #[cfg(test)]
        self.stats_full_walks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bucket_path = self.require_bucket(bucket_name)?;
        let mut object_count: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut version_count: u64 = 0;
        let mut version_bytes: u64 = 0;

        let internal = INTERNAL_FOLDERS;
        let bucket_str = bucket_path.to_string_lossy().to_string();
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
                    object_count += 1;
                    if let Ok(meta) = entry.metadata() {
                        total_bytes += meta.len();
                    }
                }
            }
        }

        let versions_root = self.bucket_versions_root(bucket_name);
        if versions_root.exists() {
            let mut v_stack = vec![versions_root.to_string_lossy().to_string()];
            while let Some(current) = v_stack.pop() {
                let entries = match std::fs::read_dir(&current) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let ft = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if ft.is_dir() {
                        v_stack.push(entry.path().to_string_lossy().to_string());
                    } else if ft.is_file() {
                        let name = entry.file_name();
                        if name.to_string_lossy().ends_with(".bin") {
                            version_count += 1;
                            if let Ok(meta) = entry.metadata() {
                                version_bytes += meta.len();
                            }
                        }
                    }
                }
            }
        }

        Ok(BucketStats {
            objects: object_count,
            bytes: total_bytes,
            version_count,
            version_bytes,
        })
    }

    pub(super) fn build_version_counters_sync(&self, bucket_name: &str) -> ListingCounters {
        let mut counters = ListingCounters::default();
        let versions_root = self.bucket_versions_root(bucket_name);
        if !versions_root.exists() {
            return counters;
        }
        let mut stack = vec![versions_root];
        while let Some(current) = stack.pop() {
            let entries = match std::fs::read_dir(current) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                if file_type.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                if !file_type.is_file() {
                    continue;
                }
                let path = entry.path();
                match path.extension().and_then(|extension| extension.to_str()) {
                    Some("bin") => {
                        counters.version_count = counters.version_count.saturating_add(1);
                        if let Ok(metadata) = entry.metadata() {
                            counters.version_logical_bytes = counters
                                .version_logical_bytes
                                .saturating_add(metadata.len());
                        }
                    }
                    Some("json") => {
                        let is_delete_marker = std::fs::read_to_string(path)
                            .ok()
                            .and_then(|content| serde_json::from_str::<Value>(&content).ok())
                            .and_then(|record| {
                                record.get("is_delete_marker").and_then(Value::as_bool)
                            })
                            .unwrap_or(false);
                        if is_delete_marker {
                            counters.delete_marker_count =
                                counters.delete_marker_count.saturating_add(1);
                        }
                    }
                    _ => {}
                }
            }
        }
        counters
    }
}
