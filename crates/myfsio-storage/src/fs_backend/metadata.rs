use super::*;

impl FsStorageBackend {
    pub(super) fn purge_meta_read_cache_for_bucket(&self, bucket_name: &str) {
        let mut cache = self.meta_read_cache.lock();
        let stale: Vec<(String, String)> = cache
            .iter()
            .filter(|((bucket, _), _)| bucket == bucket_name)
            .map(|(key, _)| key.clone())
            .collect();
        for key in stale {
            cache.pop(&key);
        }
    }

    pub(super) fn index_file_for_key(&self, bucket_name: &str, key: &str) -> (PathBuf, String) {
        let meta_root = self.bucket_meta_root(bucket_name);
        if key.ends_with('/') {
            let encoded = fs_encode_key(key);
            let trimmed = encoded.trim_end_matches('/');
            if trimmed.is_empty() {
                return (meta_root.join(INDEX_FILE), DIR_MARKER_FILE.to_string());
            }
            return (
                meta_root.join(trimmed).join(INDEX_FILE),
                DIR_MARKER_FILE.to_string(),
            );
        }
        let encoded = fs_encode_key(key);
        let encoded_path = Path::new(&encoded);
        let entry_name = encoded_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| encoded.clone());

        let parent = encoded_path.parent();
        match parent {
            Some(p) if p != Path::new("") && p != Path::new(".") => {
                (meta_root.join(p).join(INDEX_FILE), entry_name)
            }
            _ => (meta_root.join(INDEX_FILE), entry_name),
        }
    }

    pub(super) fn index_file_for_dir(&self, bucket_name: &str, rel_dir: &Path) -> PathBuf {
        let meta_root = self.bucket_meta_root(bucket_name);
        if rel_dir.as_os_str().is_empty() || rel_dir == Path::new(".") {
            meta_root.join(INDEX_FILE)
        } else {
            meta_root.join(rel_dir).join(INDEX_FILE)
        }
    }

    pub(super) fn load_dir_index_full_sync(
        &self,
        bucket_name: &str,
        rel_dir: &Path,
    ) -> HashMap<String, (Option<String>, Option<String>, Option<String>)> {
        let index_path = self.index_file_for_dir(bucket_name, rel_dir);
        let mut out = HashMap::new();
        if index_path.exists() {
            if let Ok(text) = std::fs::read_to_string(&index_path) {
                match serde_json::from_str::<HashMap<String, Value>>(&text) {
                    Ok(index) => {
                        for (name, entry) in index {
                            let fields = Self::listing_fields_from_meta(
                                entry.get("metadata").and_then(|m| m.as_object()),
                            );
                            out.insert(name, fields);
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            "corrupt metadata index {} ignored during listing: {}",
                            index_path.display(),
                            err
                        );
                    }
                }
            }
        }

        let dir = index_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.bucket_meta_root(bucket_name));
        if let Ok(read_dir) = std::fs::read_dir(&dir) {
            for dirent in read_dir.flatten() {
                let file_name = dirent.file_name();
                let Some(name) = file_name.to_str() else {
                    continue;
                };
                if !Self::is_sidecar_file_name(name) {
                    continue;
                }
                if !dirent.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let fallback_name = name
                    .strip_prefix(SIDECAR_FILE_PREFIX)
                    .and_then(|s| s.strip_suffix(SIDECAR_FILE_EXT))
                    .map(ToOwned::to_owned);
                let path = dirent.path();
                let Ok(text) = std::fs::read_to_string(&path) else {
                    if let Some(fallback) = fallback_name {
                        out.insert(fallback, (None, None, None));
                    }
                    continue;
                };
                let Ok(entry) = serde_json::from_str::<HashMap<String, Value>>(&text) else {
                    tracing::warn!(
                        "corrupt metadata sidecar {} blanks its listing entry",
                        path.display()
                    );
                    if let Some(fallback) = fallback_name {
                        out.insert(fallback, (None, None, None));
                    }
                    continue;
                };
                let Some(entry_name) = Self::sidecar_entry_name_from_file(name, &entry) else {
                    continue;
                };
                let fields = Self::listing_fields_from_meta(
                    entry.get("metadata").and_then(|m| m.as_object()),
                );
                out.insert(entry_name, fields);
            }
        }
        out
    }

    pub(super) fn listing_fields_from_meta(
        meta: Option<&serde_json::Map<String, Value>>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let etag = meta
            .and_then(|m| m.get("__etag__"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let version_id = meta
            .and_then(|m| m.get("__version_id__"))
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);
        let owner = meta
            .and_then(|m| m.get("__acl__"))
            .and_then(|v| v.as_str())
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .and_then(|acl| {
                acl.get("owner")
                    .and_then(|v| v.as_str())
                    .map(ToOwned::to_owned)
            });
        (etag, version_id, owner)
    }

    pub(super) fn sidecar_file_name(entry_name: &str) -> String {
        let plain = format!("{}{}{}", SIDECAR_FILE_PREFIX, entry_name, SIDECAR_FILE_EXT);
        if plain.len() <= SIDECAR_MAX_FILE_NAME_BYTES {
            return plain;
        }
        let digest = hex::encode(sha2::Sha256::digest(entry_name.as_bytes()));
        format!("{}{}{}", SIDECAR_FILE_PREFIX, digest, SIDECAR_FILE_EXT)
    }

    pub(super) fn is_sidecar_file_name(name: &str) -> bool {
        name.len() > SIDECAR_FILE_PREFIX.len() + SIDECAR_FILE_EXT.len()
            && name.starts_with(SIDECAR_FILE_PREFIX)
            && name.ends_with(SIDECAR_FILE_EXT)
    }

    pub(super) fn sidecar_entry_name_from_file(
        file_name: &str,
        entry: &HashMap<String, Value>,
    ) -> Option<String> {
        if let Some(Value::String(name)) = entry.get(SIDECAR_ENTRY_NAME_FIELD) {
            return Some(name.clone());
        }
        file_name
            .strip_prefix(SIDECAR_FILE_PREFIX)?
            .strip_suffix(SIDECAR_FILE_EXT)
            .map(ToOwned::to_owned)
    }

    pub(super) fn sidecar_file_for_key(&self, bucket_name: &str, key: &str) -> (PathBuf, String) {
        let (index_path, entry_name) = self.index_file_for_key(bucket_name, key);
        let dir = index_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.bucket_meta_root(bucket_name));
        (dir.join(Self::sidecar_file_name(&entry_name)), entry_name)
    }

    pub(super) fn corrupt_metadata_entry(detail: String) -> HashMap<String, Value> {
        let mut meta = serde_json::Map::new();
        meta.insert(
            META_KEY_CORRUPTED.to_string(),
            Value::String("true".to_string()),
        );
        meta.insert(
            META_KEY_CORRUPTED_AT.to_string(),
            Value::String(Utc::now().to_rfc3339()),
        );
        meta.insert(
            META_KEY_CORRUPTION_DETAIL.to_string(),
            Value::String(detail),
        );
        meta.insert(
            META_KEY_UNREADABLE.to_string(),
            Value::String("true".to_string()),
        );
        let mut entry = HashMap::new();
        entry.insert("metadata".to_string(), Value::Object(meta));
        entry
    }

    pub(super) fn entry_marks_unreadable_metadata(entry: &HashMap<String, Value>) -> bool {
        entry
            .get("metadata")
            .and_then(|m| m.as_object())
            .and_then(|m| m.get(META_KEY_UNREADABLE))
            .and_then(|v| v.as_str())
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    pub(super) fn read_index_entry_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> Option<HashMap<String, Value>> {
        let cache_key = (bucket_name.to_string(), key.to_string());
        if self.object_cache_max_size > 0 {
            if let Some(entry) = self.meta_read_cache.lock().get(&cache_key) {
                return entry.clone();
            }
        }

        let (sidecar_path, entry_name) = self.sidecar_file_for_key(bucket_name, key);
        let result = if sidecar_path.exists() {
            match std::fs::read_to_string(&sidecar_path)
                .map_err(|e| e.to_string())
                .and_then(|s| {
                    serde_json::from_str::<HashMap<String, Value>>(&s).map_err(|e| e.to_string())
                }) {
                Ok(entry) => Some(entry),
                Err(err) => {
                    tracing::warn!(
                        "unreadable metadata sidecar {} for {}/{}: {}; failing closed",
                        sidecar_path.display(),
                        bucket_name,
                        key,
                        err
                    );
                    Some(Self::corrupt_metadata_entry(format!(
                        "metadata sidecar unreadable: {}",
                        err
                    )))
                }
            }
        } else {
            let (index_path, _) = self.index_file_for_key(bucket_name, key);
            if index_path.exists() {
                match std::fs::read_to_string(&index_path)
                    .map_err(|e| e.to_string())
                    .and_then(|s| {
                        serde_json::from_str::<HashMap<String, Value>>(&s)
                            .map_err(|e| e.to_string())
                    }) {
                    Ok(index) => index.get(&entry_name).and_then(|v| {
                        if let Value::Object(map) = v {
                            Some(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                        } else {
                            None
                        }
                    }),
                    Err(err) => {
                        tracing::warn!(
                            "corrupt metadata index {} while reading {}/{}: {}; failing closed",
                            index_path.display(),
                            bucket_name,
                            key,
                            err
                        );
                        Some(Self::corrupt_metadata_entry(format!(
                            "metadata index unreadable: {}",
                            err
                        )))
                    }
                }
            } else {
                None
            }
        };

        if self.object_cache_max_size > 0 {
            self.meta_read_cache.lock().put(cache_key, result.clone());
        }
        result
    }

    pub(super) fn write_index_entry_sync(
        &self,
        bucket_name: &str,
        key: &str,
        entry: &HashMap<String, Value>,
    ) -> std::io::Result<()> {
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "metadata:rewrite")?;
        if Self::entry_marks_unreadable_metadata(entry) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "refusing to persist metadata for {}/{}: the existing metadata record is \
                     unreadable; repair or delete the object first",
                    bucket_name, key
                ),
            ));
        }
        let (index_path, entry_name) = self.index_file_for_key(bucket_name, key);
        if let Some(parent) = index_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let (sidecar_path, _) = self.sidecar_file_for_key(bucket_name, key);

        match self.metadata_layout {
            MetadataLayout::Sidecar => {
                self.write_sidecar_file(&sidecar_path, &entry_name, entry)?;
            }
            MetadataLayout::Index => {
                let lock = self.get_meta_index_lock(&index_path.to_string_lossy());
                let _guard = lock.lock();
                let mut index_data: HashMap<String, Value> = if index_path.exists() {
                    let text = std::fs::read_to_string(&index_path)?;
                    serde_json::from_str(&text).map_err(|err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "refusing to rewrite corrupt metadata index {}: {}",
                                index_path.display(),
                                err
                            ),
                        )
                    })?
                } else {
                    HashMap::new()
                };
                index_data.insert(
                    entry_name.clone(),
                    serde_json::to_value(entry).map_err(std::io::Error::other)?,
                );
                if sidecar_path.exists() {
                    self.write_sidecar_file(&sidecar_path, &entry_name, entry)?;
                }
                let json_val = serde_json::to_value(&index_data).map_err(std::io::Error::other)?;
                Self::atomic_write_json_sync(&index_path, &json_val, true)?;
            }
        }

        let cache_key = (bucket_name.to_string(), key.to_string());
        self.meta_read_cache.lock().pop(&cache_key);

        Ok(())
    }

    pub(super) fn write_sidecar_file(
        &self,
        sidecar_path: &Path,
        entry_name: &str,
        entry: &HashMap<String, Value>,
    ) -> std::io::Result<()> {
        let mut sidecar_entry = entry.clone();
        sidecar_entry.insert(
            SIDECAR_ENTRY_NAME_FIELD.to_string(),
            Value::String(entry_name.to_string()),
        );
        let json_val = serde_json::to_value(&sidecar_entry).map_err(std::io::Error::other)?;
        let lock = self.get_meta_index_lock(&sidecar_path.to_string_lossy());
        let _guard = lock.lock();
        Self::atomic_write_json_sync(sidecar_path, &json_val, true)
    }

    pub(super) fn delete_index_entry_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<()> {
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "delete:metadata-remove")?;
        let (index_path, entry_name) = self.index_file_for_key(bucket_name, key);
        let (sidecar_path, _) = self.sidecar_file_for_key(bucket_name, key);
        if sidecar_path.exists() {
            let lock = self.get_meta_index_lock(&sidecar_path.to_string_lossy());
            let _guard = lock.lock();
            std::fs::remove_file(&sidecar_path)?;
        }
        self.remove_index_entry_best_effort(&index_path, &entry_name);

        let cache_key = (bucket_name.to_string(), key.to_string());
        self.meta_read_cache.lock().pop(&cache_key);
        Ok(())
    }

    pub(super) fn remove_index_entry_best_effort(&self, index_path: &Path, entry_name: &str) {
        if !index_path.exists() {
            return;
        }
        let lock = self.get_meta_index_lock(&index_path.to_string_lossy());
        let _guard = lock.lock();
        let text = match std::fs::read_to_string(index_path) {
            Ok(text) => text,
            Err(err) => {
                tracing::warn!(
                    "failed to read metadata index {} while removing entry {}: {}",
                    index_path.display(),
                    entry_name,
                    err
                );
                return;
            }
        };
        let mut index_data: HashMap<String, Value> = match serde_json::from_str(&text) {
            Ok(data) => data,
            Err(err) => {
                tracing::warn!(
                    "corrupt metadata index {} left untouched while removing entry {}: {}",
                    index_path.display(),
                    entry_name,
                    err
                );
                return;
            }
        };
        if index_data.remove(entry_name).is_none() {
            return;
        }
        let result = if index_data.is_empty() {
            std::fs::remove_file(index_path)
        } else {
            serde_json::to_value(&index_data)
                .map_err(std::io::Error::other)
                .and_then(|json_val| Self::atomic_write_json_sync(index_path, &json_val, true))
        };
        if let Err(err) = result {
            tracing::warn!(
                "failed to update metadata index {} after removing entry {}: {}",
                index_path.display(),
                entry_name,
                err
            );
        }
    }

    pub(super) fn read_metadata_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> HashMap<String, String> {
        if let Some(entry) = self.read_index_entry_sync(bucket_name, key) {
            if let Some(Value::Object(meta)) = entry.get("metadata") {
                return meta
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect();
            }
        }

        for meta_file in [
            self.bucket_meta_root(bucket_name)
                .join(format!("{}.meta.json", key)),
            self.legacy_metadata_file(bucket_name, key),
        ] {
            if meta_file.exists() {
                if let Ok(content) = std::fs::read_to_string(&meta_file) {
                    if let Ok(payload) = serde_json::from_str::<Value>(&content) {
                        if let Some(Value::Object(meta)) = payload.get("metadata") {
                            return meta
                                .iter()
                                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                                .collect();
                        }
                    }
                }
            }
        }

        HashMap::new()
    }

    pub(super) fn write_metadata_sync(
        &self,
        bucket_name: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> std::io::Result<()> {
        if metadata.is_empty() {
            return self.delete_index_entry_sync(bucket_name, key);
        }

        let mut entry = HashMap::new();
        let meta_value = serde_json::to_value(metadata).map_err(std::io::Error::other)?;
        entry.insert("metadata".to_string(), meta_value);
        self.write_index_entry_sync(bucket_name, key, &entry)?;

        let old_meta = self
            .bucket_meta_root(bucket_name)
            .join(format!("{}.meta.json", key));
        if old_meta.exists() {
            let _ = std::fs::remove_file(&old_meta);
        }

        Ok(())
    }

    pub(super) fn stage_live_metadata_sync(
        &self,
        bucket_name: &str,
        key: &str,
        metadata: &HashMap<String, String>,
        tags: Option<&[Tag]>,
    ) -> std::io::Result<PathBuf> {
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "put:stage-sidecar")?;
        let (_, entry_name) = self.sidecar_file_for_key(bucket_name, key);
        let meta_value = serde_json::to_value(metadata).map_err(std::io::Error::other)?;
        let mut entry = serde_json::Map::new();
        entry.insert("metadata".to_string(), meta_value);
        if let Some(tags) = tags {
            if !tags.is_empty() {
                entry.insert(
                    "tags".to_string(),
                    serde_json::to_value(tags).map_err(std::io::Error::other)?,
                );
            }
        }
        entry.insert(
            SIDECAR_ENTRY_NAME_FIELD.to_string(),
            Value::String(entry_name),
        );
        entry.insert(
            SIDECAR_COMMIT_BUCKET_FIELD.to_string(),
            Value::String(bucket_name.to_string()),
        );
        entry.insert(
            SIDECAR_COMMIT_KEY_FIELD.to_string(),
            Value::String(key.to_string()),
        );
        let tmp_dir = self.tmp_dir();
        std::fs::create_dir_all(&tmp_dir)?;
        if !self
            .tmp_dir_durable
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let chain_result = (|| -> std::io::Result<()> {
                Self::fsync_dir(&tmp_dir)?;
                if let Some(parent) = tmp_dir.parent() {
                    Self::fsync_dir(parent)?;
                    if let Some(grandparent) = parent.parent() {
                        Self::fsync_dir(grandparent)?;
                    }
                }
                Ok(())
            })();
            if let Err(err) = chain_result {
                self.tmp_dir_durable
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                return Err(err);
            }
        }
        let staged_path = tmp_dir.join(format!("{}.sidecar-stage", Uuid::new_v4()));
        let write_result = (|| -> std::io::Result<()> {
            let file = std::fs::File::create(&staged_path)?;
            let mut writer = std::io::BufWriter::new(file);
            serde_json::to_writer(&mut writer, &Value::Object(entry))
                .map_err(std::io::Error::other)?;
            let file = writer.into_inner()?;
            file.sync_all()?;
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "put:stage-dir-fsync")?;
            Self::fsync_dir(&tmp_dir)?;
            Ok(())
        })();
        match write_result {
            Ok(()) => Ok(staged_path),
            Err(err) => {
                let _ = std::fs::remove_file(&staged_path);
                Err(err)
            }
        }
    }

    pub(super) fn publish_staged_metadata_sync(
        &self,
        bucket_name: &str,
        key: &str,
        staged_path: &Path,
    ) -> std::io::Result<()> {
        let (sidecar_path, _) = self.sidecar_file_for_key(bucket_name, key);
        if let Some(parent) = sidecar_path.parent() {
            Self::create_publish_dir_sync(parent)?;
        }
        {
            let lock = self.get_meta_index_lock(&sidecar_path.to_string_lossy());
            let _guard = lock.lock();
            self.publish_by_rename_sync(staged_path, &sidecar_path)?;
            if let Some(parent) = sidecar_path.parent() {
                Self::fsync_dir(parent)?;
            }
        }
        let old_meta = self
            .bucket_meta_root(bucket_name)
            .join(format!("{}.meta.json", key));
        if old_meta.exists() {
            let _ = std::fs::remove_file(&old_meta);
        }
        let cache_key = (bucket_name.to_string(), key.to_string());
        self.meta_read_cache.lock().pop(&cache_key);
        Ok(())
    }

    pub(super) fn write_live_metadata_entry_sync(
        &self,
        bucket_name: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> StorageResult<()> {
        let mut entry = self
            .read_index_entry_sync(bucket_name, key)
            .unwrap_or_default();
        let meta_map: serde_json::Map<String, Value> = metadata
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        entry.insert("metadata".to_string(), Value::Object(meta_map));
        self.write_index_entry_sync(bucket_name, key, &entry)
            .map_err(StorageError::Io)?;
        self.invalidate_bucket_caches(bucket_name);
        self.update_listing_index_after_commit(bucket_name, key);
        Ok(())
    }

    pub(super) fn mutate_object_metadata_locked_sync<F>(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: Option<&str>,
        mutate: F,
    ) -> StorageResult<()>
    where
        F: FnOnce(&mut HashMap<String, String>) -> StorageResult<()>,
    {
        self.require_bucket(bucket_name)?;
        self.validate_key(key)?;
        if version_id.is_some() {
            self.guard_versioned_key_casing(bucket_name, key)?;
        } else {
            self.guard_object_casing(bucket_name, key)?;
        }

        let Some(version_id) = version_id else {
            let mut metadata = self.read_metadata_sync(bucket_name, key);
            mutate(&mut metadata)?;
            return self.write_live_metadata_entry_sync(bucket_name, key, &metadata);
        };

        Self::validate_version_id(bucket_name, key, version_id)?;
        if self
            .try_live_version_record_sync(bucket_name, key, version_id)
            .is_some()
        {
            let mut metadata = self.read_metadata_sync(bucket_name, key);
            mutate(&mut metadata)?;
            return self.write_live_metadata_entry_sync(bucket_name, key, &metadata);
        }

        let (manifest_path, _data_path) = self.version_record_paths(bucket_name, key, version_id);
        if !manifest_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }
        let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let mut record: Value = serde_json::from_str(&content).map_err(StorageError::Json)?;
        let mut metadata = Self::version_metadata_from_record(&record);
        mutate(&mut metadata)?;
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
        crate::failpoints::hit(&self.root, "metadata:version-rewrite").map_err(StorageError::Io)?;
        Self::atomic_write_json_sync(&manifest_path, &record, true).map_err(StorageError::Io)?;
        self.invalidate_bucket_caches(bucket_name);
        Ok(())
    }

    pub(super) fn delete_metadata_sync(&self, bucket_name: &str, key: &str) -> std::io::Result<()> {
        self.delete_index_entry_sync(bucket_name, key)?;

        for meta_file in [
            self.bucket_meta_root(bucket_name)
                .join(format!("{}.meta.json", key)),
            self.legacy_metadata_file(bucket_name, key),
        ] {
            if meta_file.exists() {
                let _ = std::fs::remove_file(&meta_file);
            }
        }

        Ok(())
    }

    pub async fn delete_object_metadata_entry(&self, bucket: &str, key: &str) -> StorageResult<()> {
        run_blocking(|| {
            let _guard = self.get_object_lock(bucket, key).write();
            self.guard_object_casing(bucket, key)?;
            self.delete_metadata_sync(bucket, key)
                .map_err(StorageError::Io)?;
            if self.listing_index_enabled {
                self.invalidate_bucket_caches(bucket);
            }
            self.update_listing_index_after_commit(bucket, key);
            Ok(())
        })
    }
}
