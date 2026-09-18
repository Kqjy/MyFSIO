use super::*;

impl FsStorageBackend {
    pub(super) fn version_dir(&self, bucket_name: &str, key: &str) -> PathBuf {
        let encoded = fs_encode_key(key);
        let trimmed = encoded.trim_end_matches('/');
        self.bucket_versions_root(bucket_name).join(trimmed)
    }

    pub(super) fn delete_markers_root(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name).join("delete_markers")
    }

    pub(super) fn delete_marker_path(&self, bucket_name: &str, key: &str) -> PathBuf {
        let encoded = fs_encode_key(key);
        let trimmed = encoded.trim_end_matches('/');
        self.delete_markers_root(bucket_name)
            .join(format!("{}.json", trimmed))
    }

    pub(super) fn read_delete_marker_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> Option<(String, chrono::DateTime<Utc>)> {
        let path = self.delete_marker_path(bucket_name, key);
        if !path.is_file() {
            return None;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        let record: Value = serde_json::from_str(&content).ok()?;
        let version_id = record
            .get("version_id")
            .and_then(Value::as_str)?
            .to_string();
        let last_modified = record
            .get("last_modified")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        Some((version_id, last_modified))
    }

    pub(super) fn clear_delete_marker_sync(&self, bucket_name: &str, key: &str) {
        let path = self.delete_marker_path(bucket_name, key);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    pub(super) fn new_version_id_sync() -> String {
        let now = Utc::now();
        format!(
            "{}-{}",
            now.format("%Y%m%dT%H%M%S%6fZ"),
            &Uuid::new_v4().to_string()[..8]
        )
    }

    pub(super) fn archive_current_version_sync(
        &self,
        bucket_name: &str,
        key: &str,
        reason: &str,
    ) -> std::io::Result<Option<VersionMutation>> {
        let source = self.object_live_path(bucket_name, key);
        if !source.exists() {
            return Ok(None);
        }
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "version:archive-write")?;

        let version_dir = self.version_dir(bucket_name, key);
        std::fs::create_dir_all(&version_dir)?;

        let now = Utc::now();
        let metadata = self.read_metadata_sync(bucket_name, key);
        let raw_vid = metadata
            .get("__version_id__")
            .map(String::as_str)
            .unwrap_or("");
        let version_id = if raw_vid.is_empty() {
            "null".to_string()
        } else if raw_vid.contains('/') || raw_vid.contains('\\') || raw_vid.contains("..") {
            Self::new_version_id_sync()
        } else {
            raw_vid.to_string()
        };

        let data_path = version_dir.join(format!("{}.bin", version_id));
        if data_path.exists() {
            Self::safe_unlink(&data_path)?;
        }
        let source_meta = source.metadata()?;

        let stub_header = if metadata.contains_key(crate::segments::META_KEY_SEGMENTS) {
            crate::segments::read_stub_header(&source).unwrap_or(None)
        } else {
            None
        };
        let (source_size, etag, segment_id) = match stub_header {
            Some(header) => {
                crate::segments::write_stub(&data_path, &header)?;
                (header.total, header.etag.clone(), Some(header.segment_id))
            }
            None => {
                if std::fs::hard_link(&source, &data_path).is_err() {
                    std::fs::copy(&source, &data_path)?;
                }
                let etag = metadata
                    .get("__etag__")
                    .cloned()
                    .filter(|e| !e.is_empty())
                    .or_else(|| Self::compute_etag_sync(&source).ok())
                    .unwrap_or_default();
                (source_meta.len(), etag, None)
            }
        };

        let live_last_modified = metadata
            .get("__last_modified__")
            .and_then(|value| value.parse::<f64>().ok())
            .map(|mtime| {
                Utc.timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
                    .single()
                    .unwrap_or_else(Utc::now)
            })
            .or_else(|| {
                source_meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        Utc.timestamp_opt(d.as_secs() as i64, d.subsec_nanos())
                            .single()
                            .unwrap_or_else(Utc::now)
                    })
            })
            .unwrap_or(now);

        let live_tags = self
            .read_index_entry_sync(bucket_name, key)
            .and_then(|entry| entry.get("tags").cloned())
            .unwrap_or(Value::Array(Vec::new()));

        let mut record = serde_json::json!({
            "version_id": version_id,
            "key": key,
            "size": source_size,
            "archived_at": now.to_rfc3339(),
            "last_modified": live_last_modified.to_rfc3339(),
            "etag": etag,
            "metadata": metadata,
            "tags": live_tags,
            "reason": reason,
        });
        if let Some(seg_id) = segment_id {
            record["segment_id"] = Value::String(seg_id);
        }

        let manifest_path = version_dir.join(format!("{}.json", version_id));
        if let Err(error) = Self::atomic_write_json_sync(&manifest_path, &record, true) {
            let _ = Self::safe_unlink(&data_path);
            self.cleanup_empty_parents(&manifest_path, &self.bucket_versions_root(bucket_name));
            return Err(error);
        }

        Ok(Some(VersionMutation {
            version_id,
            kind: VersionMutationKind::Archive,
            logical_size: source_size,
            delete_marker: false,
        }))
    }

    pub(super) fn promote_latest_archived_to_live_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<Option<VersionMutation>> {
        let version_dir = self.version_dir(bucket_name, key);
        if !version_dir.exists() {
            return Ok(None);
        }

        let entries = match std::fs::read_dir(&version_dir) {
            Ok(e) => e,
            Err(_) => return Ok(None),
        };

        let mut candidates: Vec<(DateTime<Utc>, String, PathBuf, Value)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(record) = serde_json::from_str::<Value>(&content) else {
                continue;
            };
            if record
                .get("is_delete_marker")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            let version_id = record
                .get("version_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if version_id.is_empty() {
                continue;
            }
            let archived_at = record
                .get("archived_at")
                .and_then(Value::as_str)
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now);
            candidates.push((archived_at, version_id, path, record));
        }

        candidates.sort_by(|a, b| b.0.cmp(&a.0));
        let Some((_, version_id, manifest_path, record)) = candidates.into_iter().next() else {
            return Ok(None);
        };

        let (_, data_path) = self.version_record_paths(bucket_name, key, &version_id);
        if !data_path.is_file() {
            return Ok(None);
        }

        let live_path = self.object_live_path(bucket_name, key);
        if let Some(parent) = live_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if live_path.exists() {
            std::fs::remove_file(&live_path).ok();
        }
        std::fs::rename(&data_path, &live_path)?;

        let mut meta: HashMap<String, String> = record
            .get("metadata")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        meta.insert("__version_id__".to_string(), version_id.clone());
        if !meta.contains_key("__etag__") {
            if let Some(etag) = record.get("etag").and_then(Value::as_str) {
                if !etag.is_empty() {
                    meta.insert("__etag__".to_string(), etag.to_string());
                }
            }
        }
        self.write_metadata_sync(bucket_name, key, &meta)?;

        Self::safe_unlink(&manifest_path)?;
        self.cleanup_empty_parents(&manifest_path, &self.bucket_versions_root(bucket_name));

        let logical_size = record.get("size").and_then(Value::as_u64).unwrap_or(0);
        Ok(Some(VersionMutation {
            version_id,
            kind: VersionMutationKind::Restore,
            logical_size,
            delete_marker: false,
        }))
    }

    pub(super) fn write_delete_marker_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<String> {
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "delete:marker-write")?;
        let version_dir = self.version_dir(bucket_name, key);
        std::fs::create_dir_all(&version_dir)?;
        let now = Utc::now();
        let version_id = Self::new_version_id_sync();

        let record = serde_json::json!({
            "version_id": version_id,
            "key": key,
            "size": 0,
            "archived_at": now.to_rfc3339(),
            "etag": "",
            "metadata": HashMap::<String, String>::new(),
            "reason": "delete-marker",
            "is_delete_marker": true,
        });

        let manifest_path = version_dir.join(format!("{}.json", version_id));
        Self::atomic_write_json_sync(&manifest_path, &record, true)?;

        let marker_path = self.delete_marker_path(bucket_name, key);
        if let Some(parent) = marker_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let marker_record = serde_json::json!({
            "version_id": version_id,
            "last_modified": now.to_rfc3339(),
        });
        Self::atomic_write_json_sync(&marker_path, &marker_record, true)?;
        Ok(version_id)
    }

    pub(super) fn version_record_paths(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> (PathBuf, PathBuf) {
        let version_dir = self.version_dir(bucket_name, key);
        (
            version_dir.join(format!("{}.json", version_id)),
            version_dir.join(format!("{}.bin", version_id)),
        )
    }

    pub(super) fn purge_archived_null_version_sync(
        &self,
        bucket_name: &str,
        key: &str,
    ) -> std::io::Result<Option<VersionMutation>> {
        let (manifest_path, data_path) = self.version_record_paths(bucket_name, key, "null");
        let record = std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|content| serde_json::from_str::<Value>(&content).ok());
        let logical_size = record
            .as_ref()
            .and_then(|record| record.get("size").and_then(Value::as_u64))
            .or_else(|| {
                std::fs::metadata(&data_path)
                    .ok()
                    .map(|metadata| metadata.len())
            });
        let delete_marker = record
            .as_ref()
            .and_then(|record| record.get("is_delete_marker").and_then(Value::as_bool))
            .unwrap_or(false);
        if manifest_path.is_file() {
            if let Some(seg_id) = record.as_ref().and_then(|record| {
                record
                    .get("segment_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }) {
                self.release_segment_dir(bucket_name, &seg_id);
            }
            Self::safe_unlink(&manifest_path)?;
        }
        if data_path.is_file() {
            Self::safe_unlink(&data_path)?;
        }
        let versions_root = self.bucket_versions_root(bucket_name);
        self.cleanup_empty_parents(&manifest_path, &versions_root);
        Ok(logical_size.map(|logical_size| VersionMutation {
            version_id: "null".to_string(),
            kind: if delete_marker {
                VersionMutationKind::DeleteMarkerRemove
            } else {
                VersionMutationKind::Purge
            },
            logical_size,
            delete_marker,
        }))
    }

    pub(super) fn validate_version_id(
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<()> {
        const MAX_VERSION_ID_LEN: usize = 128;
        let invalid = version_id.is_empty()
            || version_id.len() > MAX_VERSION_ID_LEN
            || version_id == "."
            || version_id == ".."
            || !version_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
        if invalid {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }
        Ok(())
    }

    pub(super) fn read_version_record_sync(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> StorageResult<(Value, PathBuf)> {
        self.require_bucket(bucket_name)?;
        self.validate_key(key)?;
        self.guard_versioned_key_casing(bucket_name, key)?;
        Self::validate_version_id(bucket_name, key, version_id)?;

        if let Some(record_and_path) =
            self.try_live_version_record_sync(bucket_name, key, version_id)
        {
            return Ok(record_and_path);
        }

        let (manifest_path, data_path) = self.version_record_paths(bucket_name, key, version_id);
        if !manifest_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }

        let content = std::fs::read_to_string(&manifest_path).map_err(StorageError::Io)?;
        let record = serde_json::from_str::<Value>(&content).map_err(StorageError::Json)?;
        let is_delete_marker = record
            .get("is_delete_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !is_delete_marker && !data_path.is_file() {
            return Err(StorageError::VersionNotFound {
                bucket: bucket_name.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            });
        }
        Ok((record, data_path))
    }

    pub(super) fn try_live_version_record_sync(
        &self,
        bucket_name: &str,
        key: &str,
        version_id: &str,
    ) -> Option<(Value, PathBuf)> {
        let live_path = self.object_live_path(bucket_name, key);
        if !live_path.is_file() {
            return None;
        }
        let metadata = self.read_metadata_sync(bucket_name, key);
        let stored_version = metadata.get("__version_id__").map(String::as_str);
        let matches = if version_id == "null" {
            stored_version.is_none_or(|v| v.is_empty() || v == "null")
        } else {
            stored_version == Some(version_id)
        };
        if !matches {
            return None;
        }
        let live_version = stored_version.unwrap_or("null").to_string();
        let file_meta = std::fs::metadata(&live_path).ok()?;
        let mtime = file_meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let archived_at = Utc
            .timestamp_opt(mtime as i64, ((mtime % 1.0) * 1_000_000_000.0) as u32)
            .single()
            .unwrap_or_else(Utc::now);
        let etag = metadata.get("__etag__").cloned().unwrap_or_default();
        let mut meta_json = serde_json::Map::new();
        for (k, v) in &metadata {
            meta_json.insert(k.clone(), Value::String(v.clone()));
        }
        let tags = self
            .read_index_entry_sync(bucket_name, key)
            .and_then(|entry| entry.get("tags").cloned())
            .unwrap_or(Value::Null);
        let record = serde_json::json!({
            "version_id": live_version,
            "key": key,
            "size": file_meta.len(),
            "archived_at": archived_at.to_rfc3339(),
            "etag": etag,
            "metadata": Value::Object(meta_json),
            "tags": tags,
            "reason": "current",
            "is_delete_marker": false,
        });
        Some((record, live_path))
    }

    pub(super) fn version_metadata_from_record(record: &Value) -> HashMap<String, String> {
        record
            .get("metadata")
            .and_then(Value::as_object)
            .map(|meta| {
                meta.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default()
    }

    pub(super) fn object_meta_from_version_record(
        &self,
        key: &str,
        record: &Value,
        data_path: &Path,
    ) -> StorageResult<ObjectMeta> {
        let metadata = Self::version_metadata_from_record(record);

        let data_len = std::fs::metadata(data_path)
            .map(|meta| meta.len())
            .unwrap_or_default();
        let size = record
            .get("size")
            .and_then(Value::as_u64)
            .unwrap_or(data_len);
        let last_modified = record
            .get("last_modified")
            .and_then(Value::as_str)
            .or_else(|| record.get("archived_at").and_then(Value::as_str))
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let etag = record
            .get("etag")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| metadata.get("__etag__").cloned());

        let version_id = record
            .get("version_id")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let is_delete_marker = record
            .get("is_delete_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let mut obj = ObjectMeta::new(key.to_string(), size, last_modified);
        obj.etag = etag;
        obj.content_type = metadata.get("__content_type__").cloned();
        obj.storage_class = metadata
            .get("__storage_class__")
            .cloned()
            .or_else(|| Some("STANDARD".to_string()));
        obj.metadata = metadata
            .iter()
            .filter(|(k, _)| !k.starts_with("__"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        obj.internal_metadata = metadata;
        obj.version_id = version_id;
        obj.is_delete_marker = is_delete_marker;
        Ok(obj)
    }

    pub(super) fn version_info_from_record(
        &self,
        fallback_key: &str,
        record: &Value,
    ) -> VersionInfo {
        let version_id = record
            .get("version_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let key = record
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or(fallback_key)
            .to_string();
        let size = record.get("size").and_then(Value::as_u64).unwrap_or(0);
        let last_modified = record
            .get("last_modified")
            .and_then(Value::as_str)
            .or_else(|| record.get("archived_at").and_then(Value::as_str))
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let etag = record
            .get("etag")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let is_delete_marker = record
            .get("is_delete_marker")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        VersionInfo {
            version_id,
            key,
            size,
            last_modified,
            etag,
            is_latest: false,
            is_delete_marker,
        }
    }
}
