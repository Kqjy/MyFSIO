use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct ManifestPart {
    pub(super) etag: String,
    pub(super) size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) part_file_mtime_nanos: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(super) struct MultipartManifest {
    pub(super) object_key: String,
    pub(super) metadata: HashMap<String, String>,
    pub(super) parts: BTreeMap<u32, ManifestPart>,
}

#[derive(Debug)]
pub struct PreparedMultipartUpload {
    pub object_key: String,
    pub plaintext_path: PathBuf,
    pub composite_etag: String,
    pub plaintext_size: u64,
    pub part_sizes: Vec<u64>,
    pub metadata: HashMap<String, String>,
    pub(super) bucket: String,
    pub(super) upload_id: String,
    pub(super) selected_parts: Vec<(u32, String, u64)>,
}

impl MultipartManifest {
    pub(super) fn read_sync(manifest_path: &Path) -> StorageResult<Self> {
        let content = std::fs::read_to_string(manifest_path).map_err(StorageError::Io)?;
        let mut manifest: Self = serde_json::from_str(&content).map_err(|e| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "multipart manifest {} is malformed and cannot be trusted for completion: {}",
                    manifest_path.display(),
                    e
                ),
            ))
        })?;
        let upload_dir = manifest_path.parent().ok_or_else(|| {
            StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "multipart manifest has no parent directory",
            ))
        })?;
        let entries = std::fs::read_dir(upload_dir).map_err(StorageError::Io)?;
        for entry in entries {
            let entry = entry.map_err(StorageError::Io)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(part_number) = Self::part_record_number(&name) else {
                continue;
            };
            let content = std::fs::read_to_string(entry.path()).map_err(StorageError::Io)?;
            let part = serde_json::from_str::<ManifestPart>(&content).map_err(|error| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "multipart part record {} is malformed and cannot be trusted: {}",
                        entry.path().display(),
                        error
                    ),
                ))
            })?;
            manifest.parts.insert(part_number, part);
        }
        Ok(manifest)
    }

    pub(super) fn part_record_number(name: &str) -> Option<u32> {
        let number = name.strip_prefix("part-")?.strip_suffix(".json")?;
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        number.parse().ok()
    }
}

impl FsStorageBackend {
    pub(super) fn part_record_path(upload_dir: &Path, part_number: u32) -> PathBuf {
        upload_dir.join(format!("part-{:05}.json", part_number))
    }

    pub(super) fn part_data_path(upload_dir: &Path, part_number: u32) -> PathBuf {
        upload_dir.join(format!("part-{:05}.part", part_number))
    }

    pub(super) fn part_file_mtime_nanos(part_file: &Path) -> Option<u64> {
        std::fs::metadata(part_file)
            .and_then(|meta| meta.modified())
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|since_epoch| since_epoch.as_nanos() as u64)
    }

    pub(super) fn part_record_describes_file(
        record: &ManifestPart,
        part_file: &Path,
        file_size: u64,
    ) -> bool {
        if record.size != file_size {
            return false;
        }
        match (
            record.part_file_mtime_nanos,
            Self::part_file_mtime_nanos(part_file),
        ) {
            (Some(recorded), Some(current)) => recorded == current,
            _ => false,
        }
    }

    pub(super) fn publish_part_record_sync(
        &self,
        upload_dir: &Path,
        part_number: u32,
        etag: &str,
        size: u64,
    ) -> std::io::Result<()> {
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "mpu:part-record-write")?;
        let record = serde_json::to_value(ManifestPart {
            etag: etag.to_string(),
            size,
            part_file_mtime_nanos: Self::part_file_mtime_nanos(&Self::part_data_path(
                upload_dir,
                part_number,
            )),
        })
        .map_err(std::io::Error::other)?;
        Self::atomic_write_json_sync(
            &Self::part_record_path(upload_dir, part_number),
            &record,
            true,
        )
    }

    pub(super) fn read_part_record_sync(upload_dir: &Path, part_number: u32) -> Option<Value> {
        let content =
            std::fs::read_to_string(Self::part_record_path(upload_dir, part_number)).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub(super) fn restore_displaced_part_record(
        upload_dir: &Path,
        part_number: u32,
        displaced_record: Option<Value>,
    ) {
        let Some(record) = displaced_record else {
            return;
        };
        if !Self::part_data_path(upload_dir, part_number).exists() {
            return;
        }
        if let Err(error) = Self::atomic_write_json_sync(
            &Self::part_record_path(upload_dir, part_number),
            &record,
            true,
        ) {
            tracing::error!(
                upload_dir = %upload_dir.display(),
                part_number,
                "failed to restore the displaced part record after a failed replacement; the \
                 part's bytes are intact but it will not be listed until it is re-uploaded: {}",
                error
            );
        }
    }

    pub(super) fn retract_part_record_sync(
        root: &Path,
        upload_dir: &Path,
        part_number: u32,
    ) -> std::io::Result<()> {
        let _ = root;
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(root, "mpu:part-record-retract")?;
        match std::fs::remove_file(Self::part_record_path(upload_dir, part_number)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        Self::retract_legacy_manifest_part_sync(root, upload_dir, part_number)?;
        Self::fsync_dir(upload_dir)
    }

    pub(super) fn retract_legacy_manifest_part_sync(
        root: &Path,
        upload_dir: &Path,
        part_number: u32,
    ) -> std::io::Result<()> {
        let _ = root;
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        let content = match std::fs::read_to_string(&manifest_path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let Ok(mut manifest) = serde_json::from_str::<Value>(&content) else {
            return Ok(());
        };
        let Some(parts) = manifest.get_mut("parts").and_then(Value::as_object_mut) else {
            return Ok(());
        };
        let stale_keys: Vec<String> = parts
            .keys()
            .filter(|key| key.parse::<u32>().ok() == Some(part_number))
            .cloned()
            .collect();
        if stale_keys.is_empty() {
            return Ok(());
        }
        for key in stale_keys {
            parts.remove(&key);
        }
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(root, "mpu:part-record-retract-manifest")?;
        Self::atomic_write_json_sync(&manifest_path, &manifest, true)
    }

    pub async fn prepare_multipart_for_transform(
        &self,
        bucket: &str,
        upload_id: &str,
        parts: &[PartInfo],
    ) -> StorageResult<PreparedMultipartUpload> {
        let (upload_dir, manifest_path) = run_blocking(|| {
            let upload_dir = self.multipart_upload_dir(bucket, upload_id)?;
            let manifest_path = upload_dir.join(MANIFEST_FILE);
            if !manifest_path.exists() {
                return Err(StorageError::UploadNotFound(upload_id.to_string()));
            }
            Ok((upload_dir, manifest_path))
        })?;

        let tmp_dir = self.tmp_dir();
        tokio::fs::create_dir_all(&tmp_dir)
            .await
            .map_err(StorageError::Io)?;
        let plaintext_path = tmp_dir.join(format!("{}.tmp", Uuid::new_v4()));
        let plaintext_path_owned = plaintext_path.clone();
        let upload_dir_owned = upload_dir.clone();
        let manifest_path_owned = manifest_path.clone();
        let part_infos = parts.to_vec();
        let chunk_size = self.stream_chunk_size;
        let upload_lock =
            self.get_meta_index_lock(&upload_dir.join(".manifest.lock").to_string_lossy());
        #[cfg(any(test, feature = "failpoints"))]
        let fp_root = self.root.clone();

        let assemble = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Write};
            let _guard = upload_lock.lock();
            let manifest = MultipartManifest::read_sync(&manifest_path_owned)?;
            let mut output =
                std::fs::File::create(&plaintext_path_owned).map_err(StorageError::Io)?;
            let mut digest_concat = Vec::with_capacity(part_infos.len() * 16);
            let mut total_size = 0u64;
            let mut part_sizes = Vec::with_capacity(part_infos.len());
            let mut selected_parts = Vec::with_capacity(part_infos.len());
            let mut buffer = vec![0u8; chunk_size];

            for part_info in &part_infos {
                #[cfg(any(test, feature = "failpoints"))]
                crate::failpoints::hit(&fp_root, "mpu:during-assembly")
                    .map_err(StorageError::Io)?;
                let part_file =
                    FsStorageBackend::part_data_path(&upload_dir_owned, part_info.part_number);
                let file_size = std::fs::metadata(&part_file)
                    .map_err(StorageError::Io)?
                    .len();
                let manifest_part =
                    manifest.parts.get(&part_info.part_number).ok_or_else(|| {
                        StorageError::InvalidObjectKey(format!(
                            "Part {} not found",
                            part_info.part_number
                        ))
                    })?;
                let mut input = std::fs::File::open(&part_file).map_err(StorageError::Io)?;
                let mut copied = 0u64;
                let mut hasher = Md5::new();
                loop {
                    let count = input.read(&mut buffer).map_err(StorageError::Io)?;
                    if count == 0 {
                        break;
                    }
                    output
                        .write_all(&buffer[..count])
                        .map_err(StorageError::Io)?;
                    hasher.update(&buffer[..count]);
                    copied += count as u64;
                }
                if copied != file_size || file_size != manifest_part.size {
                    return Err(StorageError::Internal(format!(
                        "Part {} changed while completing the multipart upload",
                        part_info.part_number
                    )));
                }
                let digest: [u8; 16] = hasher.finalize().into();
                digest_concat.extend_from_slice(&digest);
                total_size += file_size;
                part_sizes.push(file_size);
                selected_parts.push((
                    part_info.part_number,
                    manifest_part.etag.clone(),
                    manifest_part.size,
                ));
            }
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&fp_root, "mpu:assembly-sync").map_err(StorageError::Io)?;
            output.sync_all().map_err(StorageError::Io)?;
            let mut composite_hasher = Md5::new();
            composite_hasher.update(&digest_concat);
            let composite_etag = format!("{:x}-{}", composite_hasher.finalize(), part_infos.len());
            Ok::<_, StorageError>((
                manifest,
                composite_etag,
                total_size,
                part_sizes,
                selected_parts,
            ))
        })
        .await;

        let (manifest, composite_etag, plaintext_size, part_sizes, selected_parts) = match assemble
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                let _ = std::fs::remove_file(&plaintext_path);
                return Err(error);
            }
            Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
            Err(join) => {
                let _ = std::fs::remove_file(&plaintext_path);
                return Err(StorageError::Io(std::io::Error::other(join)));
            }
        };

        #[cfg(any(test, feature = "failpoints"))]
        if let Err(error) = crate::failpoints::hit(&self.root, "mpu:after-assembly") {
            let _ = std::fs::remove_file(&plaintext_path);
            return Err(StorageError::Io(error));
        }

        let mut metadata = manifest.metadata;
        metadata.insert(
            META_KEY_PART_SIZES.to_string(),
            encode_part_sizes(&part_sizes),
        );
        Ok(PreparedMultipartUpload {
            object_key: manifest.object_key,
            plaintext_path,
            composite_etag,
            plaintext_size,
            part_sizes,
            metadata,
            bucket: bucket.to_string(),
            upload_id: upload_id.to_string(),
            selected_parts,
        })
    }

    pub async fn commit_transformed_multipart(
        &self,
        prepared: &PreparedMultipartUpload,
        transformed_path: &Path,
        stored_size: u64,
        metadata: HashMap<String, String>,
        mut options: crate::traits::PutCommitOptions,
    ) -> StorageResult<ObjectMeta> {
        if metadata_has_pending_sse(&metadata)
            || metadata.contains_key(crate::segments::META_KEY_SEGMENTS)
        {
            return Err(StorageError::InvalidArgument(
                "transformed multipart metadata is not final".to_string(),
            ));
        }
        if prepared.bucket.is_empty()
            || prepared.upload_id.is_empty()
            || transformed_path.parent() != Some(self.tmp_dir().as_path())
        {
            return Err(StorageError::InvalidArgument(
                "prepared multipart data must live in the storage tmp directory".to_string(),
            ));
        }
        let upload_dir = self.multipart_upload_dir(&prepared.bucket, &prepared.upload_id)?;
        let manifest_path = upload_dir.join(MANIFEST_FILE);
        let upload_lock =
            self.get_meta_index_lock(&upload_dir.join(".manifest.lock").to_string_lossy());
        options.etag_override = Some(prepared.composite_etag.clone());

        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "mpu:before-commit").map_err(StorageError::Io)?;

        let result = run_blocking(|| {
            let _upload_guard = upload_lock.lock();
            if !manifest_path.exists() {
                return Err(StorageError::UploadNotFound(prepared.upload_id.clone()));
            }
            let manifest = MultipartManifest::read_sync(&manifest_path)?;
            if manifest.object_key != prepared.object_key {
                return Err(StorageError::UploadNotFound(prepared.upload_id.clone()));
            }
            for (part_number, etag, size) in &prepared.selected_parts {
                let Some(current) = manifest.parts.get(part_number) else {
                    return Err(StorageError::PreconditionFailed(format!(
                        "Part {} changed while completing the multipart upload",
                        part_number
                    )));
                };
                if current.etag != *etag || current.size != *size {
                    return Err(StorageError::PreconditionFailed(format!(
                        "Part {} changed while completing the multipart upload",
                        part_number
                    )));
                }
            }
            let quota_lock = self.quota_lock_if_configured(&prepared.bucket);
            let _quota_guard = quota_lock.as_ref().map(|lock| lock.lock());
            let _object_guard = self
                .get_object_lock(&prepared.bucket, &prepared.object_key)
                .write();
            self.finalize_put_sync(
                &prepared.bucket,
                &prepared.object_key,
                transformed_path,
                prepared.composite_etag.clone(),
                stored_size,
                Some(metadata),
                &options,
            )
        });

        if result.is_ok() {
            #[cfg(any(test, feature = "failpoints"))]
            crate::failpoints::hit(&self.root, "mpu:after-commit").map_err(StorageError::Io)?;
            let _guard = upload_lock.lock();
            let _ = std::fs::remove_dir_all(upload_dir);
        }
        result
    }
}
