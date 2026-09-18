use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiskCasingVerdict {
    PathVerified,
    ComponentVerified,
    Aliased,
    Unlinked,
}

impl FsStorageBackend {
    pub(super) fn probe_case_insensitive_fs(&self) -> bool {
        let dir = self.tmp_dir();
        let _ = std::fs::create_dir_all(&dir);
        let name = format!(".case-probe-{}", Uuid::new_v4().simple());
        let lower = dir.join(&name);
        let upper = dir.join(name.to_ascii_uppercase());
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lower)
            .is_err()
        {
            return true;
        }
        let insensitive = upper.exists();
        let _ = std::fs::remove_file(&lower);
        insensitive
    }

    pub fn case_insensitive_fs(&self) -> bool {
        self.case_insensitive_fs
    }

    pub(super) fn verify_disk_casing(&self, expected: &Path) -> StorageResult<bool> {
        if !self.case_insensitive_fs {
            return Ok(true);
        }
        let canonical_root = match &self.canonical_root {
            Some(path) => path.clone(),
            None => std::fs::canonicalize(&self.root).map_err(StorageError::Io)?,
        };
        let mut probe = expected;
        loop {
            if !probe.starts_with(&self.root) {
                return Ok(false);
            }
            if probe == self.root.as_path() {
                return Ok(true);
            }
            match self.resolve_disk_casing(probe, &canonical_root)? {
                DiskCasingVerdict::PathVerified => return Ok(true),
                DiskCasingVerdict::Aliased => return Ok(false),
                DiskCasingVerdict::ComponentVerified | DiskCasingVerdict::Unlinked => {
                    match probe.parent() {
                        Some(parent) => probe = parent,
                        None => return Ok(true),
                    }
                }
            }
        }
    }

    pub(super) fn resolve_disk_casing(
        &self,
        probe: &Path,
        canonical_root: &Path,
    ) -> StorageResult<DiskCasingVerdict> {
        for _ in 0..DISK_CASING_RESOLVE_ATTEMPTS {
            let canonical = match std::fs::canonicalize(probe) {
                Ok(canonical) => canonical,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(DiskCasingVerdict::Unlinked);
                }
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Self::listed_entry_casing(probe);
                }
                Err(err) => return Err(StorageError::Io(err)),
            };
            let Ok(actual_rel) = canonical.strip_prefix(canonical_root) else {
                if Self::disk_entry_is_gone(probe) {
                    return Ok(DiskCasingVerdict::Unlinked);
                }
                continue;
            };
            let Ok(expected_rel) = probe.strip_prefix(&self.root) else {
                return Ok(DiskCasingVerdict::Aliased);
            };
            return Ok(if Self::path_components_match(expected_rel, actual_rel) {
                DiskCasingVerdict::PathVerified
            } else {
                DiskCasingVerdict::Aliased
            });
        }
        Ok(DiskCasingVerdict::Aliased)
    }

    pub(super) fn listed_entry_casing(probe: &Path) -> StorageResult<DiskCasingVerdict> {
        let (Some(parent), Some(name)) = (probe.parent(), probe.file_name()) else {
            return Ok(DiskCasingVerdict::Aliased);
        };
        let entries = match std::fs::read_dir(parent) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DiskCasingVerdict::Unlinked);
            }
            Err(err) => return Err(StorageError::Io(err)),
        };
        for entry in entries.flatten() {
            if entry.file_name() == name {
                return Ok(DiskCasingVerdict::ComponentVerified);
            }
        }
        Ok(if Self::disk_entry_is_gone(probe) {
            DiskCasingVerdict::Unlinked
        } else {
            DiskCasingVerdict::Aliased
        })
    }

    pub(super) fn disk_entry_is_gone(probe: &Path) -> bool {
        matches!(
            std::fs::symlink_metadata(probe),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound
        )
    }

    pub(super) fn path_components_match(expected_rel: &Path, actual_rel: &Path) -> bool {
        let mut expected_parts = expected_rel.components();
        let mut actual_parts = actual_rel.components();
        loop {
            match (expected_parts.next(), actual_parts.next()) {
                (Some(expected), Some(actual)) => {
                    if expected.as_os_str() != actual.as_os_str() {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    pub(super) fn guard_object_casing(
        &self,
        bucket_name: &str,
        object_key: &str,
    ) -> StorageResult<()> {
        if !self.case_insensitive_fs {
            return Ok(());
        }
        let live_path = self.object_live_path(bucket_name, object_key);
        let live_ok = self.verify_disk_casing(&live_path)?;
        let metadata_ok = if std::fs::symlink_metadata(&live_path).is_ok() {
            true
        } else {
            let (sidecar_path, _) = self.sidecar_file_for_key(bucket_name, object_key);
            self.verify_disk_casing(&sidecar_path)?
                && self.verify_disk_casing(&self.legacy_metadata_file(bucket_name, object_key))?
        };
        if live_ok && metadata_ok {
            return Ok(());
        }
        Err(StorageError::ObjectNotFound {
            bucket: bucket_name.to_string(),
            key: object_key.to_string(),
        })
    }

    pub(super) fn guard_versioned_key_casing(
        &self,
        bucket_name: &str,
        object_key: &str,
    ) -> StorageResult<()> {
        let live_ok = self.verify_disk_casing(&self.object_live_path(bucket_name, object_key))?;
        let version_ok = self.verify_disk_casing(&self.version_dir(bucket_name, object_key))?;
        if live_ok && version_ok {
            Ok(())
        } else {
            Err(StorageError::ObjectNotFound {
                bucket: bucket_name.to_string(),
                key: object_key.to_string(),
            })
        }
    }
}
