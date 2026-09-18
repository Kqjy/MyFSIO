use super::*;

impl FsStorageBackend {
    pub fn preflight_meta_migration(&self) -> MetaMigrationPreflight {
        let mut preflight = MetaMigrationPreflight::default();
        let buckets_root = self.system_buckets_root();
        let Ok(buckets) = std::fs::read_dir(&buckets_root) else {
            return preflight;
        };
        for bucket_entry in buckets.flatten() {
            let meta_root = bucket_entry.path().join(BUCKET_META_DIR);
            if !meta_root.is_dir() {
                continue;
            }
            let mut stack = vec![meta_root];
            while let Some(dir) = stack.pop() {
                let Ok(read_dir) = std::fs::read_dir(&dir) else {
                    preflight
                        .corrupt
                        .push(format!("unreadable directory {}", dir.display()));
                    continue;
                };
                let mut index_path = None;
                for dirent in read_dir.flatten() {
                    let path = dirent.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if dirent.file_name() == INDEX_FILE {
                        index_path = Some(path);
                    }
                }
                let Some(index_path) = index_path else {
                    continue;
                };
                preflight.index_files += 1;
                let index: HashMap<String, Value> = match std::fs::read_to_string(&index_path)
                    .map_err(|e| e.to_string())
                    .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
                {
                    Ok(index) => index,
                    Err(err) => {
                        preflight
                            .corrupt
                            .push(format!("{}: {}", index_path.display(), err));
                        continue;
                    }
                };
                let mut names_in_dir: HashMap<String, String> = HashMap::new();
                for entry_name in index.keys() {
                    preflight.entries += 1;
                    let sidecar_name = Self::sidecar_file_name(entry_name);
                    if let Some(previous) =
                        names_in_dir.insert(sidecar_name.clone(), entry_name.clone())
                    {
                        preflight.collisions.push(format!(
                            "{}: entries '{}' and '{}' both map to sidecar {}",
                            index_path.display(),
                            previous,
                            entry_name,
                            sidecar_name
                        ));
                    }
                    let sidecar_path = dir.join(&sidecar_name);
                    if sidecar_path.exists() {
                        let matches = std::fs::read_to_string(&sidecar_path)
                            .ok()
                            .and_then(|s| serde_json::from_str::<HashMap<String, Value>>(&s).ok())
                            .and_then(|existing| {
                                Self::sidecar_entry_name_from_file(&sidecar_name, &existing)
                            })
                            .is_some_and(|name| name == *entry_name);
                        if !matches {
                            preflight.collisions.push(format!(
                                "{}: existing sidecar {} does not belong to entry '{}'",
                                index_path.display(),
                                sidecar_name,
                                entry_name
                            ));
                        }
                    }
                }
            }
        }
        preflight
    }

    pub fn migrate_meta_indexes_to_sidecars(&self) -> MetaMigrationReport {
        let mut report = MetaMigrationReport::default();
        let buckets_root = self.system_buckets_root();
        let Ok(buckets) = std::fs::read_dir(&buckets_root) else {
            return report;
        };
        for bucket_entry in buckets.flatten() {
            let meta_root = bucket_entry.path().join(BUCKET_META_DIR);
            if !meta_root.is_dir() {
                continue;
            }
            let mut stack = vec![meta_root];
            while let Some(dir) = stack.pop() {
                let Ok(read_dir) = std::fs::read_dir(&dir) else {
                    report
                        .failures
                        .push(format!("unreadable directory {}", dir.display()));
                    continue;
                };
                let mut index_path = None;
                for dirent in read_dir.flatten() {
                    let path = dirent.path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if dirent.file_name() == INDEX_FILE {
                        index_path = Some(path);
                    }
                }
                if let Some(index_path) = index_path {
                    self.migrate_one_index(&index_path, &mut report);
                }
            }
        }
        self.meta_read_cache.lock().clear();
        report
    }

    pub(super) fn migrate_one_index(&self, index_path: &Path, report: &mut MetaMigrationReport) {
        let lock = self.get_meta_index_lock(&index_path.to_string_lossy());
        let _guard = lock.lock();
        let text = match std::fs::read_to_string(index_path) {
            Ok(text) => text,
            Err(err) => {
                report.index_files_failed += 1;
                report
                    .failures
                    .push(format!("{}: read failed: {}", index_path.display(), err));
                return;
            }
        };
        let index: HashMap<String, Value> = match serde_json::from_str(&text) {
            Ok(index) => index,
            Err(err) => {
                report.index_files_failed += 1;
                report.failures.push(format!(
                    "{}: corrupt JSON (left in place): {}",
                    index_path.display(),
                    err
                ));
                return;
            }
        };
        let Some(dir) = index_path.parent() else {
            return;
        };
        let mut all_ok = true;
        for (entry_name, entry) in &index {
            let sidecar_path = dir.join(Self::sidecar_file_name(entry_name));
            if sidecar_path.exists() {
                let existing = std::fs::read_to_string(&sidecar_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<HashMap<String, Value>>(&s).ok());
                match existing {
                    Some(existing) => {
                        let sidecar_name = sidecar_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let matches = Self::sidecar_entry_name_from_file(&sidecar_name, &existing)
                            .as_deref()
                            == Some(entry_name.as_str());
                        if matches {
                            report.entries_skipped += 1;
                        } else {
                            all_ok = false;
                            report.failures.push(format!(
                                "{}: sidecar name collision for entry {}",
                                sidecar_path.display(),
                                entry_name
                            ));
                        }
                    }
                    None => {
                        all_ok = false;
                        report.failures.push(format!(
                            "{}: existing sidecar unreadable for entry {} (left in place)",
                            sidecar_path.display(),
                            entry_name
                        ));
                    }
                }
                continue;
            }
            let Some(entry_obj) = entry.as_object() else {
                all_ok = false;
                report.failures.push(format!(
                    "{}: entry {} is not an object",
                    index_path.display(),
                    entry_name
                ));
                continue;
            };
            let entry_map: HashMap<String, Value> = entry_obj
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            #[cfg(any(test, feature = "failpoints"))]
            if let Err(err) = crate::failpoints::hit(&self.root, "migrate:sidecar-write") {
                all_ok = false;
                report.failures.push(format!(
                    "{}: failed writing sidecar for {}: {}",
                    index_path.display(),
                    entry_name,
                    err
                ));
                continue;
            }
            match self.write_sidecar_file(&sidecar_path, entry_name, &entry_map) {
                Ok(()) => report.entries_written += 1,
                Err(err) => {
                    all_ok = false;
                    report.failures.push(format!(
                        "{}: failed writing sidecar for {}: {}",
                        index_path.display(),
                        entry_name,
                        err
                    ));
                }
            }
        }
        if all_ok {
            Self::fsync_dir_best_effort(dir);
            let backup_path = index_path.with_file_name(format!("{}.migrated", INDEX_FILE));
            match std::fs::rename(index_path, &backup_path) {
                Ok(()) => {
                    Self::fsync_dir_best_effort(dir);
                    report.index_files_migrated += 1;
                }
                Err(err) => {
                    report.index_files_failed += 1;
                    report.failures.push(format!(
                        "{}: sidecars written but moving the index aside failed: {}",
                        index_path.display(),
                        err
                    ));
                }
            }
        } else {
            report.index_files_failed += 1;
        }
    }
}
