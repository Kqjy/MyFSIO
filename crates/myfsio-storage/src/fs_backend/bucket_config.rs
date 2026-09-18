use super::*;

impl FsStorageBackend {
    pub(super) fn bucket_config_path(&self, bucket_name: &str) -> PathBuf {
        self.system_bucket_root(bucket_name)
            .join(BUCKET_CONFIG_FILE)
    }

    pub(super) fn legacy_bucket_policies_path(&self) -> PathBuf {
        self.system_root_path()
            .join("config")
            .join("bucket_policies.json")
    }

    pub(super) fn read_bucket_config_sync(&self, bucket_name: &str) -> BucketConfig {
        if validation::bucket_name_rejection(bucket_name).is_some() {
            return BucketConfig {
                unreadable: true,
                ..BucketConfig::default()
            };
        }

        if let Some(entry) = self.bucket_config_cache.get(bucket_name) {
            let (config, cached_at) = entry.value();
            if cached_at.elapsed() < self.bucket_config_cache_ttl {
                return config.clone();
            }
        }

        let config_path = self.bucket_config_path(bucket_name);
        let mut config = if config_path.exists() {
            match std::fs::read_to_string(&config_path)
                .ok()
                .and_then(|s| serde_json::from_str::<BucketConfig>(&s).ok())
            {
                Some(parsed) => parsed,
                None => {
                    tracing::error!(
                        bucket = bucket_name,
                        path = %config_path.display(),
                        "bucket config is unreadable or corrupt; treating it as fail-closed"
                    );
                    BucketConfig {
                        unreadable: true,
                        ..BucketConfig::default()
                    }
                }
            }
        } else {
            BucketConfig::default()
        };
        if config.policy.is_none() {
            config.policy = self.read_legacy_bucket_policy_sync(bucket_name);
        }

        self.bucket_config_cache
            .insert(bucket_name.to_string(), (config.clone(), Instant::now()));
        config
    }

    pub(super) fn read_legacy_bucket_policy_sync(&self, bucket_name: &str) -> Option<Value> {
        let path = self.legacy_bucket_policies_path();
        let text = std::fs::read_to_string(path).ok()?;
        let value = serde_json::from_str::<Value>(&text).ok()?;
        value
            .get("policies")
            .and_then(|policies| policies.get(bucket_name))
            .cloned()
            .or_else(|| value.get(bucket_name).cloned())
    }

    pub(super) fn remove_legacy_bucket_policy_sync(
        &self,
        bucket_name: &str,
    ) -> std::io::Result<()> {
        let path = self.legacy_bucket_policies_path();
        if !path.exists() {
            return Ok(());
        }

        let text = std::fs::read_to_string(&path)?;
        let Ok(mut value) = serde_json::from_str::<Value>(&text) else {
            return Ok(());
        };
        let changed = {
            let Some(object) = value.as_object_mut() else {
                return Ok(());
            };

            let mut changed = false;
            if let Some(policies) = object.get_mut("policies").and_then(Value::as_object_mut) {
                changed |= policies.remove(bucket_name).is_some();
            }
            changed |= object.remove(bucket_name).is_some();
            changed
        };
        if !changed {
            return Ok(());
        }

        Self::atomic_write_json_sync(&path, &value, true)
    }

    pub(super) fn write_bucket_config_sync(
        &self,
        bucket_name: &str,
        config: &BucketConfig,
    ) -> std::io::Result<()> {
        if let Some(err) = validation::bucket_name_rejection(bucket_name) {
            return Err(std::io::Error::other(err));
        }
        if config.unreadable {
            return Err(std::io::Error::other(format!(
                "Bucket configuration for '{}' is unreadable or corrupt; refusing to overwrite it \
                 and discard its settings",
                bucket_name
            )));
        }
        let config_path = self.bucket_config_path(bucket_name);
        let json_val = serde_json::to_value(config).map_err(std::io::Error::other)?;
        #[cfg(any(test, feature = "failpoints"))]
        crate::failpoints::hit(&self.root, "bucket:config-write")?;
        Self::atomic_write_json_sync(&config_path, &json_val, true)?;
        if config.policy.is_none() {
            self.remove_legacy_bucket_policy_sync(bucket_name)?;
        }
        self.bucket_config_cache
            .insert(bucket_name.to_string(), (config.clone(), Instant::now()));
        Ok(())
    }

    pub async fn mutate_bucket_config<F>(
        &self,
        bucket_name: &str,
        f: F,
    ) -> StorageResult<BucketConfig>
    where
        F: FnOnce(&mut BucketConfig),
    {
        run_blocking(move || {
            self.require_bucket(bucket_name)?;
            let lock = self
                .bucket_config_locks
                .entry(bucket_name.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone();
            let _guard = lock.lock();
            let mut config = self.read_bucket_config_sync(bucket_name);
            if config.unreadable {
                return Err(StorageError::Internal(format!(
                    "Bucket configuration for '{}' is unreadable or corrupt; refusing to \
                     overwrite it",
                    bucket_name
                )));
            }
            f(&mut config);
            self.write_bucket_config_sync(bucket_name, &config)
                .map_err(StorageError::Io)?;
            Ok(config)
        })
    }
}
