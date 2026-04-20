use chrono::{DateTime, Duration, Utc};
use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct LifecycleConfig {
    pub interval_seconds: u64,
    pub max_history_per_bucket: usize,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 3600,
            max_history_per_bucket: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleExecutionRecord {
    pub timestamp: f64,
    pub bucket_name: String,
    pub objects_deleted: u64,
    pub versions_deleted: u64,
    pub uploads_aborted: u64,
    #[serde(default)]
    pub errors: Vec<String>,
    pub execution_time_seconds: f64,
}

#[derive(Debug, Clone, Default)]
struct BucketLifecycleResult {
    bucket_name: String,
    objects_deleted: u64,
    versions_deleted: u64,
    uploads_aborted: u64,
    errors: Vec<String>,
    execution_time_seconds: f64,
}

#[derive(Debug, Clone, Default)]
struct ParsedLifecycleRule {
    status: String,
    prefix: String,
    expiration_days: Option<u64>,
    expiration_date: Option<DateTime<Utc>>,
    noncurrent_days: Option<u64>,
    abort_incomplete_multipart_days: Option<u64>,
}

pub struct LifecycleService {
    storage: Arc<FsStorageBackend>,
    storage_root: PathBuf,
    config: LifecycleConfig,
    running: Arc<RwLock<bool>>,
}

impl LifecycleService {
    pub fn new(
        storage: Arc<FsStorageBackend>,
        storage_root: impl Into<PathBuf>,
        config: LifecycleConfig,
    ) -> Self {
        Self {
            storage,
            storage_root: storage_root.into(),
            config,
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn run_cycle(&self) -> Result<Value, String> {
        {
            let mut running = self.running.write().await;
            if *running {
                return Err("Lifecycle already running".to_string());
            }
            *running = true;
        }

        let result = self.evaluate_rules().await;
        *self.running.write().await = false;
        Ok(result)
    }

    async fn evaluate_rules(&self) -> Value {
        let buckets = match self.storage.list_buckets().await {
            Ok(buckets) => buckets,
            Err(err) => return json!({ "error": err.to_string() }),
        };

        let mut bucket_results = Vec::new();
        let mut total_objects_deleted = 0u64;
        let mut total_versions_deleted = 0u64;
        let mut total_uploads_aborted = 0u64;
        let mut errors = Vec::new();

        for bucket in &buckets {
            let started_at = std::time::Instant::now();
            let mut result = BucketLifecycleResult {
                bucket_name: bucket.name.clone(),
                ..Default::default()
            };

            let config = match self.storage.get_bucket_config(&bucket.name).await {
                Ok(config) => config,
                Err(err) => {
                    result.errors.push(err.to_string());
                    result.execution_time_seconds = started_at.elapsed().as_secs_f64();
                    self.append_history(&result);
                    errors.extend(result.errors.clone());
                    bucket_results.push(result);
                    continue;
                }
            };
            let Some(lifecycle) = config.lifecycle.as_ref() else {
                continue;
            };
            let rules = parse_lifecycle_rules(lifecycle);
            if rules.is_empty() {
                continue;
            }

            for rule in &rules {
                if rule.status != "Enabled" {
                    continue;
                }
                if let Some(err) = self
                    .apply_expiration_rule(&bucket.name, rule, &mut result)
                    .await
                {
                    result.errors.push(err);
                }
                if let Some(err) = self
                    .apply_noncurrent_expiration_rule(&bucket.name, rule, &mut result)
                    .await
                {
                    result.errors.push(err);
                }
                if let Some(err) = self
                    .apply_abort_incomplete_multipart_rule(&bucket.name, rule, &mut result)
                    .await
                {
                    result.errors.push(err);
                }
            }

            result.execution_time_seconds = started_at.elapsed().as_secs_f64();
            if result.objects_deleted > 0
                || result.versions_deleted > 0
                || result.uploads_aborted > 0
                || !result.errors.is_empty()
            {
                total_objects_deleted += result.objects_deleted;
                total_versions_deleted += result.versions_deleted;
                total_uploads_aborted += result.uploads_aborted;
                errors.extend(result.errors.clone());
                self.append_history(&result);
                bucket_results.push(result);
            }
        }

        json!({
            "objects_deleted": total_objects_deleted,
            "versions_deleted": total_versions_deleted,
            "multipart_aborted": total_uploads_aborted,
            "buckets_evaluated": buckets.len(),
            "results": bucket_results.iter().map(result_to_json).collect::<Vec<_>>(),
            "errors": errors,
        })
    }

    async fn apply_expiration_rule(
        &self,
        bucket: &str,
        rule: &ParsedLifecycleRule,
        result: &mut BucketLifecycleResult,
    ) -> Option<String> {
        let cutoff = if let Some(days) = rule.expiration_days {
            Some(Utc::now() - Duration::days(days as i64))
        } else {
            rule.expiration_date
        };
        let Some(cutoff) = cutoff else {
            return None;
        };

        let params = myfsio_common::types::ListParams {
            max_keys: 10_000,
            prefix: if rule.prefix.is_empty() {
                None
            } else {
                Some(rule.prefix.clone())
            },
            ..Default::default()
        };
        match self.storage.list_objects(bucket, &params).await {
            Ok(objects) => {
                for object in &objects.objects {
                    if object.last_modified < cutoff {
                        if let Err(err) = self.storage.delete_object(bucket, &object.key).await {
                            result
                                .errors
                                .push(format!("{}:{}: {}", bucket, object.key, err));
                        } else {
                            result.objects_deleted += 1;
                        }
                    }
                }
                None
            }
            Err(err) => Some(format!("Failed to list objects for {}: {}", bucket, err)),
        }
    }

    async fn apply_noncurrent_expiration_rule(
        &self,
        bucket: &str,
        rule: &ParsedLifecycleRule,
        result: &mut BucketLifecycleResult,
    ) -> Option<String> {
        let Some(days) = rule.noncurrent_days else {
            return None;
        };
        let cutoff = Utc::now() - Duration::days(days as i64);
        let versions_root = version_root_for_bucket(&self.storage_root, bucket);
        if !versions_root.exists() {
            return None;
        }

        let mut stack = VecDeque::from([versions_root]);
        while let Some(current) = stack.pop_front() {
            let entries = match std::fs::read_dir(&current) {
                Ok(entries) => entries,
                Err(err) => return Some(err.to_string()),
            };
            for entry in entries.flatten() {
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(_) => continue,
                };
                if file_type.is_dir() {
                    stack.push_back(entry.path());
                    continue;
                }
                if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let contents = match std::fs::read_to_string(entry.path()) {
                    Ok(contents) => contents,
                    Err(_) => continue,
                };
                let Ok(manifest) = serde_json::from_str::<Value>(&contents) else {
                    continue;
                };
                let key = manifest
                    .get("key")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_string();
                if !rule.prefix.is_empty() && !key.starts_with(&rule.prefix) {
                    continue;
                }
                let archived_at = manifest
                    .get("archived_at")
                    .and_then(|value| value.as_str())
                    .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                    .map(|value| value.with_timezone(&Utc));
                if archived_at.is_none() || archived_at.unwrap() >= cutoff {
                    continue;
                }
                let version_id = manifest
                    .get("version_id")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let data_path = entry.path().with_file_name(format!("{}.bin", version_id));
                let _ = std::fs::remove_file(&data_path);
                let _ = std::fs::remove_file(entry.path());
                result.versions_deleted += 1;
            }
        }
        None
    }

    async fn apply_abort_incomplete_multipart_rule(
        &self,
        bucket: &str,
        rule: &ParsedLifecycleRule,
        result: &mut BucketLifecycleResult,
    ) -> Option<String> {
        let Some(days) = rule.abort_incomplete_multipart_days else {
            return None;
        };
        let cutoff = Utc::now() - Duration::days(days as i64);
        match self.storage.list_multipart_uploads(bucket).await {
            Ok(uploads) => {
                for upload in &uploads {
                    if upload.initiated < cutoff {
                        if let Err(err) = self.storage.abort_multipart(bucket, &upload.upload_id).await
                        {
                            result
                                .errors
                                .push(format!("abort {}: {}", upload.upload_id, err));
                        } else {
                            result.uploads_aborted += 1;
                        }
                    }
                }
                None
            }
            Err(err) => Some(format!("Failed to list multipart uploads for {}: {}", bucket, err)),
        }
    }

    fn append_history(&self, result: &BucketLifecycleResult) {
        let path = lifecycle_history_path(&self.storage_root, &result.bucket_name);
        let mut history = load_history(&path);
        history.insert(
            0,
            LifecycleExecutionRecord {
                timestamp: Utc::now().timestamp_millis() as f64 / 1000.0,
                bucket_name: result.bucket_name.clone(),
                objects_deleted: result.objects_deleted,
                versions_deleted: result.versions_deleted,
                uploads_aborted: result.uploads_aborted,
                errors: result.errors.clone(),
                execution_time_seconds: result.execution_time_seconds,
            },
        );
        history.truncate(self.config.max_history_per_bucket);
        let payload = json!({
            "executions": history,
        });
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &path,
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string()),
        );
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs(self.config.interval_seconds);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                tracing::info!("Lifecycle evaluation starting");
                match self.run_cycle().await {
                    Ok(result) => tracing::info!("Lifecycle cycle complete: {:?}", result),
                    Err(err) => tracing::warn!("Lifecycle cycle failed: {}", err),
                }
            }
        })
    }
}

pub fn read_history(storage_root: &Path, bucket_name: &str, limit: usize, offset: usize) -> Value {
    let path = lifecycle_history_path(storage_root, bucket_name);
    let mut history = load_history(&path);
    let total = history.len();
    let executions = history
        .drain(offset.min(total)..)
        .take(limit)
        .collect::<Vec<_>>();
    json!({
        "executions": executions,
        "total": total,
        "limit": limit,
        "offset": offset,
        "enabled": true,
    })
}

fn load_history(path: &Path) -> Vec<LifecycleExecutionRecord> {
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| serde_json::from_str::<Value>(&contents).ok())
        .and_then(|value| value.get("executions").cloned())
        .and_then(|value| serde_json::from_value::<Vec<LifecycleExecutionRecord>>(value).ok())
        .unwrap_or_default()
}

fn lifecycle_history_path(storage_root: &Path, bucket_name: &str) -> PathBuf {
    storage_root
        .join(".myfsio.sys")
        .join("buckets")
        .join(bucket_name)
        .join("lifecycle_history.json")
}

fn version_root_for_bucket(storage_root: &Path, bucket_name: &str) -> PathBuf {
    storage_root
        .join(".myfsio.sys")
        .join("buckets")
        .join(bucket_name)
        .join("versions")
}

fn parse_lifecycle_rules(value: &Value) -> Vec<ParsedLifecycleRule> {
    match value {
        Value::String(raw) => parse_lifecycle_rules_from_string(raw),
        Value::Array(items) => items.iter().filter_map(parse_lifecycle_rule).collect(),
        Value::Object(map) => map
            .get("Rules")
            .and_then(|rules| rules.as_array())
            .map(|rules| rules.iter().filter_map(parse_lifecycle_rule).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn parse_lifecycle_rules_from_string(raw: &str) -> Vec<ParsedLifecycleRule> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        return parse_lifecycle_rules(&json);
    }
    let Ok(doc) = roxmltree::Document::parse(raw) else {
        return Vec::new();
    };
    doc.descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "Rule")
        .map(|rule| ParsedLifecycleRule {
            status: child_text(&rule, "Status").unwrap_or_else(|| "Enabled".to_string()),
            prefix: child_text(&rule, "Prefix")
                .or_else(|| {
                    rule.descendants()
                        .find(|node| {
                            node.is_element()
                                && node.tag_name().name() == "Filter"
                                && node
                                    .children()
                                    .any(|child| {
                                        child.is_element()
                                            && child.tag_name().name() == "Prefix"
                                    })
                        })
                        .and_then(|filter| child_text(&filter, "Prefix"))
                })
                .unwrap_or_default(),
            expiration_days: rule
                .descendants()
                .find(|node| node.is_element() && node.tag_name().name() == "Expiration")
                .and_then(|expiration| child_text(&expiration, "Days"))
                .and_then(|value| value.parse::<u64>().ok()),
            expiration_date: rule
                .descendants()
                .find(|node| node.is_element() && node.tag_name().name() == "Expiration")
                .and_then(|expiration| child_text(&expiration, "Date"))
                .as_deref()
                .and_then(parse_datetime),
            noncurrent_days: rule
                .descendants()
                .find(|node| {
                    node.is_element() && node.tag_name().name() == "NoncurrentVersionExpiration"
                })
                .and_then(|node| child_text(&node, "NoncurrentDays"))
                .and_then(|value| value.parse::<u64>().ok()),
            abort_incomplete_multipart_days: rule
                .descendants()
                .find(|node| {
                    node.is_element()
                        && node.tag_name().name() == "AbortIncompleteMultipartUpload"
                })
                .and_then(|node| child_text(&node, "DaysAfterInitiation"))
                .and_then(|value| value.parse::<u64>().ok()),
        })
        .collect()
}

fn parse_lifecycle_rule(value: &Value) -> Option<ParsedLifecycleRule> {
    let map = value.as_object()?;
    Some(ParsedLifecycleRule {
        status: map
            .get("Status")
            .and_then(|value| value.as_str())
            .unwrap_or("Enabled")
            .to_string(),
        prefix: map
            .get("Prefix")
            .and_then(|value| value.as_str())
            .or_else(|| {
                map.get("Filter")
                    .and_then(|value| value.get("Prefix"))
                    .and_then(|value| value.as_str())
            })
            .unwrap_or_default()
            .to_string(),
        expiration_days: map
            .get("Expiration")
            .and_then(|value| value.get("Days"))
            .and_then(|value| value.as_u64()),
        expiration_date: map
            .get("Expiration")
            .and_then(|value| value.get("Date"))
            .and_then(|value| value.as_str())
            .and_then(parse_datetime),
        noncurrent_days: map
            .get("NoncurrentVersionExpiration")
            .and_then(|value| value.get("NoncurrentDays"))
            .and_then(|value| value.as_u64()),
        abort_incomplete_multipart_days: map
            .get("AbortIncompleteMultipartUpload")
            .and_then(|value| value.get("DaysAfterInitiation"))
            .and_then(|value| value.as_u64()),
    })
}

fn parse_datetime(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn result_to_json(result: &BucketLifecycleResult) -> Value {
    json!({
        "bucket_name": result.bucket_name,
        "objects_deleted": result.objects_deleted,
        "versions_deleted": result.versions_deleted,
        "uploads_aborted": result.uploads_aborted,
        "errors": result.errors,
        "execution_time_seconds": result.execution_time_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn parses_rules_from_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <Expiration><Days>10</Days></Expiration>
                <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>
                <AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload>
              </Rule>
            </LifecycleConfiguration>"#;
        let rules = parse_lifecycle_rules(&Value::String(xml.to_string()));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(rules[0].expiration_days, Some(10));
        assert_eq!(rules[0].noncurrent_days, Some(30));
        assert_eq!(rules[0].abort_incomplete_multipart_days, Some(7));
    }

    #[tokio::test]
    async fn run_cycle_writes_history_and_deletes_noncurrent_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        storage.create_bucket("docs").await.unwrap();
        storage.set_versioning("docs", true).await.unwrap();

        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"old".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"new".to_vec())),
                None,
            )
            .await
            .unwrap();

        let versions_root = version_root_for_bucket(tmp.path(), "docs").join("logs").join("file.txt");
        let manifest = std::fs::read_dir(&versions_root)
            .unwrap()
            .flatten()
            .find(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .unwrap()
            .path();
        let old_manifest = json!({
            "version_id": "ver-1",
            "key": "logs/file.txt",
            "size": 3,
            "archived_at": (Utc::now() - Duration::days(45)).to_rfc3339(),
            "etag": "etag",
        });
        std::fs::write(&manifest, serde_json::to_string(&old_manifest).unwrap()).unwrap();
        std::fs::write(manifest.with_file_name("ver-1.bin"), b"old").unwrap();

        let lifecycle_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>
              </Rule>
            </LifecycleConfiguration>"#;
        let mut config = storage.get_bucket_config("docs").await.unwrap();
        config.lifecycle = Some(Value::String(lifecycle_xml.to_string()));
        storage.set_bucket_config("docs", &config).await.unwrap();

        let service = LifecycleService::new(storage.clone(), tmp.path(), LifecycleConfig::default());
        let result = service.run_cycle().await.unwrap();
        assert_eq!(result["versions_deleted"], 1);

        let history = read_history(tmp.path(), "docs", 50, 0);
        assert_eq!(history["total"], 1);
        assert_eq!(history["executions"][0]["versions_deleted"], 1);
    }
}
