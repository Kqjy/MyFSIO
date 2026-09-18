use chrono::{DateTime, Duration, Utc};
use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::services::object_lock;

const LIFECYCLE_PAGE_SIZE: usize = 1_000;

pub struct LifecycleConfig {
    pub interval_seconds: u64,
    pub max_history_per_bucket: usize,
    pub page_size: usize,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 3600,
            max_history_per_bucket: 50,
            page_size: LIFECYCLE_PAGE_SIZE,
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
    tags: Vec<(String, String)>,
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
    replication: Option<Arc<crate::services::replication::ReplicationManager>>,
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
            replication: None,
        }
    }

    pub fn with_replication(
        mut self,
        replication: Arc<crate::services::replication::ReplicationManager>,
    ) -> Self {
        self.replication = Some(replication);
        self
    }

    fn page_size(&self) -> usize {
        if self.config.page_size == 0 {
            LIFECYCLE_PAGE_SIZE
        } else {
            self.config.page_size
        }
    }

    async fn propagate_delete(
        &self,
        bucket: &str,
        key: &str,
        outcome: &myfsio_common::types::DeleteOutcome,
    ) {
        let Some(replication) = self.replication.clone() else {
            return;
        };
        let action = if outcome.is_delete_marker {
            "delete-marker"
        } else {
            "delete"
        };
        replication
            .trigger(
                bucket.to_string(),
                key.to_string(),
                action.to_string(),
                outcome.version_id.clone(),
            )
            .await;
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
        let cutoff = match rule.expiration_days {
            Some(days) => Utc::now() - Duration::days(days as i64),
            None => {
                let expiration_date = rule.expiration_date?;
                let now = Utc::now();
                if now < expiration_date {
                    return None;
                }
                now
            }
        };

        let prefix = if rule.prefix.is_empty() {
            None
        } else {
            Some(rule.prefix.clone())
        };
        let mut continuation_token = None;
        loop {
            let params = myfsio_common::types::ListParams {
                max_keys: self.page_size(),
                prefix: prefix.clone(),
                continuation_token: continuation_token.clone(),
                ..Default::default()
            };
            let page = match self.storage.list_objects(bucket, &params).await {
                Ok(page) => page,
                Err(err) => return Some(format!("Failed to list objects for {}: {}", bucket, err)),
            };
            for object in &page.objects {
                if object.last_modified >= cutoff
                    || !self
                        .object_matches_tag_filter(bucket, &object.key, rule)
                        .await
                {
                    continue;
                }
                let metadata = self
                    .storage
                    .get_object_metadata(bucket, &object.key)
                    .await
                    .unwrap_or_default();
                if let Err(message) = object_lock::can_delete_object(&metadata, false) {
                    tracing::info!(
                        bucket = bucket,
                        key = %object.key,
                        "lifecycle skip locked: {}",
                        message
                    );
                    continue;
                }
                match self.storage.delete_object(bucket, &object.key).await {
                    Ok(outcome) => {
                        result.objects_deleted += 1;
                        self.propagate_delete(bucket, &object.key, &outcome).await;
                    }
                    Err(err) => result
                        .errors
                        .push(format!("{}:{}: {}", bucket, object.key, err)),
                }
            }
            if !page.is_truncated {
                return None;
            }
            match page.next_continuation_token {
                Some(token) => continuation_token = Some(token),
                None => return None,
            }
        }
    }

    async fn object_matches_tag_filter(
        &self,
        bucket: &str,
        key: &str,
        rule: &ParsedLifecycleRule,
    ) -> bool {
        if rule.tags.is_empty() {
            return true;
        }
        match self.storage.get_object_tags(bucket, key).await {
            Ok(tags) => rule
                .tags
                .iter()
                .all(|(k, v)| tags.iter().any(|t| t.key == *k && t.value == *v)),
            Err(_) => false,
        }
    }

    async fn apply_noncurrent_expiration_rule(
        &self,
        bucket: &str,
        rule: &ParsedLifecycleRule,
        result: &mut BucketLifecycleResult,
    ) -> Option<String> {
        let days = rule.noncurrent_days?;
        let cutoff = Utc::now() - Duration::days(days as i64);
        let versions_root = version_root_for_bucket(&self.storage_root, bucket);
        if !versions_root.exists() {
            return None;
        }

        let scan_bucket = bucket.to_string();
        let scan_prefix = rule.prefix.clone();
        let scan_tags = rule.tags.clone();
        let scanned = tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, String, PathBuf)>, String> {
                let mut candidates = Vec::new();
                let mut stack = VecDeque::from([versions_root]);
                while let Some(current) = stack.pop_front() {
                    let entries = match std::fs::read_dir(&current) {
                        Ok(entries) => entries,
                        Err(err) => return Err(err.to_string()),
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
                        if !scan_prefix.is_empty() && !key.starts_with(&scan_prefix) {
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
                        if !scan_tags.is_empty() {
                            let Some(version_tags_value) = manifest.get("tags") else {
                                continue;
                            };
                            let version_tags: Vec<myfsio_common::types::Tag> =
                                serde_json::from_value(version_tags_value.clone())
                                    .unwrap_or_default();
                            let matched = scan_tags.iter().all(|(k, v)| {
                                version_tags.iter().any(|t| t.key == *k && t.value == *v)
                            });
                            if !matched {
                                continue;
                            }
                        }
                        if let Some(version_meta) =
                            manifest.get("metadata").and_then(|m| m.as_object())
                        {
                            let metadata_map: std::collections::HashMap<String, String> =
                                version_meta
                                    .iter()
                                    .filter_map(|(k, v)| {
                                        v.as_str().map(|s| (k.clone(), s.to_string()))
                                    })
                                    .collect();
                            if let Err(message) =
                                object_lock::can_delete_object(&metadata_map, false)
                            {
                                tracing::info!(
                                    bucket = %scan_bucket,
                                    key = %key,
                                    "lifecycle skip locked archived version: {}",
                                    message
                                );
                                continue;
                            }
                        }
                        let version_id = manifest
                            .get("version_id")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default()
                            .to_string();
                        candidates.push((key, version_id, entry.path()));
                    }
                }
                Ok(candidates)
            },
        )
        .await;

        let candidates = match scanned {
            Ok(Ok(candidates)) => candidates,
            Ok(Err(message)) => return Some(message),
            Err(join) => return Some(join.to_string()),
        };

        for (key, version_id, manifest_path) in candidates {
            if !version_id.is_empty() {
                match self
                    .storage
                    .delete_object_version(bucket, &key, &version_id)
                    .await
                {
                    Ok(_) => result.versions_deleted += 1,
                    Err(err) => result
                        .errors
                        .push(format!("expire version {}: {}", version_id, err)),
                }
            } else {
                let data_path = manifest_path.with_extension("bin");
                let _ = tokio::fs::remove_file(&data_path).await;
                let _ = tokio::fs::remove_file(&manifest_path).await;
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
        let days = rule.abort_incomplete_multipart_days?;
        let cutoff = Utc::now() - Duration::days(days as i64);
        match self.storage.list_multipart_uploads(bucket).await {
            Ok(uploads) => {
                for upload in &uploads {
                    if upload.initiated < cutoff {
                        if let Err(err) = self
                            .storage
                            .abort_multipart(bucket, &upload.upload_id)
                            .await
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
            Err(err) => Some(format!(
                "Failed to list multipart uploads for {}: {}",
                bucket, err
            )),
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
        if let Err(err) = myfsio_common::fs_util::atomic_write_json(&path, &payload) {
            tracing::error!(
                path = %path.display(),
                error = %err,
                "Failed to persist lifecycle execution history for bucket {}; the run itself completed but will not appear in the history",
                result.bucket_name
            );
        }
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
    if myfsio_storage::validation::bucket_name_rejection(bucket_name).is_some() {
        return json!({
            "executions": Vec::<LifecycleExecutionRecord>::new(),
            "total": 0,
            "limit": limit,
            "offset": offset,
            "enabled": true,
        });
    }
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
                    let filter = rule
                        .children()
                        .find(|node| node.is_element() && node.tag_name().name() == "Filter")?;
                    if let Some(prefix) = child_text(&filter, "Prefix") {
                        return Some(prefix);
                    }
                    let and = filter
                        .children()
                        .find(|node| node.is_element() && node.tag_name().name() == "And")?;
                    child_text(&and, "Prefix")
                })
                .unwrap_or_default(),
            tags: {
                let mut collected: Vec<(String, String)> = Vec::new();
                if let Some(filter) = rule
                    .children()
                    .find(|node| node.is_element() && node.tag_name().name() == "Filter")
                {
                    let direct_tag = filter
                        .children()
                        .find(|node| node.is_element() && node.tag_name().name() == "Tag");
                    if let Some(tag) = direct_tag {
                        if let Some(key) = child_text(&tag, "Key") {
                            collected.push((key, child_text(&tag, "Value").unwrap_or_default()));
                        }
                    }
                    if let Some(and) = filter
                        .children()
                        .find(|node| node.is_element() && node.tag_name().name() == "And")
                    {
                        for tag in and
                            .children()
                            .filter(|node| node.is_element() && node.tag_name().name() == "Tag")
                        {
                            if let Some(key) = child_text(&tag, "Key") {
                                collected
                                    .push((key, child_text(&tag, "Value").unwrap_or_default()));
                            }
                        }
                    }
                }
                collected
            },
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
                    node.is_element() && node.tag_name().name() == "AbortIncompleteMultipartUpload"
                })
                .and_then(|node| child_text(&node, "DaysAfterInitiation"))
                .and_then(|value| value.parse::<u64>().ok()),
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleConfigError {
    Malformed(String),
    Unsupported(String),
    Invalid(String),
}

impl LifecycleConfigError {
    pub fn message(&self) -> &str {
        match self {
            Self::Malformed(message) | Self::Unsupported(message) | Self::Invalid(message) => {
                message
            }
        }
    }
}

fn lifecycle_allowed_children(element: &str) -> &'static [&'static str] {
    match element {
        "LifecycleConfiguration" => &["Rule"],
        "Rule" => &[
            "ID",
            "Status",
            "Prefix",
            "Filter",
            "Expiration",
            "NoncurrentVersionExpiration",
            "AbortIncompleteMultipartUpload",
        ],
        "Filter" => &["Prefix", "Tag", "And"],
        "And" => &["Prefix", "Tag"],
        "Tag" => &["Key", "Value"],
        "Expiration" => &["Days", "Date"],
        "NoncurrentVersionExpiration" => &["NoncurrentDays"],
        "AbortIncompleteMultipartUpload" => &["DaysAfterInitiation"],
        _ => &[],
    }
}

pub fn validate_lifecycle_configuration(raw: &str) -> Result<(), LifecycleConfigError> {
    let doc = roxmltree::Document::parse(raw).map_err(|err| {
        LifecycleConfigError::Malformed(format!(
            "LifecycleConfiguration is not well-formed XML: {}",
            err
        ))
    })?;

    let root = doc.root_element();
    let root_name = root.tag_name().name();
    if root_name != "LifecycleConfiguration" {
        return Err(LifecycleConfigError::Malformed(format!(
            "LifecycleConfiguration must be the root element, found <{}>",
            root_name
        )));
    }

    validate_lifecycle_elements(root)?;

    let rules: Vec<_> = root.children().filter(|node| node.is_element()).collect();
    if rules.is_empty() {
        return Err(LifecycleConfigError::Invalid(
            "LifecycleConfiguration must contain at least one Rule".to_string(),
        ));
    }
    for rule in &rules {
        validate_lifecycle_rule_node(rule)?;
    }
    Ok(())
}

fn validate_lifecycle_elements(node: roxmltree::Node<'_, '_>) -> Result<(), LifecycleConfigError> {
    let parent = node.tag_name().name();
    let allowed = lifecycle_allowed_children(parent);
    for child in node.children().filter(|child| child.is_element()) {
        let name = child.tag_name().name();
        if !allowed.contains(&name) {
            return Err(LifecycleConfigError::Unsupported(format!(
                "Lifecycle element <{}> inside <{}> is not supported by this server",
                name, parent
            )));
        }
        validate_lifecycle_elements(child)?;
    }
    Ok(())
}

fn validate_lifecycle_rule_node(
    rule: &roxmltree::Node<'_, '_>,
) -> Result<(), LifecycleConfigError> {
    match child_text(rule, "Status") {
        Some(status) => {
            if status != "Enabled" && status != "Disabled" {
                return Err(LifecycleConfigError::Invalid(format!(
                    "Lifecycle 'Status' must be 'Enabled' or 'Disabled', found '{}'",
                    status
                )));
            }
        }
        None => {
            return Err(LifecycleConfigError::Invalid(
                "Lifecycle 'Status' is required and must be 'Enabled' or 'Disabled'".to_string(),
            ));
        }
    }

    let mut actions = 0usize;

    if let Some(expiration) = child_element(rule, "Expiration") {
        match (
            child_text(&expiration, "Days"),
            child_text(&expiration, "Date"),
        ) {
            (Some(_), Some(_)) => {
                return Err(LifecycleConfigError::Invalid(
                    "Lifecycle 'Expiration' must specify either 'Days' or 'Date', not both"
                        .to_string(),
                ))
            }
            (Some(days), None) => validate_lifecycle_days("Days", &days)?,
            (None, Some(date)) => {
                if parse_datetime(&date).is_none() {
                    return Err(LifecycleConfigError::Invalid(format!(
                        "Lifecycle 'Date' must be an RFC 3339 timestamp, found '{}'",
                        date
                    )));
                }
            }
            (None, None) => {
                return Err(LifecycleConfigError::Invalid(
                    "Lifecycle 'Expiration' must specify 'Days' or 'Date'".to_string(),
                ))
            }
        }
        actions += 1;
    }

    if let Some(noncurrent) = child_element(rule, "NoncurrentVersionExpiration") {
        let days = child_text(&noncurrent, "NoncurrentDays").ok_or_else(|| {
            LifecycleConfigError::Invalid(
                "Lifecycle 'NoncurrentVersionExpiration' must specify 'NoncurrentDays'".to_string(),
            )
        })?;
        validate_lifecycle_days("NoncurrentDays", &days)?;
        actions += 1;
    }

    if let Some(abort) = child_element(rule, "AbortIncompleteMultipartUpload") {
        let days = child_text(&abort, "DaysAfterInitiation").ok_or_else(|| {
            LifecycleConfigError::Invalid(
                "Lifecycle 'AbortIncompleteMultipartUpload' must specify 'DaysAfterInitiation'"
                    .to_string(),
            )
        })?;
        validate_lifecycle_days("DaysAfterInitiation", &days)?;
        actions += 1;
    }

    if actions == 0 {
        return Err(LifecycleConfigError::Invalid(
            "Lifecycle 'Rule' must specify Expiration, NoncurrentVersionExpiration or AbortIncompleteMultipartUpload".to_string(),
        ));
    }
    Ok(())
}

fn validate_lifecycle_days(name: &str, text: &str) -> Result<(), LifecycleConfigError> {
    let parsed: i64 = text.parse().map_err(|_| {
        LifecycleConfigError::Invalid(format!("Lifecycle '{}' must be a positive integer", name))
    })?;
    if parsed < 1 {
        return Err(LifecycleConfigError::Invalid(format!(
            "Lifecycle '{}' must be a positive integer (>= 1)",
            name
        )));
    }
    Ok(())
}

fn child_element<'a, 'input>(
    node: &roxmltree::Node<'a, 'input>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn parse_lifecycle_rule(value: &Value) -> Option<ParsedLifecycleRule> {
    let map = value.as_object()?;
    let mut tags: Vec<(String, String)> = Vec::new();
    if let Some(filter) = map.get("Filter").and_then(|v| v.as_object()) {
        if let Some(tag) = filter.get("Tag").and_then(|v| v.as_object()) {
            if let (Some(k), Some(v)) = (
                tag.get("Key").and_then(|v| v.as_str()),
                tag.get("Value").and_then(|v| v.as_str()),
            ) {
                tags.push((k.to_string(), v.to_string()));
            }
        }
        if let Some(and) = filter.get("And").and_then(|v| v.as_object()) {
            if let Some(arr) = and.get("Tags").and_then(|v| v.as_array()) {
                for entry in arr {
                    if let (Some(k), Some(v)) = (
                        entry.get("Key").and_then(|v| v.as_str()),
                        entry.get("Value").and_then(|v| v.as_str()),
                    ) {
                        tags.push((k.to_string(), v.to_string()));
                    }
                }
            }
            if let Some(tag) = and.get("Tag").and_then(|v| v.as_object()) {
                if let (Some(k), Some(v)) = (
                    tag.get("Key").and_then(|v| v.as_str()),
                    tag.get("Value").and_then(|v| v.as_str()),
                ) {
                    tags.push((k.to_string(), v.to_string()));
                }
            }
        }
    }
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
            .or_else(|| {
                map.get("Filter")
                    .and_then(|value| value.get("And"))
                    .and_then(|value| value.get("Prefix"))
                    .and_then(|value| value.as_str())
            })
            .unwrap_or_default()
            .to_string(),
        tags,
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

    #[test]
    fn parses_xml_filter_and_with_prefix_and_tags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter>
                  <And>
                    <Prefix>logs/</Prefix>
                    <Tag><Key>env</Key><Value>prod</Value></Tag>
                    <Tag><Key>tier</Key><Value>cold</Value></Tag>
                  </And>
                </Filter>
                <Expiration><Days>10</Days></Expiration>
              </Rule>
            </LifecycleConfiguration>"#;
        let rules = parse_lifecycle_rules(&Value::String(xml.to_string()));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(
            rules[0].tags,
            vec![
                ("env".to_string(), "prod".to_string()),
                ("tier".to_string(), "cold".to_string()),
            ]
        );
        assert_eq!(rules[0].expiration_days, Some(10));
    }

    #[test]
    fn parses_xml_filter_with_single_tag() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><Tag><Key>env</Key><Value>prod</Value></Tag></Filter>
                <Expiration><Days>5</Days></Expiration>
              </Rule>
            </LifecycleConfiguration>"#;
        let rules = parse_lifecycle_rules(&Value::String(xml.to_string()));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "");
        assert_eq!(rules[0].tags, vec![("env".to_string(), "prod".to_string())]);
    }

    #[test]
    fn xml_tags_outside_filter_are_ignored() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <Expiration>
                  <Days>10</Days>
                  <Tag><Key>spurious</Key><Value>nope</Value></Tag>
                </Expiration>
              </Rule>
            </LifecycleConfiguration>"#;
        let rules = parse_lifecycle_rules(&Value::String(xml.to_string()));
        assert_eq!(rules.len(), 1);
        assert!(rules[0].tags.is_empty());
        assert_eq!(rules[0].prefix, "logs/");
    }

    fn supported_lifecycle_xml() -> String {
        r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <Rule>
                <ID>expire-logs</ID>
                <Status>Enabled</Status>
                <Filter>
                  <And>
                    <Prefix>logs/</Prefix>
                    <Tag><Key>env</Key><Value>prod</Value></Tag>
                  </And>
                </Filter>
                <Expiration><Days>10</Days></Expiration>
                <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>
                <AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload>
              </Rule>
            </LifecycleConfiguration>"#
            .to_string()
    }

    fn rule_xml(body: &str) -> String {
        format!(
            "<LifecycleConfiguration><Rule><Status>Enabled</Status>{}</Rule></LifecycleConfiguration>",
            body
        )
    }

    #[test]
    fn accepts_supported_lifecycle_configuration() {
        assert_eq!(
            validate_lifecycle_configuration(&supported_lifecycle_xml()),
            Ok(())
        );
    }

    #[test]
    fn accepts_expiration_date_and_disabled_status() {
        let xml = "<LifecycleConfiguration><Rule><Status>Disabled</Status>\
                   <Prefix>tmp/</Prefix>\
                   <Expiration><Date>2026-01-01T00:00:00Z</Date></Expiration>\
                   </Rule></LifecycleConfiguration>";
        assert_eq!(validate_lifecycle_configuration(xml), Ok(()));
    }

    #[test]
    fn accepted_configuration_is_parsed_by_the_executor() {
        let xml = supported_lifecycle_xml();
        validate_lifecycle_configuration(&xml).expect("valid");
        let rules = parse_lifecycle_rules(&Value::String(xml));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(rules[0].expiration_days, Some(10));
        assert_eq!(rules[0].noncurrent_days, Some(30));
        assert_eq!(rules[0].abort_incomplete_multipart_days, Some(7));
    }

    #[test]
    fn rejects_malformed_xml() {
        for raw in ["", "not xml at all", "<LifecycleConfiguration><Rule>"] {
            assert!(matches!(
                validate_lifecycle_configuration(raw),
                Err(LifecycleConfigError::Malformed(_))
            ));
        }
    }

    #[test]
    fn rejects_wrong_root_element() {
        assert!(matches!(
            validate_lifecycle_configuration("<Lifecycle><Rule/></Lifecycle>"),
            Err(LifecycleConfigError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_unsupported_elements() {
        let cases = [
            (
                "Transition",
                rule_xml("<Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition>"),
            ),
            (
                "NoncurrentVersionTransition",
                rule_xml("<NoncurrentVersionTransition><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionTransition>"),
            ),
            (
                "ExpiredObjectDeleteMarker",
                rule_xml("<Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration>"),
            ),
            (
                "NewerNoncurrentVersions",
                rule_xml("<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>"),
            ),
            (
                "ObjectSizeGreaterThan",
                rule_xml("<Filter><And><Prefix>a/</Prefix><ObjectSizeGreaterThan>5368709120</ObjectSizeGreaterThan></And></Filter><Expiration><Days>1</Days></Expiration>"),
            ),
            (
                "ObjectSizeLessThan",
                rule_xml("<Filter><ObjectSizeLessThan>1024</ObjectSizeLessThan></Filter><Expiration><Days>1</Days></Expiration>"),
            ),
        ];
        for (element, xml) in cases {
            match validate_lifecycle_configuration(&xml) {
                Err(LifecycleConfigError::Unsupported(message)) => {
                    assert!(
                        message.contains(element),
                        "message {} should name {}",
                        message,
                        element
                    );
                }
                other => panic!("expected {} to be rejected, got {:?}", element, other),
            }
        }
    }

    #[test]
    fn rejects_unknown_future_element() {
        assert!(matches!(
            validate_lifecycle_configuration(&rule_xml(
                "<Expiration><Days>1</Days></Expiration><SomeFutureAction><Days>1</Days></SomeFutureAction>"
            )),
            Err(LifecycleConfigError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_misplaced_tag_element() {
        assert!(matches!(
            validate_lifecycle_configuration(&rule_xml(
                "<Expiration><Days>1</Days><Tag><Key>a</Key><Value>b</Value></Tag></Expiration>"
            )),
            Err(LifecycleConfigError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_non_positive_days() {
        for body in [
            "<Expiration><Days>0</Days></Expiration>",
            "<Expiration><Days>-1</Days></Expiration>",
            "<Expiration><Days>ten</Days></Expiration>",
            "<NoncurrentVersionExpiration><NoncurrentDays>0</NoncurrentDays></NoncurrentVersionExpiration>",
            "<AbortIncompleteMultipartUpload><DaysAfterInitiation>0</DaysAfterInitiation></AbortIncompleteMultipartUpload>",
        ] {
            assert!(
                matches!(
                    validate_lifecycle_configuration(&rule_xml(body)),
                    Err(LifecycleConfigError::Invalid(_))
                ),
                "expected {} to be rejected",
                body
            );
        }
    }

    #[test]
    fn rejects_rules_without_an_actionable_element() {
        for body in [
            "",
            "<Filter><Prefix>logs/</Prefix></Filter>",
            "<Expiration></Expiration>",
            "<Expiration><Days></Days></Expiration>",
        ] {
            assert!(
                matches!(
                    validate_lifecycle_configuration(&rule_xml(body)),
                    Err(LifecycleConfigError::Invalid(_))
                ),
                "expected {:?} to be rejected",
                body
            );
        }
    }

    #[test]
    fn rejects_configuration_without_rules() {
        assert!(matches!(
            validate_lifecycle_configuration("<LifecycleConfiguration></LifecycleConfiguration>"),
            Err(LifecycleConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_invalid_status_and_date() {
        assert!(matches!(
            validate_lifecycle_configuration(
                "<LifecycleConfiguration><Rule><Status>enabled</Status>\
                 <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
            ),
            Err(LifecycleConfigError::Invalid(_))
        ));
        assert!(matches!(
            validate_lifecycle_configuration(&rule_xml(
                "<Expiration><Date>2026-01-01</Date></Expiration>"
            )),
            Err(LifecycleConfigError::Invalid(_))
        ));
        assert!(matches!(
            validate_lifecycle_configuration(&rule_xml(
                "<Expiration><Days>1</Days><Date>2026-01-01T00:00:00Z</Date></Expiration>"
            )),
            Err(LifecycleConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_missing_or_empty_status() {
        assert!(matches!(
            validate_lifecycle_configuration(
                "<LifecycleConfiguration><Rule>\
                 <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
            ),
            Err(LifecycleConfigError::Invalid(_))
        ));
        assert!(matches!(
            validate_lifecycle_configuration(
                "<LifecycleConfiguration><Rule><Status></Status>\
                 <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
            ),
            Err(LifecycleConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_json_lifecycle_body() {
        let json = r#"{"Rules":[{"Status":"Enabled","Expiration":{"Days":1}}]}"#;
        assert!(matches!(
            validate_lifecycle_configuration(json),
            Err(LifecycleConfigError::Malformed(_))
        ));
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

        let versions_root = version_root_for_bucket(tmp.path(), "docs")
            .join("logs")
            .join("file.txt");
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

        let service =
            LifecycleService::new(storage.clone(), tmp.path(), LifecycleConfig::default());
        let result = service.run_cycle().await.unwrap();
        assert_eq!(result["versions_deleted"], 1);

        let history = read_history(tmp.path(), "docs", 50, 0);
        assert_eq!(history["total"], 1);
        assert_eq!(history["executions"][0]["versions_deleted"], 1);
    }

    #[tokio::test]
    async fn noncurrent_expiration_removes_data_file_when_manifest_lacks_version_id() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        storage.create_bucket("docs").await.unwrap();

        let version_dir = version_root_for_bucket(tmp.path(), "docs")
            .join("logs")
            .join("file.txt");
        std::fs::create_dir_all(&version_dir).unwrap();
        let manifest = version_dir.join("legacy-1.json");
        let data = version_dir.join("legacy-1.bin");
        let legacy_manifest = json!({
            "key": "logs/file.txt",
            "size": 3,
            "archived_at": (Utc::now() - Duration::days(45)).to_rfc3339(),
            "etag": "etag",
        });
        std::fs::write(&manifest, serde_json::to_string(&legacy_manifest).unwrap()).unwrap();
        std::fs::write(&data, b"old").unwrap();

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

        let service =
            LifecycleService::new(storage.clone(), tmp.path(), LifecycleConfig::default());
        let result = service.run_cycle().await.unwrap();
        assert_eq!(result["versions_deleted"], 1);
        assert!(!manifest.exists());
        assert!(!data.exists());
    }

    #[tokio::test]
    async fn noncurrent_tag_filter_uses_version_tags_not_current_tags() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        storage.create_bucket("docs").await.unwrap();
        storage.set_versioning("docs", true).await.unwrap();

        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"v1".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"v2".to_vec())),
                None,
            )
            .await
            .unwrap();

        let live_tags = vec![myfsio_common::types::Tag {
            key: "env".to_string(),
            value: "prod".to_string(),
        }];
        storage
            .set_object_tags("docs", "logs/file.txt", &live_tags)
            .await
            .unwrap();

        let versions_root = version_root_for_bucket(tmp.path(), "docs")
            .join("logs")
            .join("file.txt");
        let manifest = std::fs::read_dir(&versions_root)
            .unwrap()
            .flatten()
            .find(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .unwrap()
            .path();
        let archived_manifest = json!({
            "version_id": "ver-untagged",
            "key": "logs/file.txt",
            "size": 2,
            "archived_at": (Utc::now() - Duration::days(45)).to_rfc3339(),
            "etag": "etag",
            "tags": [],
        });
        std::fs::write(
            &manifest,
            serde_json::to_string(&archived_manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(manifest.with_file_name("ver-untagged.bin"), b"v1").unwrap();

        let lifecycle_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><And><Prefix>logs/</Prefix><Tag><Key>env</Key><Value>prod</Value></Tag></And></Filter>
                <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>
              </Rule>
            </LifecycleConfiguration>"#;
        let mut config = storage.get_bucket_config("docs").await.unwrap();
        config.lifecycle = Some(Value::String(lifecycle_xml.to_string()));
        storage.set_bucket_config("docs", &config).await.unwrap();

        let service =
            LifecycleService::new(storage.clone(), tmp.path(), LifecycleConfig::default());
        let result = service.run_cycle().await.unwrap();
        assert_eq!(
            result["versions_deleted"], 0,
            "noncurrent expiration must consult the version's own tags, not the current key's"
        );
        assert!(
            manifest.exists(),
            "the untagged archived version should still be on disk"
        );
    }

    #[tokio::test]
    async fn noncurrent_tag_filter_deletes_when_version_tags_match() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        storage.create_bucket("docs").await.unwrap();
        storage.set_versioning("docs", true).await.unwrap();

        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"v1".to_vec())),
                None,
            )
            .await
            .unwrap();
        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"v2".to_vec())),
                None,
            )
            .await
            .unwrap();

        let versions_root = version_root_for_bucket(tmp.path(), "docs")
            .join("logs")
            .join("file.txt");
        let manifest = std::fs::read_dir(&versions_root)
            .unwrap()
            .flatten()
            .find(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .unwrap()
            .path();
        let archived_manifest = json!({
            "version_id": "ver-tagged",
            "key": "logs/file.txt",
            "size": 2,
            "archived_at": (Utc::now() - Duration::days(45)).to_rfc3339(),
            "etag": "etag",
            "tags": [{ "key": "env", "value": "prod" }],
        });
        std::fs::write(
            &manifest,
            serde_json::to_string(&archived_manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(manifest.with_file_name("ver-tagged.bin"), b"v1").unwrap();

        let lifecycle_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><And><Prefix>logs/</Prefix><Tag><Key>env</Key><Value>prod</Value></Tag></And></Filter>
                <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration>
              </Rule>
            </LifecycleConfiguration>"#;
        let mut config = storage.get_bucket_config("docs").await.unwrap();
        config.lifecycle = Some(Value::String(lifecycle_xml.to_string()));
        storage.set_bucket_config("docs", &config).await.unwrap();

        let service =
            LifecycleService::new(storage.clone(), tmp.path(), LifecycleConfig::default());
        let result = service.run_cycle().await.unwrap();
        assert_eq!(result["versions_deleted"], 1);
    }

    async fn run_date_expiration_cycle(
        date: DateTime<Utc>,
    ) -> (Arc<FsStorageBackend>, Value, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        storage.create_bucket("docs").await.unwrap();
        storage
            .put_object(
                "docs",
                "logs/file.txt",
                Box::pin(std::io::Cursor::new(b"payload".to_vec())),
                None,
            )
            .await
            .unwrap();

        let lifecycle_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <Expiration><Date>{}</Date></Expiration>
              </Rule>
            </LifecycleConfiguration>"#,
            date.to_rfc3339()
        );
        let mut config = storage.get_bucket_config("docs").await.unwrap();
        config.lifecycle = Some(Value::String(lifecycle_xml));
        storage.set_bucket_config("docs", &config).await.unwrap();

        let service =
            LifecycleService::new(storage.clone(), tmp.path(), LifecycleConfig::default());
        let result = service.run_cycle().await.unwrap();
        (storage, result, tmp)
    }

    #[tokio::test]
    async fn expiration_walks_past_the_first_listing_page() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(FsStorageBackend::new(tmp.path().to_path_buf()));
        storage.create_bucket("docs").await.unwrap();

        let page_size = 10;
        let total = page_size * 3 + 4;
        for index in 0..total {
            storage
                .put_object(
                    "docs",
                    &format!("logs/file-{:05}.txt", index),
                    Box::pin(std::io::Cursor::new(b"payload".to_vec())),
                    None,
                )
                .await
                .unwrap();
        }

        let lifecycle_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <LifecycleConfiguration>
              <Rule>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <Expiration><Date>{}</Date></Expiration>
              </Rule>
            </LifecycleConfiguration>"#,
            (Utc::now() - Duration::days(1)).to_rfc3339()
        );
        let mut config = storage.get_bucket_config("docs").await.unwrap();
        config.lifecycle = Some(Value::String(lifecycle_xml));
        storage.set_bucket_config("docs", &config).await.unwrap();

        let service = LifecycleService::new(
            storage.clone(),
            tmp.path(),
            LifecycleConfig {
                page_size,
                ..LifecycleConfig::default()
            },
        );
        let result = service.run_cycle().await.unwrap();

        assert_eq!(
            result["objects_deleted"], total as u64,
            "every eligible object must expire, not just the first listing page"
        );
        let params = myfsio_common::types::ListParams {
            max_keys: 10,
            prefix: Some("logs/".to_string()),
            ..Default::default()
        };
        assert!(storage
            .list_objects("docs", &params)
            .await
            .unwrap()
            .objects
            .is_empty());
    }

    #[tokio::test]
    async fn future_expiration_date_deletes_nothing() {
        let (storage, result, _tmp) =
            run_date_expiration_cycle(Utc::now() + Duration::days(365)).await;
        assert_eq!(
            result["objects_deleted"], 0,
            "a rule dated in the future must not expire anything yet"
        );
        assert!(storage.head_object("docs", "logs/file.txt").await.is_ok());
    }

    #[tokio::test]
    async fn past_expiration_date_deletes_objects_modified_after_the_date() {
        let (storage, result, _tmp) =
            run_date_expiration_cycle(Utc::now() - Duration::days(1)).await;
        assert_eq!(
            result["objects_deleted"], 1,
            "once the date has passed every matching object expires regardless of its age"
        );
        assert!(storage.head_object("docs", "logs/file.txt").await.is_err());
    }
}
