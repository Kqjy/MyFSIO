use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LATENCY_SAMPLES: usize = 5000;
const MAX_ERROR_BUCKETS: usize = 50;
const RECENT_ERRORS_CAPACITY: usize = 256;
const OTHER_BUCKET: &str = "(other)";

pub struct MetricsConfig {
    pub interval_minutes: u64,
    pub retention_hours: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            interval_minutes: 5,
            retention_hours: 24,
        }
    }
}

#[derive(Debug, Clone)]
struct OperationStats {
    count: u64,
    success_count: u64,
    error_count: u64,
    latency_sum_ms: f64,
    latency_min_ms: f64,
    latency_max_ms: f64,
    bytes_in: u64,
    bytes_out: u64,
    latency_samples: Vec<f64>,
}

impl Default for OperationStats {
    fn default() -> Self {
        Self {
            count: 0,
            success_count: 0,
            error_count: 0,
            latency_sum_ms: 0.0,
            latency_min_ms: f64::INFINITY,
            latency_max_ms: 0.0,
            bytes_in: 0,
            bytes_out: 0,
            latency_samples: Vec::new(),
        }
    }
}

impl OperationStats {
    fn record(&mut self, latency_ms: f64, success: bool, bytes_in: u64, bytes_out: u64) {
        self.count += 1;
        if success {
            self.success_count += 1;
        } else {
            self.error_count += 1;
        }
        self.latency_sum_ms += latency_ms;
        if latency_ms < self.latency_min_ms {
            self.latency_min_ms = latency_ms;
        }
        if latency_ms > self.latency_max_ms {
            self.latency_max_ms = latency_ms;
        }
        self.bytes_in += bytes_in;
        self.bytes_out += bytes_out;

        if self.latency_samples.len() < MAX_LATENCY_SAMPLES {
            self.latency_samples.push(latency_ms);
        } else {
            let mut rng = rand::thread_rng();
            let j = rng.gen_range(0..self.count as usize);
            if j < MAX_LATENCY_SAMPLES {
                self.latency_samples[j] = latency_ms;
            }
        }
    }

    fn compute_percentile(sorted: &[f64], p: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let k = (sorted.len() - 1) as f64 * (p / 100.0);
        let f = k.floor() as usize;
        let c = (f + 1).min(sorted.len() - 1);
        let d = k - f as f64;
        sorted[f] + d * (sorted[c] - sorted[f])
    }

    fn to_json(&self) -> Value {
        let avg = if self.count > 0 {
            self.latency_sum_ms / self.count as f64
        } else {
            0.0
        };
        let min = if self.latency_min_ms.is_infinite() {
            0.0
        } else {
            self.latency_min_ms
        };
        let mut sorted = self.latency_samples.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        json!({
            "count": self.count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "latency_avg_ms": round2(avg),
            "latency_min_ms": round2(min),
            "latency_max_ms": round2(self.latency_max_ms),
            "latency_p50_ms": round2(Self::compute_percentile(&sorted, 50.0)),
            "latency_p95_ms": round2(Self::compute_percentile(&sorted, 95.0)),
            "latency_p99_ms": round2(Self::compute_percentile(&sorted, 99.0)),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        })
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub window_seconds: u64,
    pub by_method: HashMap<String, Value>,
    pub by_endpoint: HashMap<String, Value>,
    pub by_status_class: HashMap<String, u64>,
    pub error_codes: HashMap<String, u64>,
    #[serde(default)]
    pub error_buckets: HashMap<String, HashMap<String, u64>>,
    pub totals: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentError {
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub endpoint_type: String,
    pub bucket: Option<String>,
    pub key: Option<String>,
    pub status: u16,
    pub code: String,
    pub request_id: Option<String>,
    pub latency_ms: f64,
    pub source: &'static str,
}

struct Inner {
    by_method: HashMap<String, OperationStats>,
    by_endpoint: HashMap<String, OperationStats>,
    by_status_class: HashMap<String, u64>,
    error_codes: HashMap<String, u64>,
    error_buckets: HashMap<String, HashMap<String, u64>>,
    recent_errors: VecDeque<RecentError>,
    totals: OperationStats,
    window_start: f64,
    snapshots: Vec<MetricsSnapshot>,
}

pub struct MetricsService {
    config: MetricsConfig,
    inner: Arc<Mutex<Inner>>,
    snapshots_path: PathBuf,
}

impl MetricsService {
    pub fn new(storage_root: &Path, config: MetricsConfig) -> Self {
        let snapshots_path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("operation_metrics.json");

        let mut snapshots = load_snapshots(&snapshots_path);
        let cutoff = now_secs() - (config.retention_hours * 3600) as f64;
        snapshots.retain(|s| s.timestamp.timestamp() as f64 > cutoff);

        Self {
            config,
            inner: Arc::new(Mutex::new(Inner {
                by_method: HashMap::new(),
                by_endpoint: HashMap::new(),
                by_status_class: HashMap::new(),
                error_codes: HashMap::new(),
                error_buckets: HashMap::new(),
                recent_errors: VecDeque::with_capacity(RECENT_ERRORS_CAPACITY),
                totals: OperationStats::default(),
                window_start: now_secs(),
                snapshots,
            })),
            snapshots_path,
        }
    }

    pub fn record_request(
        &self,
        method: &str,
        endpoint_type: &str,
        status_code: u16,
        latency_ms: f64,
        bytes_in: u64,
        bytes_out: u64,
        error_code: Option<&str>,
        bucket: Option<&str>,
        key: Option<&str>,
        request_id: Option<&str>,
        source: &'static str,
    ) {
        let success = (200..400).contains(&status_code);
        let status_class = format!("{}xx", status_code / 100);

        let mut inner = self.inner.lock();
        inner
            .by_method
            .entry(method.to_string())
            .or_default()
            .record(latency_ms, success, bytes_in, bytes_out);
        inner
            .by_endpoint
            .entry(endpoint_type.to_string())
            .or_default()
            .record(latency_ms, success, bytes_in, bytes_out);
        *inner.by_status_class.entry(status_class).or_insert(0) += 1;
        if let Some(code) = error_code {
            *inner.error_codes.entry(code.to_string()).or_insert(0) += 1;
            if let Some(bucket_name) = bucket {
                record_error_bucket(&mut inner.error_buckets, bucket_name, code);
            }
        }
        inner
            .totals
            .record(latency_ms, success, bytes_in, bytes_out);

        if status_code >= 400 {
            let code = match error_code {
                Some(code) => code,
                None if source == "ui" => "UIError",
                None => "Other",
            };
            if inner.recent_errors.len() == RECENT_ERRORS_CAPACITY {
                inner.recent_errors.pop_front();
            }
            inner.recent_errors.push_back(RecentError {
                timestamp: Utc::now(),
                method: method.to_string(),
                endpoint_type: endpoint_type.to_string(),
                bucket: bucket.map(str::to_string),
                key: key.map(str::to_string),
                status: status_code,
                code: code.to_string(),
                request_id: request_id.map(str::to_string),
                latency_ms: round2(latency_ms),
                source,
            });
        }
    }

    pub fn get_current_stats(&self) -> Value {
        let inner = self.inner.lock();
        let window_seconds = (now_secs() - inner.window_start).max(0.0) as u64;
        let by_method: HashMap<String, Value> = inner
            .by_method
            .iter()
            .map(|(k, v)| (k.clone(), v.to_json()))
            .collect();
        let by_endpoint: HashMap<String, Value> = inner
            .by_endpoint
            .iter()
            .map(|(k, v)| (k.clone(), v.to_json()))
            .collect();
        json!({
            "timestamp": Utc::now().to_rfc3339(),
            "window_seconds": window_seconds,
            "by_method": by_method,
            "by_endpoint": by_endpoint,
            "by_status_class": inner.by_status_class,
            "error_codes": inner.error_codes,
            "error_buckets": inner.error_buckets,
            "totals": inner.totals.to_json(),
        })
    }

    pub fn get_history(&self, hours: Option<u64>) -> Vec<MetricsSnapshot> {
        let inner = self.inner.lock();
        let mut snapshots = inner.snapshots.clone();
        if let Some(h) = hours {
            let cutoff = now_secs() - (h * 3600) as f64;
            snapshots.retain(|s| s.timestamp.timestamp() as f64 > cutoff);
        }
        snapshots
    }

    pub fn interval_minutes(&self) -> u64 {
        self.config.interval_minutes
    }

    pub fn error_summary(&self, hours: u64) -> Value {
        let hours = hours.min(self.config.retention_hours.max(1));
        let cutoff = now_secs() - (hours * 3600) as f64;
        let mut error_codes = HashMap::<String, u64>::new();
        let mut error_buckets = HashMap::<String, HashMap<String, u64>>::new();

        let inner = self.inner.lock();
        merge_counts(&mut error_codes, &inner.error_codes);
        merge_bucket_counts(&mut error_buckets, &inner.error_buckets);
        for snapshot in inner
            .snapshots
            .iter()
            .filter(|s| s.timestamp.timestamp() as f64 > cutoff)
        {
            merge_counts(&mut error_codes, &snapshot.error_codes);
            merge_bucket_counts(&mut error_buckets, &snapshot.error_buckets);
        }
        let total_errors = error_codes.values().sum::<u64>();
        json!({
            "enabled": true,
            "hours": hours,
            "total_errors": total_errors,
            "error_codes": error_codes,
            "error_buckets": error_buckets,
            "window_included": true,
        })
    }

    pub fn recent_errors(&self, limit: usize, code: Option<&str>, bucket: Option<&str>) -> Value {
        let limit = limit.clamp(1, RECENT_ERRORS_CAPACITY);
        let inner = self.inner.lock();
        let total_buffered = inner.recent_errors.len();
        let errors: Vec<RecentError> = inner
            .recent_errors
            .iter()
            .rev()
            .filter(|item| code.is_none_or(|value| item.code == value))
            .filter(|item| bucket.is_none_or(|value| item.bucket.as_deref() == Some(value)))
            .take(limit)
            .cloned()
            .collect();
        json!({
            "enabled": true,
            "total_buffered": total_buffered,
            "errors": errors,
        })
    }

    pub fn snapshot(&self) -> Value {
        let current = self.get_current_stats();
        let history = self.get_history(None);
        json!({
            "enabled": true,
            "current": current,
            "snapshots": history,
        })
    }

    fn take_snapshot(&self) {
        if self.take_snapshot_inner() {
            self.save_snapshots();
        }
    }

    fn take_snapshot_inner(&self) -> bool {
        let mut should_save = false;
        {
            let mut inner = self.inner.lock();
            let window_seconds = (now_secs() - inner.window_start).max(0.0) as u64;
            let cutoff = now_secs() - (self.config.retention_hours * 3600) as f64;
            let before_prune = inner.snapshots.len();
            inner
                .snapshots
                .retain(|s| s.timestamp.timestamp() as f64 > cutoff);
            should_save |= inner.snapshots.len() != before_prune;

            if inner.totals.count == 0 {
                inner.by_method.clear();
                inner.by_endpoint.clear();
                inner.by_status_class.clear();
                inner.error_codes.clear();
                inner.error_buckets.clear();
                inner.window_start = now_secs();
                return should_save;
            }

            let by_method: HashMap<String, Value> = inner
                .by_method
                .iter()
                .map(|(k, v)| (k.clone(), v.to_json()))
                .collect();
            let by_endpoint: HashMap<String, Value> = inner
                .by_endpoint
                .iter()
                .map(|(k, v)| (k.clone(), v.to_json()))
                .collect();

            let snap = MetricsSnapshot {
                timestamp: Utc::now(),
                window_seconds,
                by_method,
                by_endpoint,
                by_status_class: inner.by_status_class.clone(),
                error_codes: inner.error_codes.clone(),
                error_buckets: inner.error_buckets.clone(),
                totals: inner.totals.to_json(),
            };

            inner.snapshots.push(snap);

            inner.by_method.clear();
            inner.by_endpoint.clear();
            inner.by_status_class.clear();
            inner.error_codes.clear();
            inner.error_buckets.clear();
            inner.totals = OperationStats::default();
            inner.window_start = now_secs();
            should_save = true;
        }
        should_save
    }

    fn save_snapshots(&self) {
        let snapshots = { self.inner.lock().snapshots.clone() };
        if let Some(parent) = self.snapshots_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = json!({ "snapshots": snapshots });
        let serialized = serde_json::to_string_pretty(&data).unwrap_or_default();
        let tmp = self.snapshots_path.with_extension("json.tmp");
        if std::fs::write(&tmp, serialized).is_ok() {
            let _ = std::fs::rename(&tmp, &self.snapshots_path);
        }
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = std::time::Duration::from_secs(self.config.interval_minutes * 60);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                self.take_snapshot();
            }
        })
    }

    pub fn flush(&self) {
        let has_live_requests = { self.inner.lock().totals.count > 0 };
        if has_live_requests {
            self.take_snapshot();
        }
    }
}

fn record_error_bucket(
    error_buckets: &mut HashMap<String, HashMap<String, u64>>,
    bucket: &str,
    code: &str,
) {
    let target = if error_buckets.contains_key(bucket) || error_buckets.len() < MAX_ERROR_BUCKETS {
        bucket
    } else {
        OTHER_BUCKET
    };
    *error_buckets
        .entry(target.to_string())
        .or_default()
        .entry(code.to_string())
        .or_insert(0) += 1;
}

fn merge_counts(target: &mut HashMap<String, u64>, source: &HashMap<String, u64>) {
    for (key, count) in source {
        *target.entry(key.clone()).or_insert(0) += *count;
    }
}

fn merge_bucket_counts(
    target: &mut HashMap<String, HashMap<String, u64>>,
    source: &HashMap<String, HashMap<String, u64>>,
) {
    for (bucket, codes) in source {
        let entry = target.entry(bucket.clone()).or_default();
        merge_counts(entry, codes);
    }
}

fn load_snapshots(path: &Path) -> Vec<MetricsSnapshot> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<Value>(&raw) {
        Ok(value) => value
            .get("snapshots")
            .and_then(|snapshots| {
                serde_json::from_value::<Vec<MetricsSnapshot>>(snapshots.clone()).ok()
            })
            .unwrap_or_default(),
        Err(err) => {
            rename_corrupt_file(path, err.to_string());
            Vec::new()
        }
    }
}

fn rename_corrupt_file(path: &Path, error: String) {
    let ts = Utc::now().timestamp();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operation_metrics.json");
    let corrupt_path = path.with_file_name(format!("{name}.corrupt-{ts}"));
    match std::fs::rename(path, &corrupt_path) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            corrupt_path = %corrupt_path.display(),
            error = %error,
            "Renamed corrupt operation metrics file"
        ),
        Err(rename_err) => tracing::warn!(
            path = %path.display(),
            error = %error,
            rename_error = %rename_err,
            "Failed to rename corrupt operation metrics file"
        ),
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;
    use tempfile::tempdir;

    fn service(root: &Path) -> MetricsService {
        MetricsService::new(
            root,
            MetricsConfig {
                interval_minutes: 5,
                retention_hours: 1,
            },
        )
    }

    fn record_api_error(metrics: &MetricsService, code: &str, bucket: &str, index: usize) {
        metrics.record_request(
            "GET",
            "object",
            404,
            index as f64,
            0,
            0,
            Some(code),
            Some(bucket),
            Some("key"),
            Some(&format!("req-{index}")),
            "api",
        );
    }

    #[test]
    fn recent_errors_ring_capacity_and_filtering() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        for i in 0..300 {
            let code = if i % 2 == 0 {
                "NoSuchKey"
            } else {
                "AccessDenied"
            };
            record_api_error(&metrics, code, "bucket-a", i);
        }

        let all = metrics.recent_errors(256, None, None);
        assert_eq!(all["total_buffered"], 256);
        assert_eq!(all["errors"].as_array().unwrap().len(), 256);
        assert_eq!(all["errors"][0]["request_id"], "req-299");
        assert_eq!(all["errors"][255]["request_id"], "req-44");

        let filtered = metrics.recent_errors(10, Some("NoSuchKey"), Some("bucket-a"));
        let errors = filtered["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 10);
        assert!(errors.iter().all(|item| item["code"] == "NoSuchKey"));
        assert!(errors.iter().all(|item| item["bucket"] == "bucket-a"));
    }

    #[test]
    fn bucket_cap_overflows_to_other() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        for i in 0..52 {
            record_api_error(&metrics, "AccessDenied", &format!("bucket-{i}"), i);
        }

        let stats = metrics.get_current_stats();
        let buckets = stats["error_buckets"].as_object().unwrap();
        assert!(buckets.contains_key(OTHER_BUCKET));
        assert_eq!(buckets[OTHER_BUCKET]["AccessDenied"], 2);
        assert!(!buckets.contains_key("bucket-50"));
    }

    #[test]
    fn error_summary_merges_live_and_snapshots_and_clamps_hours() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        record_api_error(&metrics, "AccessDenied", "bucket-a", 1);
        record_api_error(&metrics, "AccessDenied", "bucket-a", 2);
        metrics.take_snapshot();
        record_api_error(&metrics, "NoSuchKey", "bucket-b", 3);

        let summary = metrics.error_summary(24);
        assert_eq!(summary["hours"], 1);
        assert_eq!(summary["total_errors"], 3);
        assert_eq!(summary["error_codes"]["AccessDenied"], 2);
        assert_eq!(summary["error_codes"]["NoSuchKey"], 1);
        assert_eq!(summary["error_buckets"]["bucket-a"]["AccessDenied"], 2);
        assert_eq!(summary["error_buckets"]["bucket-b"]["NoSuchKey"], 1);
    }

    #[test]
    fn empty_window_snapshot_skips_append_and_writes_only_when_pruned() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        metrics.take_snapshot();
        assert!(metrics.get_history(None).is_empty());
        assert!(!metrics.snapshots_path.exists());

        {
            let mut inner = metrics.inner.lock();
            inner.snapshots.push(MetricsSnapshot {
                timestamp: Utc::now() - Duration::hours(2),
                window_seconds: 300,
                by_method: HashMap::new(),
                by_endpoint: HashMap::new(),
                by_status_class: HashMap::new(),
                error_codes: HashMap::new(),
                error_buckets: HashMap::new(),
                totals: json!({ "count": 1 }),
            });
        }
        metrics.take_snapshot();
        assert!(metrics.get_history(None).is_empty());
        assert!(metrics.snapshots_path.exists());
        let saved: Value =
            serde_json::from_str(&std::fs::read_to_string(&metrics.snapshots_path).unwrap())
                .unwrap();
        assert_eq!(saved["snapshots"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn corrupt_snapshot_file_is_renamed_on_load() {
        let tmp = tempdir().unwrap();
        let path = tmp
            .path()
            .join(".myfsio.sys")
            .join("config")
            .join("operation_metrics.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{not json").unwrap();

        let metrics = service(tmp.path());
        assert!(metrics.get_history(None).is_empty());
        assert!(!path.exists());
        let entries: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert!(entries
            .iter()
            .any(|name| name.starts_with("operation_metrics.json.corrupt-")));
    }

    #[test]
    fn snapshot_deserializes_with_and_without_error_buckets() {
        let tmp = tempdir().unwrap();
        let path = tmp
            .path()
            .join(".myfsio.sys")
            .join("config")
            .join("operation_metrics.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "snapshots": [
                    {
                        "timestamp": Utc::now(),
                        "window_seconds": 300,
                        "by_method": {},
                        "by_endpoint": {},
                        "by_status_class": {},
                        "error_codes": { "AccessDenied": 1 },
                        "totals": { "count": 1 }
                    },
                    {
                        "timestamp": Utc::now(),
                        "window_seconds": 300,
                        "by_method": {},
                        "by_endpoint": {},
                        "by_status_class": {},
                        "error_codes": { "NoSuchKey": 2 },
                        "error_buckets": { "bucket-a": { "NoSuchKey": 2 } },
                        "totals": { "count": 2 }
                    }
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let metrics = service(tmp.path());
        let history = metrics.get_history(None);
        assert_eq!(history.len(), 2);
        assert!(history[0].error_buckets.is_empty());
        assert_eq!(history[1].error_buckets["bucket-a"]["NoSuchKey"], 2);
    }
}
