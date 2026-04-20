use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_LATENCY_SAMPLES: usize = 5000;

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
    pub totals: Value,
}

struct Inner {
    by_method: HashMap<String, OperationStats>,
    by_endpoint: HashMap<String, OperationStats>,
    by_status_class: HashMap<String, u64>,
    error_codes: HashMap<String, u64>,
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

        let mut snapshots: Vec<MetricsSnapshot> = if snapshots_path.exists() {
            std::fs::read_to_string(&snapshots_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| {
                    v.get("snapshots").and_then(|s| {
                        serde_json::from_value::<Vec<MetricsSnapshot>>(s.clone()).ok()
                    })
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let cutoff = now_secs() - (config.retention_hours * 3600) as f64;
        snapshots.retain(|s| s.timestamp.timestamp() as f64 > cutoff);

        Self {
            config,
            inner: Arc::new(Mutex::new(Inner {
                by_method: HashMap::new(),
                by_endpoint: HashMap::new(),
                by_status_class: HashMap::new(),
                error_codes: HashMap::new(),
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
        }
        inner
            .totals
            .record(latency_ms, success, bytes_in, bytes_out);
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
        let snapshot = {
            let mut inner = self.inner.lock();
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

            let snap = MetricsSnapshot {
                timestamp: Utc::now(),
                window_seconds,
                by_method,
                by_endpoint,
                by_status_class: inner.by_status_class.clone(),
                error_codes: inner.error_codes.clone(),
                totals: inner.totals.to_json(),
            };

            inner.snapshots.push(snap.clone());
            let cutoff = now_secs() - (self.config.retention_hours * 3600) as f64;
            inner
                .snapshots
                .retain(|s| s.timestamp.timestamp() as f64 > cutoff);

            inner.by_method.clear();
            inner.by_endpoint.clear();
            inner.by_status_class.clear();
            inner.error_codes.clear();
            inner.totals = OperationStats::default();
            inner.window_start = now_secs();

            snap
        };
        let _ = snapshot;
        self.save_snapshots();
    }

    fn save_snapshots(&self) {
        let snapshots = { self.inner.lock().snapshots.clone() };
        if let Some(parent) = self.snapshots_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = json!({ "snapshots": snapshots });
        let _ = std::fs::write(
            &self.snapshots_path,
            serde_json::to_string_pretty(&data).unwrap_or_default(),
        );
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
}

pub fn classify_endpoint(path: &str) -> &'static str {
    if path.is_empty() || path == "/" {
        return "service";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.starts_with("/ui") {
        return "ui";
    }
    if trimmed.starts_with("/kms") {
        return "kms";
    }
    if trimmed.starts_with("/myfsio") {
        return "service";
    }
    let parts: Vec<&str> = trimmed.trim_start_matches('/').split('/').collect();
    match parts.len() {
        0 => "service",
        1 => "bucket",
        _ => "object",
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
