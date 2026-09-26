use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_ERROR_BUCKETS: usize = 50;
const RECENT_ERRORS_CAPACITY: usize = 256;
const OTHER_BUCKET: &str = "(other)";
const LATENCY_BUCKETS: usize = 80;
const LATENCY_BASE_MS: f64 = 0.05;
const LATENCY_GROWTH: f64 = 1.25;
const SERVER_ERROR_CODES: [&str; 4] = [
    "InternalError",
    "ServiceUnavailable",
    "SlowDown",
    "NotImplemented",
];

pub const SOURCE_API: &str = "api";
pub const SOURCE_UI: &str = "ui";
pub const SOURCE_INTERNAL: &str = "internal";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsScope {
    All,
    Api,
    Ui,
    Internal,
}

impl MetricsScope {
    pub fn parse(value: Option<&str>) -> Self {
        match value
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("api") => Self::Api,
            Some("ui") => Self::Ui,
            Some("internal") => Self::Internal,
            _ => Self::All,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Api => SOURCE_API,
            Self::Ui => SOURCE_UI,
            Self::Internal => SOURCE_INTERNAL,
        }
    }

    fn includes(self, source: &str) -> bool {
        match self {
            Self::All => true,
            Self::Api => source == SOURCE_API,
            Self::Ui => source == SOURCE_UI,
            Self::Internal => source == SOURCE_INTERNAL,
        }
    }
}

fn latency_bucket(latency_ms: f64) -> usize {
    if latency_ms.is_nan() || latency_ms < LATENCY_BASE_MS {
        return 0;
    }
    let index = ((latency_ms / LATENCY_BASE_MS).ln() / LATENCY_GROWTH.ln()).floor();
    if !index.is_finite() {
        return LATENCY_BUCKETS - 1;
    }
    (index as usize + 1).min(LATENCY_BUCKETS - 1)
}

fn latency_bucket_bounds(index: usize) -> (f64, f64) {
    if index == 0 {
        return (0.0, LATENCY_BASE_MS);
    }
    (
        LATENCY_BASE_MS * LATENCY_GROWTH.powi(index as i32 - 1),
        LATENCY_BASE_MS * LATENCY_GROWTH.powi(index as i32),
    )
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
    latency_hist: Vec<u64>,
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
            latency_hist: vec![0; LATENCY_BUCKETS],
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
        self.latency_hist[latency_bucket(latency_ms)] += 1;
    }

    fn merge(&mut self, other: &OperationStats) {
        self.count += other.count;
        self.success_count += other.success_count;
        self.error_count += other.error_count;
        self.latency_sum_ms += other.latency_sum_ms;
        self.latency_min_ms = self.latency_min_ms.min(other.latency_min_ms);
        self.latency_max_ms = self.latency_max_ms.max(other.latency_max_ms);
        self.bytes_in += other.bytes_in;
        self.bytes_out += other.bytes_out;
        for (slot, count) in self.latency_hist.iter_mut().zip(&other.latency_hist) {
            *slot += *count;
        }
    }

    fn percentile(&self, p: f64) -> f64 {
        let total: u64 = self.latency_hist.iter().sum();
        if self.count == 0 || total == 0 {
            return 0.0;
        }
        let rank = (p / 100.0) * total as f64;
        let mut cumulative = 0u64;
        for (index, count) in self.latency_hist.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            if (cumulative + count) as f64 >= rank {
                let fraction = ((rank - cumulative as f64) / *count as f64).clamp(0.0, 1.0);
                let (low, high) = latency_bucket_bounds(index);
                let value = low + fraction * (high - low);
                let floor = if self.latency_min_ms.is_finite() {
                    self.latency_min_ms
                } else {
                    0.0
                };
                return value.clamp(floor, self.latency_max_ms.max(floor));
            }
            cumulative += count;
        }
        self.latency_max_ms
    }

    fn to_json(&self, include_hist: bool) -> Value {
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
        let mut value = json!({
            "count": self.count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "latency_avg_ms": round2(avg),
            "latency_min_ms": round2(min),
            "latency_max_ms": round2(self.latency_max_ms),
            "latency_p50_ms": round2(self.percentile(50.0)),
            "latency_p95_ms": round2(self.percentile(95.0)),
            "latency_p99_ms": round2(self.percentile(99.0)),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        });
        if include_hist {
            let pairs: Vec<[u64; 2]> = self
                .latency_hist
                .iter()
                .enumerate()
                .filter(|(_, count)| **count > 0)
                .map(|(index, count)| [index as u64, *count])
                .collect();
            value["latency_hist"] = json!(pairs);
        }
        value
    }

    fn from_json(value: &Value) -> Self {
        let read_u64 = |name: &str| value.get(name).and_then(Value::as_u64).unwrap_or(0);
        let read_f64 = |name: &str| value.get(name).and_then(Value::as_f64).unwrap_or(0.0);
        let count = read_u64("count");
        let mut stats = OperationStats {
            count,
            success_count: read_u64("success_count"),
            error_count: read_u64("error_count"),
            latency_sum_ms: read_f64("latency_avg_ms") * count as f64,
            latency_min_ms: if count > 0 {
                read_f64("latency_min_ms")
            } else {
                f64::INFINITY
            },
            latency_max_ms: read_f64("latency_max_ms"),
            bytes_in: read_u64("bytes_in"),
            bytes_out: read_u64("bytes_out"),
            latency_hist: vec![0; LATENCY_BUCKETS],
        };
        if let Some(pairs) = value.get("latency_hist").and_then(Value::as_array) {
            for pair in pairs {
                let index = pair.get(0).and_then(Value::as_u64).unwrap_or(u64::MAX) as usize;
                let bucket_count = pair.get(1).and_then(Value::as_u64).unwrap_or(0);
                if index < LATENCY_BUCKETS {
                    stats.latency_hist[index] += bucket_count;
                }
            }
        } else if count > 0 {
            let median = count / 2;
            let upper = count * 45 / 100;
            let tail = count * 4 / 100;
            let rest = count - median - upper - tail;
            stats.latency_hist[latency_bucket(read_f64("latency_p50_ms"))] += median;
            stats.latency_hist[latency_bucket(read_f64("latency_p95_ms"))] += upper;
            stats.latency_hist[latency_bucket(read_f64("latency_p99_ms"))] += tail;
            stats.latency_hist[latency_bucket(stats.latency_max_ms)] += rest;
        }
        stats
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceSnapshot {
    #[serde(default)]
    pub by_method: HashMap<String, Value>,
    #[serde(default)]
    pub by_endpoint: HashMap<String, Value>,
    #[serde(default)]
    pub by_status_class: HashMap<String, u64>,
    #[serde(default)]
    pub error_codes: HashMap<String, u64>,
    #[serde(default)]
    pub error_buckets: HashMap<String, HashMap<String, u64>>,
    #[serde(default)]
    pub totals: Value,
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
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub by_source: HashMap<String, SourceSnapshot>,
}

impl MetricsSnapshot {
    fn epoch_secs(&self) -> f64 {
        self.timestamp.timestamp_millis() as f64 / 1000.0
    }
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

#[derive(Debug, Clone, Default)]
struct Window {
    by_method: HashMap<String, OperationStats>,
    by_endpoint: HashMap<String, OperationStats>,
    by_status_class: HashMap<String, u64>,
    error_codes: HashMap<String, u64>,
    error_buckets: HashMap<String, HashMap<String, u64>>,
    totals: OperationStats,
}

impl Window {
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        method: &str,
        endpoint_type: &str,
        status_code: u16,
        latency_ms: f64,
        bytes_in: u64,
        bytes_out: u64,
        error_code: Option<&str>,
        bucket: Option<&str>,
    ) {
        let success = (200..400).contains(&status_code);
        self.by_method
            .entry(method.to_string())
            .or_default()
            .record(latency_ms, success, bytes_in, bytes_out);
        self.by_endpoint
            .entry(endpoint_type.to_string())
            .or_default()
            .record(latency_ms, success, bytes_in, bytes_out);
        *self
            .by_status_class
            .entry(format!("{}xx", status_code / 100))
            .or_insert(0) += 1;
        if let Some(code) = error_code {
            *self.error_codes.entry(code.to_string()).or_insert(0) += 1;
            if let Some(bucket_name) = bucket {
                record_error_bucket(&mut self.error_buckets, bucket_name, code);
            }
        }
        self.totals.record(latency_ms, success, bytes_in, bytes_out);
    }

    fn is_empty(&self) -> bool {
        self.totals.count == 0
    }

    fn merge(&mut self, other: &Window) {
        merge_stats(&mut self.by_method, &other.by_method);
        merge_stats(&mut self.by_endpoint, &other.by_endpoint);
        merge_counts(&mut self.by_status_class, &other.by_status_class);
        merge_counts(&mut self.error_codes, &other.error_codes);
        merge_bucket_counts(&mut self.error_buckets, &other.error_buckets);
        self.totals.merge(&other.totals);
    }

    fn from_parts(
        by_method: &HashMap<String, Value>,
        by_endpoint: &HashMap<String, Value>,
        by_status_class: &HashMap<String, u64>,
        error_codes: &HashMap<String, u64>,
        error_buckets: &HashMap<String, HashMap<String, u64>>,
        totals: &Value,
    ) -> Self {
        Self {
            by_method: parse_stats(by_method),
            by_endpoint: parse_stats(by_endpoint),
            by_status_class: by_status_class.clone(),
            error_codes: error_codes.clone(),
            error_buckets: error_buckets.clone(),
            totals: OperationStats::from_json(totals),
        }
    }

    fn to_source_snapshot(&self) -> SourceSnapshot {
        SourceSnapshot {
            by_method: stats_json(&self.by_method, true),
            by_endpoint: stats_json(&self.by_endpoint, true),
            by_status_class: self.by_status_class.clone(),
            error_codes: self.error_codes.clone(),
            error_buckets: self.error_buckets.clone(),
            totals: self.totals.to_json(true),
        }
    }

    fn to_public_snapshot(&self, timestamp: DateTime<Utc>, window_seconds: u64) -> MetricsSnapshot {
        MetricsSnapshot {
            timestamp,
            window_seconds,
            by_method: stats_json(&self.by_method, false),
            by_endpoint: stats_json(&self.by_endpoint, false),
            by_status_class: self.by_status_class.clone(),
            error_codes: self.error_codes.clone(),
            error_buckets: self.error_buckets.clone(),
            totals: self.totals.to_json(false),
            by_source: HashMap::new(),
        }
    }
}

fn is_ui_endpoint(endpoint: &str) -> bool {
    endpoint == "ui" || endpoint.starts_with("ui_")
}

fn legacy_scoped(all: Window, scope: MetricsScope) -> Window {
    let want_ui = match scope {
        MetricsScope::All => return all,
        MetricsScope::Internal => return Window::default(),
        MetricsScope::Ui => true,
        MetricsScope::Api => false,
    };
    let has_ui = all.by_endpoint.keys().any(|key| is_ui_endpoint(key));
    let has_api = all.by_endpoint.keys().any(|key| !is_ui_endpoint(key));
    let (wanted_present, other_present) = if want_ui {
        (has_ui, has_api)
    } else {
        (has_api, has_ui)
    };
    if !wanted_present {
        return Window::default();
    }
    if !other_present {
        return all;
    }

    let mut scoped = Window::default();
    for (endpoint, stats) in all.by_endpoint {
        if is_ui_endpoint(&endpoint) == want_ui {
            scoped.totals.merge(&stats);
            scoped.by_endpoint.insert(endpoint, stats);
        }
    }
    let errors = scoped.totals.error_count;
    let server_errors = if want_ui {
        0
    } else {
        let server: u64 = all
            .error_codes
            .iter()
            .filter(|(code, _)| SERVER_ERROR_CODES.contains(&code.as_str()))
            .map(|(_, count)| *count)
            .sum();
        scoped.error_codes = all.error_codes;
        scoped.error_buckets = all.error_buckets;
        server.min(errors)
    };
    for (class, count) in [
        ("2xx", scoped.totals.success_count),
        ("4xx", errors - server_errors),
        ("5xx", server_errors),
    ] {
        if count > 0 {
            scoped.by_status_class.insert(class.to_string(), count);
        }
    }
    scoped
}

fn scoped_window(snapshot: &MetricsSnapshot, scope: MetricsScope) -> Window {
    if !snapshot.by_source.is_empty() {
        let mut window = Window::default();
        for (source, part) in &snapshot.by_source {
            if scope.includes(source) {
                window.merge(&Window::from_parts(
                    &part.by_method,
                    &part.by_endpoint,
                    &part.by_status_class,
                    &part.error_codes,
                    &part.error_buckets,
                    &part.totals,
                ));
            }
        }
        return window;
    }
    let all = Window::from_parts(
        &snapshot.by_method,
        &snapshot.by_endpoint,
        &snapshot.by_status_class,
        &snapshot.error_codes,
        &snapshot.error_buckets,
        &snapshot.totals,
    );
    legacy_scoped(all, scope)
}

fn parse_stats(source: &HashMap<String, Value>) -> HashMap<String, OperationStats> {
    source
        .iter()
        .map(|(key, value)| (key.clone(), OperationStats::from_json(value)))
        .collect()
}

fn stats_json(
    source: &HashMap<String, OperationStats>,
    include_hist: bool,
) -> HashMap<String, Value> {
    source
        .iter()
        .map(|(key, stats)| (key.clone(), stats.to_json(include_hist)))
        .collect()
}

fn merge_stats(
    target: &mut HashMap<String, OperationStats>,
    source: &HashMap<String, OperationStats>,
) {
    for (key, stats) in source {
        target.entry(key.clone()).or_default().merge(stats);
    }
}

fn window_view(window: &Window, scope: MetricsScope, window_seconds: u64) -> Value {
    json!({
        "timestamp": Utc::now().to_rfc3339(),
        "scope": scope.as_str(),
        "window_seconds": window_seconds,
        "by_method": stats_json(&window.by_method, false),
        "by_endpoint": stats_json(&window.by_endpoint, false),
        "by_status_class": window.by_status_class,
        "error_codes": window.error_codes,
        "error_buckets": window.error_buckets,
        "totals": window.totals.to_json(false),
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecentStatusCounts {
    pub requests: u64,
    pub server_errors: u64,
    pub client_errors: u64,
    pub window_seconds: u64,
}

struct RangeWindow {
    window: Window,
    live: Window,
    hours: u64,
    window_seconds: u64,
    live_window_seconds: u64,
    snapshot_count: usize,
}

struct Inner {
    windows: HashMap<&'static str, Window>,
    recent_errors: HashMap<&'static str, VecDeque<RecentError>>,
    window_start: f64,
    snapshots: Vec<Arc<MetricsSnapshot>>,
}

impl Inner {
    fn live_window(&self, scope: MetricsScope) -> Window {
        let mut window = Window::default();
        for (source, part) in &self.windows {
            if scope.includes(source) {
                window.merge(part);
            }
        }
        window
    }
}

pub struct MetricsService {
    config: MetricsConfig,
    inner: Arc<Mutex<Inner>>,
    snapshots_path: PathBuf,
    started_at: f64,
}

impl MetricsService {
    pub fn new(storage_root: &Path, config: MetricsConfig) -> Self {
        let snapshots_path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("operation_metrics.json");

        let mut snapshots = load_snapshots(&snapshots_path);
        let cutoff = now_secs() - (config.retention_hours * 3600) as f64;
        snapshots.retain(|s| s.epoch_secs() > cutoff);
        let started_at = now_secs();

        Self {
            config,
            inner: Arc::new(Mutex::new(Inner {
                windows: HashMap::new(),
                recent_errors: HashMap::new(),
                window_start: started_at,
                snapshots: snapshots.into_iter().map(Arc::new).collect(),
            })),
            snapshots_path,
            started_at,
        }
    }

    #[allow(clippy::too_many_arguments)]
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
        let mut inner = self.inner.lock();
        inner.windows.entry(source).or_default().record(
            method,
            endpoint_type,
            status_code,
            latency_ms,
            bytes_in,
            bytes_out,
            error_code,
            bucket,
        );

        if status_code >= 400 {
            let code = match error_code {
                Some(code) => code,
                None if source == SOURCE_UI => "UIError",
                None => "Other",
            };
            let ring = inner
                .recent_errors
                .entry(source)
                .or_insert_with(|| VecDeque::with_capacity(RECENT_ERRORS_CAPACITY));
            if ring.len() == RECENT_ERRORS_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(RecentError {
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

    pub fn record_bytes_out(
        &self,
        source: &'static str,
        method: &str,
        endpoint_type: &str,
        bytes: u64,
    ) {
        if bytes == 0 {
            return;
        }
        let mut inner = self.inner.lock();
        let window = inner.windows.entry(source).or_default();
        window.totals.bytes_out += bytes;
        if let Some(stats) = window.by_method.get_mut(method) {
            stats.bytes_out += bytes;
        }
        if let Some(stats) = window.by_endpoint.get_mut(endpoint_type) {
            stats.bytes_out += bytes;
        }
    }

    pub fn get_current_stats(&self, scope: MetricsScope) -> Value {
        let (window, window_seconds) = {
            let inner = self.inner.lock();
            (
                inner.live_window(scope),
                (now_secs() - inner.window_start).max(0.0) as u64,
            )
        };
        window_view(&window, scope, window_seconds)
    }

    fn clamp_hours(&self, hours: u64) -> u64 {
        hours.clamp(1, self.config.retention_hours.max(1))
    }

    fn collect_range(&self, hours: u64, scope: MetricsScope) -> RangeWindow {
        let hours = self.clamp_hours(hours);
        let mut range = self.collect_span(hours * 3600, scope);
        range.hours = hours;
        range
    }

    fn collect_span(&self, span_seconds: u64, scope: MetricsScope) -> RangeWindow {
        let span_seconds = span_seconds.min(self.config.retention_hours.max(1) * 3600);
        let now = now_secs();
        let cutoff = now - span_seconds as f64;
        let (snapshots, live, window_start) = {
            let inner = self.inner.lock();
            let snapshots: Vec<Arc<MetricsSnapshot>> = inner
                .snapshots
                .iter()
                .filter(|s| s.epoch_secs() > cutoff)
                .cloned()
                .collect();
            (snapshots, inner.live_window(scope), inner.window_start)
        };

        let mut window = Window::default();
        let mut coverage_start = self.started_at.min(window_start);
        for snapshot in &snapshots {
            window.merge(&scoped_window(snapshot, scope));
            coverage_start =
                coverage_start.min(snapshot.epoch_secs() - snapshot.window_seconds as f64);
        }
        window.merge(&live);
        let coverage_start = coverage_start.max(cutoff);
        RangeWindow {
            window,
            live,
            hours: span_seconds / 3600,
            window_seconds: (now - coverage_start).max(1.0) as u64,
            live_window_seconds: (now - window_start).max(0.0) as u64,
            snapshot_count: snapshots.len(),
        }
    }

    pub fn recent_status_counts(
        &self,
        span_seconds: u64,
        scope: MetricsScope,
    ) -> RecentStatusCounts {
        let range = self.collect_span(span_seconds, scope);
        let class = |name: &str| range.window.by_status_class.get(name).copied().unwrap_or(0);
        RecentStatusCounts {
            requests: range.window.totals.count,
            server_errors: class("5xx"),
            client_errors: class("4xx"),
            window_seconds: range.window_seconds,
        }
    }

    pub fn range_stats(&self, hours: u64, scope: MetricsScope) -> Value {
        let range = self.collect_range(hours, scope);
        let mut view = window_view(&range.window, scope, range.window_seconds);
        view["hours"] = json!(range.hours);
        view["live_window_seconds"] = json!(range.live_window_seconds);
        view["snapshot_count"] = json!(range.snapshot_count);
        view["live"] = json!({
            "window_seconds": range.live_window_seconds,
            "count": range.live.totals.count,
            "by_status_class": range.live.by_status_class,
        });
        view
    }

    pub fn get_history(&self, hours: Option<u64>, scope: MetricsScope) -> Vec<MetricsSnapshot> {
        let snapshots: Vec<Arc<MetricsSnapshot>> = {
            let inner = self.inner.lock();
            match hours {
                Some(h) => {
                    let cutoff = now_secs() - (h * 3600) as f64;
                    inner
                        .snapshots
                        .iter()
                        .filter(|s| s.epoch_secs() > cutoff)
                        .cloned()
                        .collect()
                }
                None => inner.snapshots.clone(),
            }
        };
        snapshots
            .iter()
            .map(|snapshot| {
                scoped_window(snapshot, scope)
                    .to_public_snapshot(snapshot.timestamp, snapshot.window_seconds)
            })
            .collect()
    }

    pub fn interval_minutes(&self) -> u64 {
        self.config.interval_minutes
    }

    pub fn retention_hours(&self) -> u64 {
        self.config.retention_hours
    }

    pub fn error_summary(&self, hours: u64, scope: MetricsScope) -> Value {
        let range = self.collect_range(hours, scope);
        let total_errors = range.window.error_codes.values().sum::<u64>();
        json!({
            "enabled": true,
            "hours": range.hours,
            "scope": scope.as_str(),
            "total_errors": total_errors,
            "error_codes": range.window.error_codes,
            "error_buckets": range.window.error_buckets,
            "window_included": true,
        })
    }

    pub fn recent_errors(
        &self,
        limit: usize,
        code: Option<&str>,
        bucket: Option<&str>,
        scope: MetricsScope,
        hours: Option<u64>,
    ) -> Value {
        let limit = limit.clamp(1, RECENT_ERRORS_CAPACITY);
        let cutoff = hours.map(|h| Utc::now() - chrono::Duration::hours(h as i64));
        let inner = self.inner.lock();
        let mut total_buffered = 0usize;
        let mut items: Vec<&RecentError> = Vec::new();
        for (source, ring) in &inner.recent_errors {
            if scope.includes(source) {
                total_buffered += ring.len();
                items.extend(ring.iter().rev());
            }
        }
        items.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let errors: Vec<RecentError> = items
            .into_iter()
            .filter(|item| cutoff.is_none_or(|value| item.timestamp >= value))
            .filter(|item| code.is_none_or(|value| item.code == value))
            .filter(|item| bucket.is_none_or(|value| item.bucket.as_deref() == Some(value)))
            .take(limit)
            .cloned()
            .collect();
        json!({
            "enabled": true,
            "scope": scope.as_str(),
            "total_buffered": total_buffered,
            "errors": errors,
        })
    }

    fn take_snapshot(&self) {
        if self.take_snapshot_inner() {
            if let Err(err) = self.save_snapshots() {
                tracing::error!(
                    path = %self.snapshots_path.display(),
                    error = %err,
                    "Failed to persist operation metrics history; the window just closed is live-only and will be lost on restart"
                );
            }
        }
    }

    fn take_snapshot_inner(&self) -> bool {
        let mut inner = self.inner.lock();
        let now = now_secs();
        let window_seconds = (now - inner.window_start).max(0.0) as u64;
        let cutoff = now - (self.config.retention_hours * 3600) as f64;
        let before_prune = inner.snapshots.len();
        inner.snapshots.retain(|s| s.epoch_secs() > cutoff);
        let pruned = inner.snapshots.len() != before_prune;

        if inner.windows.values().all(Window::is_empty) {
            inner.windows.clear();
            inner.window_start = now;
            return pruned;
        }

        let mut all = Window::default();
        let mut by_source = HashMap::new();
        for (source, window) in &inner.windows {
            if window.is_empty() {
                continue;
            }
            all.merge(window);
            by_source.insert(source.to_string(), window.to_source_snapshot());
        }
        let mut snapshot = all.to_public_snapshot(Utc::now(), window_seconds);
        snapshot.by_source = by_source;
        inner.snapshots.push(Arc::new(snapshot));
        inner.windows.clear();
        inner.window_start = now;
        true
    }

    fn save_snapshots(&self) -> std::io::Result<()> {
        let snapshots = { self.inner.lock().snapshots.clone() };
        let refs: Vec<&MetricsSnapshot> = snapshots.iter().map(Arc::as_ref).collect();
        let data = json!({ "snapshots": refs });
        myfsio_common::fs_util::atomic_write_json(&self.snapshots_path, &data)
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
        let has_live_requests = {
            let inner = self.inner.lock();
            inner.windows.values().any(|window| !window.is_empty())
        };
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
            SOURCE_API,
        );
    }

    fn record_ok(metrics: &MetricsService, endpoint: &str, latency_ms: f64, source: &'static str) {
        metrics.record_request(
            "GET", endpoint, 200, latency_ms, 10, 20, None, None, None, None, source,
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

        let all = metrics.recent_errors(256, None, None, MetricsScope::All, None);
        assert_eq!(all["total_buffered"], 256);
        assert_eq!(all["errors"].as_array().unwrap().len(), 256);
        assert_eq!(all["errors"][0]["request_id"], "req-299");
        assert_eq!(all["errors"][255]["request_id"], "req-44");

        let filtered = metrics.recent_errors(
            10,
            Some("NoSuchKey"),
            Some("bucket-a"),
            MetricsScope::Api,
            Some(1),
        );
        let errors = filtered["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 10);
        assert!(errors.iter().all(|item| item["code"] == "NoSuchKey"));
        assert!(errors.iter().all(|item| item["bucket"] == "bucket-a"));
    }

    #[test]
    fn recent_errors_keep_separate_rings_per_source() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        record_api_error(&metrics, "NoSuchKey", "bucket-a", 1);
        for _ in 0..300 {
            metrics.record_request(
                "GET", "ui_other", 401, 1.0, 0, 0, None, None, None, None, SOURCE_UI,
            );
        }

        let api = metrics.recent_errors(256, None, None, MetricsScope::Api, None);
        assert_eq!(api["total_buffered"], 1);
        assert_eq!(api["errors"][0]["code"], "NoSuchKey");

        let ui = metrics.recent_errors(256, None, None, MetricsScope::Ui, None);
        assert_eq!(ui["total_buffered"], 256);
        assert!(ui["errors"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["code"] == "UIError"));
    }

    #[test]
    fn bucket_cap_overflows_to_other() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        for i in 0..52 {
            record_api_error(&metrics, "AccessDenied", &format!("bucket-{i}"), i);
        }

        let stats = metrics.get_current_stats(MetricsScope::All);
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

        let summary = metrics.error_summary(24, MetricsScope::All);
        assert_eq!(summary["hours"], 1);
        assert_eq!(summary["total_errors"], 3);
        assert_eq!(summary["error_codes"]["AccessDenied"], 2);
        assert_eq!(summary["error_codes"]["NoSuchKey"], 1);
        assert_eq!(summary["error_buckets"]["bucket-a"]["AccessDenied"], 2);
        assert_eq!(summary["error_buckets"]["bucket-b"]["NoSuchKey"], 1);

        let ui_summary = metrics.error_summary(1, MetricsScope::Ui);
        assert_eq!(ui_summary["total_errors"], 0);
    }

    #[test]
    fn scopes_separate_sources_live_and_across_snapshots() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        record_ok(&metrics, "object", 2.0, SOURCE_API);
        record_ok(&metrics, "ui_metrics", 1.0, SOURCE_UI);
        record_ok(&metrics, "health", 0.5, SOURCE_INTERNAL);
        metrics.take_snapshot();
        record_ok(&metrics, "object", 3.0, SOURCE_API);
        record_ok(&metrics, "ui_metrics", 1.0, SOURCE_UI);

        let live_api = metrics.get_current_stats(MetricsScope::Api);
        assert_eq!(live_api["totals"]["count"], 1);

        let api = metrics.range_stats(1, MetricsScope::Api);
        assert_eq!(api["totals"]["count"], 2);
        assert_eq!(api["by_endpoint"]["object"]["count"], 2);
        assert!(api["by_endpoint"].get("ui_metrics").is_none());
        assert_eq!(api["snapshot_count"], 1);
        assert_eq!(api["scope"], "api");
        assert_eq!(api["live"]["count"], 1);

        let ui = metrics.range_stats(1, MetricsScope::Ui);
        assert_eq!(ui["totals"]["count"], 2);
        let internal = metrics.range_stats(1, MetricsScope::Internal);
        assert_eq!(internal["totals"]["count"], 1);
        let all = metrics.range_stats(1, MetricsScope::All);
        assert_eq!(all["totals"]["count"], 5);
        assert_eq!(all["totals"]["bytes_out"], 100);

        let history = metrics.get_history(Some(1), MetricsScope::Api);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].totals["count"], 1);
        assert!(history[0].totals.get("latency_hist").is_none());
        assert!(history[0].by_source.is_empty());
    }

    #[test]
    fn recent_status_counts_cover_live_and_recent_snapshots() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        record_ok(&metrics, "object", 1.0, SOURCE_API);
        metrics.record_request(
            "PUT",
            "object",
            503,
            1.0,
            0,
            0,
            Some("SlowDown"),
            None,
            None,
            None,
            SOURCE_API,
        );
        metrics.take_snapshot();
        metrics.record_request(
            "GET",
            "object",
            500,
            1.0,
            0,
            0,
            Some("InternalError"),
            None,
            None,
            None,
            SOURCE_API,
        );
        metrics.record_request(
            "GET", "ui_other", 500, 1.0, 0, 0, None, None, None, None, SOURCE_UI,
        );

        let counts = metrics.recent_status_counts(900, MetricsScope::Api);
        assert_eq!(counts.requests, 3);
        assert_eq!(counts.server_errors, 2);
        assert_eq!(counts.client_errors, 0);
        assert!(counts.window_seconds >= 1);
    }

    #[test]
    fn streamed_bytes_out_land_on_the_request_window() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        metrics.record_request(
            "POST", "object", 200, 1.0, 0, 0, None, None, None, None, SOURCE_API,
        );
        metrics.record_bytes_out(SOURCE_API, "POST", "object", 4096);
        metrics.record_bytes_out(SOURCE_API, "POST", "object", 0);

        let stats = metrics.get_current_stats(MetricsScope::Api);
        assert_eq!(stats["totals"]["bytes_out"], 4096);
        assert_eq!(stats["by_method"]["POST"]["bytes_out"], 4096);
        assert_eq!(stats["by_endpoint"]["object"]["bytes_out"], 4096);
        assert_eq!(stats["totals"]["count"], 1);
    }

    #[test]
    fn range_percentiles_merge_across_snapshots() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        for _ in 0..90 {
            record_ok(&metrics, "object", 1.0, SOURCE_API);
        }
        metrics.take_snapshot();
        for _ in 0..10 {
            record_ok(&metrics, "object", 500.0, SOURCE_API);
        }

        let stats = metrics.range_stats(1, MetricsScope::Api);
        let p50 = stats["totals"]["latency_p50_ms"].as_f64().unwrap();
        let p95 = stats["totals"]["latency_p95_ms"].as_f64().unwrap();
        assert!((0.8..=1.25).contains(&p50), "p50 {p50}");
        assert!((400.0..=500.0).contains(&p95), "p95 {p95}");
        assert_eq!(stats["totals"]["latency_max_ms"], 500.0);
    }

    #[test]
    fn persisted_snapshots_round_trip_histograms() {
        let tmp = tempdir().unwrap();
        {
            let metrics = service(tmp.path());
            for _ in 0..95 {
                record_ok(&metrics, "object", 1.0, SOURCE_API);
            }
            for _ in 0..5 {
                record_ok(&metrics, "object", 900.0, SOURCE_API);
            }
            metrics.flush();
        }
        let reloaded = service(tmp.path());
        let stats = reloaded.range_stats(1, MetricsScope::Api);
        assert_eq!(stats["totals"]["count"], 100);
        let p99 = stats["totals"]["latency_p99_ms"].as_f64().unwrap();
        assert!((700.0..=900.0).contains(&p99), "p99 {p99}");
    }

    #[test]
    fn legacy_snapshots_split_by_endpoint_prefix() {
        let tmp = tempdir().unwrap();
        let path = tmp
            .path()
            .join(".myfsio.sys")
            .join("config")
            .join("operation_metrics.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let stats = |count: u64, errors: u64| {
            json!({
                "count": count,
                "success_count": count - errors,
                "error_count": errors,
                "latency_avg_ms": 5.0,
                "latency_min_ms": 1.0,
                "latency_max_ms": 20.0,
                "latency_p50_ms": 4.0,
                "latency_p95_ms": 15.0,
                "latency_p99_ms": 19.0,
                "bytes_in": 0,
                "bytes_out": 0
            })
        };
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "snapshots": [{
                    "timestamp": Utc::now(),
                    "window_seconds": 300,
                    "by_method": { "GET": stats(40, 6) },
                    "by_endpoint": { "object": stats(10, 3), "ui_metrics": stats(30, 3) },
                    "by_status_class": { "2xx": 34, "4xx": 5, "5xx": 1 },
                    "error_codes": { "NoSuchKey": 2, "InternalError": 1 },
                    "totals": stats(40, 6)
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        let metrics = service(tmp.path());
        let api = metrics.range_stats(1, MetricsScope::Api);
        assert_eq!(api["totals"]["count"], 10);
        assert_eq!(api["by_status_class"]["4xx"], 2);
        assert_eq!(api["by_status_class"]["5xx"], 1);
        assert_eq!(api["error_codes"]["NoSuchKey"], 2);

        let ui = metrics.range_stats(1, MetricsScope::Ui);
        assert_eq!(ui["totals"]["count"], 30);
        assert_eq!(ui["by_status_class"]["4xx"], 3);
        assert!(ui["error_codes"].as_object().unwrap().is_empty());

        let all = metrics.range_stats(1, MetricsScope::All);
        assert_eq!(all["totals"]["count"], 40);
        assert_eq!(all["by_status_class"]["2xx"], 34);
    }

    #[test]
    fn empty_window_snapshot_skips_append_and_writes_only_when_pruned() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        metrics.take_snapshot();
        assert!(metrics.get_history(None, MetricsScope::All).is_empty());
        assert!(!metrics.snapshots_path.exists());

        {
            let mut inner = metrics.inner.lock();
            inner.snapshots.push(Arc::new(MetricsSnapshot {
                timestamp: Utc::now() - Duration::hours(2),
                window_seconds: 300,
                by_method: HashMap::new(),
                by_endpoint: HashMap::new(),
                by_status_class: HashMap::new(),
                error_codes: HashMap::new(),
                error_buckets: HashMap::new(),
                totals: json!({ "count": 1 }),
                by_source: HashMap::new(),
            }));
        }
        metrics.take_snapshot();
        assert!(metrics.get_history(None, MetricsScope::All).is_empty());
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
        assert!(metrics.get_history(None, MetricsScope::All).is_empty());
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
        let history = metrics.get_history(None, MetricsScope::All);
        assert_eq!(history.len(), 2);
        assert!(history[0].error_buckets.is_empty());
        assert_eq!(history[1].error_buckets["bucket-a"]["NoSuchKey"], 2);
    }

    #[test]
    fn latency_buckets_are_monotonic_and_bounded() {
        assert_eq!(latency_bucket(0.0), 0);
        assert_eq!(latency_bucket(f64::NAN), 0);
        assert_eq!(latency_bucket(f64::INFINITY), LATENCY_BUCKETS - 1);
        let mut previous = 0;
        for step in 0..2000 {
            let latency = 0.01 * 1.01f64.powi(step);
            let bucket = latency_bucket(latency);
            assert!(bucket >= previous);
            let (low, high) = latency_bucket_bounds(bucket);
            if bucket < LATENCY_BUCKETS - 1 {
                assert!(latency >= low * 0.999 && latency < high * 1.001);
            }
            previous = bucket;
        }
    }

    #[test]
    fn scope_parse_defaults_to_all() {
        assert_eq!(MetricsScope::parse(None), MetricsScope::All);
        assert_eq!(MetricsScope::parse(Some("API")), MetricsScope::Api);
        assert_eq!(MetricsScope::parse(Some("ui")), MetricsScope::Ui);
        assert_eq!(
            MetricsScope::parse(Some("internal")),
            MetricsScope::Internal
        );
        assert_eq!(MetricsScope::parse(Some("bogus")), MetricsScope::All);
    }
}
