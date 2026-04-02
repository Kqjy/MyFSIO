use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

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

struct MethodStats {
    count: u64,
    success_count: u64,
    error_count: u64,
    bytes_in: u64,
    bytes_out: u64,
    latencies: Vec<f64>,
}

impl MethodStats {
    fn new() -> Self {
        Self {
            count: 0,
            success_count: 0,
            error_count: 0,
            bytes_in: 0,
            bytes_out: 0,
            latencies: Vec::new(),
        }
    }

    fn to_json(&self) -> Value {
        let (min, max, avg, p50, p95, p99) = if self.latencies.is_empty() {
            (0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        } else {
            let mut sorted = self.latencies.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let len = sorted.len();
            let sum: f64 = sorted.iter().sum();
            (
                sorted[0],
                sorted[len - 1],
                sum / len as f64,
                sorted[len / 2],
                sorted[((len as f64 * 0.95) as usize).min(len - 1)],
                sorted[((len as f64 * 0.99) as usize).min(len - 1)],
            )
        };

        json!({
            "count": self.count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "latency_min_ms": min,
            "latency_max_ms": max,
            "latency_avg_ms": avg,
            "latency_p50_ms": p50,
            "latency_p95_ms": p95,
            "latency_p99_ms": p99,
        })
    }
}

struct CurrentWindow {
    by_method: HashMap<String, MethodStats>,
    by_status_class: HashMap<String, u64>,
    start_time: Instant,
}

impl CurrentWindow {
    fn new() -> Self {
        Self {
            by_method: HashMap::new(),
            by_status_class: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    fn reset(&mut self) {
        self.by_method.clear();
        self.by_status_class.clear();
        self.start_time = Instant::now();
    }
}

pub struct MetricsService {
    config: MetricsConfig,
    current: Arc<RwLock<CurrentWindow>>,
    snapshots: Arc<RwLock<Vec<Value>>>,
    snapshots_path: PathBuf,
}

impl MetricsService {
    pub fn new(storage_root: &std::path::Path, config: MetricsConfig) -> Self {
        let snapshots_path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("operation_metrics.json");

        let snapshots = if snapshots_path.exists() {
            std::fs::read_to_string(&snapshots_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|v| v.get("snapshots").and_then(|s| s.as_array().cloned()))
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        Self {
            config,
            current: Arc::new(RwLock::new(CurrentWindow::new())),
            snapshots: Arc::new(RwLock::new(snapshots)),
            snapshots_path,
        }
    }

    pub async fn record(&self, method: &str, status: u16, latency_ms: f64, bytes_in: u64, bytes_out: u64) {
        let mut window = self.current.write().await;
        let stats = window.by_method.entry(method.to_string()).or_insert_with(MethodStats::new);
        stats.count += 1;
        if status < 400 {
            stats.success_count += 1;
        } else {
            stats.error_count += 1;
        }
        stats.bytes_in += bytes_in;
        stats.bytes_out += bytes_out;
        stats.latencies.push(latency_ms);

        let class = format!("{}xx", status / 100);
        *window.by_status_class.entry(class).or_insert(0) += 1;
    }

    pub async fn snapshot(&self) -> Value {
        let window = self.current.read().await;
        let mut by_method = serde_json::Map::new();
        for (method, stats) in &window.by_method {
            by_method.insert(method.clone(), stats.to_json());
        }

        let snapshots = self.snapshots.read().await;
        json!({
            "enabled": true,
            "current_window": {
                "by_method": by_method,
                "by_status_class": window.by_status_class,
                "window_start_elapsed_secs": window.start_time.elapsed().as_secs_f64(),
            },
            "snapshots": *snapshots,
        })
    }

    async fn flush_window(&self) {
        let snap = {
            let mut window = self.current.write().await;
            let mut by_method = serde_json::Map::new();
            for (method, stats) in &window.by_method {
                by_method.insert(method.clone(), stats.to_json());
            }
            let snap = json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "window_seconds": self.config.interval_minutes * 60,
                "by_method": by_method,
                "by_status_class": window.by_status_class,
            });
            window.reset();
            snap
        };

        let max_snapshots = (self.config.retention_hours * 60 / self.config.interval_minutes) as usize;
        {
            let mut snapshots = self.snapshots.write().await;
            snapshots.push(snap);
            if snapshots.len() > max_snapshots {
                let excess = snapshots.len() - max_snapshots;
                snapshots.drain(..excess);
            }
        }
        self.save_snapshots().await;
    }

    async fn save_snapshots(&self) {
        let snapshots = self.snapshots.read().await;
        let data = json!({ "snapshots": *snapshots });
        if let Some(parent) = self.snapshots_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
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
                self.flush_window().await;
            }
        })
    }
}
