use chrono::{DateTime, Utc};
use myfsio_storage::fs_backend::FsStorageBackend;
use myfsio_storage::traits::StorageEngine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysinfo::{Disks, System};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct SystemMetricsConfig {
    pub interval_minutes: u64,
    pub retention_hours: u64,
    pub storage_refresh_minutes: u64,
}

impl Default for SystemMetricsConfig {
    fn default() -> Self {
        Self {
            interval_minutes: 5,
            retention_hours: 24,
            storage_refresh_minutes: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetricsSnapshot {
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemMetricsHistoryPoint {
    pub timestamp: DateTime<Utc>,
    pub cpu_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_percent_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_percent_max: Option<f64>,
    pub memory_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_percent_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_percent_max: Option<f64>,
    pub disk_percent: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_percent_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_percent_max: Option<f64>,
    pub storage_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_bytes_min: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_bytes_max: Option<u64>,
}

pub struct SystemMetricsHistory {
    pub history: Vec<SystemMetricsHistoryPoint>,
    pub aggregated: bool,
    pub bucket_seconds: Option<f64>,
    pub sample_count: usize,
}

pub const DEFAULT_HISTORY_POINTS: usize = 240;

pub struct SystemMetricsService {
    storage_root: PathBuf,
    storage: Arc<FsStorageBackend>,
    config: SystemMetricsConfig,
    history: Arc<RwLock<Vec<SystemMetricsSnapshot>>>,
    history_path: PathBuf,
    storage_bytes_cache: Arc<RwLock<StorageBytesCache>>,
}

#[derive(Debug, Clone, Copy, Default)]
struct StorageBytesCache {
    bytes: u64,
    last_refresh: Option<DateTime<Utc>>,
}

impl SystemMetricsService {
    pub fn new(
        storage_root: &Path,
        storage: Arc<FsStorageBackend>,
        config: SystemMetricsConfig,
    ) -> Self {
        let history_path = storage_root
            .join(".myfsio.sys")
            .join("config")
            .join("metrics_history.json");

        let mut history = load_history(&history_path);
        prune_history(&mut history, config.retention_hours);

        Self {
            storage_root: storage_root.to_path_buf(),
            storage,
            config,
            history: Arc::new(RwLock::new(history)),
            history_path,
            storage_bytes_cache: Arc::new(RwLock::new(StorageBytesCache::default())),
        }
    }

    pub async fn get_history(&self, hours: Option<u64>) -> Vec<SystemMetricsSnapshot> {
        let mut history = self.history.read().await.clone();
        prune_history(&mut history, hours.unwrap_or(self.config.retention_hours));
        history
    }

    pub async fn get_history_aggregated(
        &self,
        hours: u64,
        points: Option<usize>,
    ) -> SystemMetricsHistory {
        let end = Utc::now();
        let start = end - chrono::Duration::hours(hours as i64);
        let mut history = self.history.read().await.clone();
        history.retain(|item| item.timestamp > start && item.timestamp <= end);
        aggregate_history(history, start, end, clamp_history_points(points))
    }

    pub async fn storage_last_refresh(&self) -> Option<DateTime<Utc>> {
        self.storage_bytes_cache.read().await.last_refresh
    }

    async fn take_snapshot(&self) {
        let snapshot = self.collect_snapshot().await;
        let mut history = self.history.write().await;
        history.push(snapshot);
        prune_history(&mut history, self.config.retention_hours);
        drop(history);
        self.save_history().await;
    }

    async fn collect_snapshot(&self) -> SystemMetricsSnapshot {
        collect_snapshot(
            &self.storage_root,
            &self.storage,
            &self.storage_bytes_cache,
            self.config.storage_refresh_minutes,
        )
        .await
    }

    async fn save_history(&self) {
        let history = self.history.read().await;
        let data = json!({ "history": *history });
        if let Some(parent) = self.history_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let serialized = serde_json::to_string_pretty(&data).unwrap_or_default();
        let tmp = self.history_path.with_extension("json.tmp");
        if std::fs::write(&tmp, serialized).is_ok() {
            let _ = std::fs::rename(&tmp, &self.history_path);
        }
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval =
            std::time::Duration::from_secs(self.config.interval_minutes.saturating_mul(60));
        tokio::spawn(async move {
            self.take_snapshot().await;
            let mut timer = tokio::time::interval(interval);
            timer.tick().await;
            loop {
                timer.tick().await;
                self.take_snapshot().await;
            }
        })
    }
}

fn prune_history(history: &mut Vec<SystemMetricsSnapshot>, retention_hours: u64) {
    let cutoff = Utc::now() - chrono::Duration::hours(retention_hours as i64);
    history.retain(|item| item.timestamp > cutoff);
}

fn clamp_history_points(points: Option<usize>) -> usize {
    points.unwrap_or(DEFAULT_HISTORY_POINTS).clamp(50, 1000)
}

impl From<SystemMetricsSnapshot> for SystemMetricsHistoryPoint {
    fn from(snapshot: SystemMetricsSnapshot) -> Self {
        Self {
            timestamp: snapshot.timestamp,
            cpu_percent: snapshot.cpu_percent,
            cpu_percent_min: None,
            cpu_percent_max: None,
            memory_percent: snapshot.memory_percent,
            memory_percent_min: None,
            memory_percent_max: None,
            disk_percent: snapshot.disk_percent,
            disk_percent_min: None,
            disk_percent_max: None,
            storage_bytes: snapshot.storage_bytes,
            storage_bytes_min: None,
            storage_bytes_max: None,
        }
    }
}

struct HistoryBucket {
    count: u64,
    cpu_sum: f64,
    cpu_min: f64,
    cpu_max: f64,
    memory_sum: f64,
    memory_min: f64,
    memory_max: f64,
    disk_sum: f64,
    disk_min: f64,
    disk_max: f64,
    storage_sum: u128,
    storage_min: u64,
    storage_max: u64,
}

impl HistoryBucket {
    fn new(snapshot: &SystemMetricsSnapshot) -> Self {
        Self {
            count: 1,
            cpu_sum: snapshot.cpu_percent,
            cpu_min: snapshot.cpu_percent,
            cpu_max: snapshot.cpu_percent,
            memory_sum: snapshot.memory_percent,
            memory_min: snapshot.memory_percent,
            memory_max: snapshot.memory_percent,
            disk_sum: snapshot.disk_percent,
            disk_min: snapshot.disk_percent,
            disk_max: snapshot.disk_percent,
            storage_sum: snapshot.storage_bytes as u128,
            storage_min: snapshot.storage_bytes,
            storage_max: snapshot.storage_bytes,
        }
    }

    fn add(&mut self, snapshot: &SystemMetricsSnapshot) {
        self.count += 1;
        self.cpu_sum += snapshot.cpu_percent;
        self.cpu_min = self.cpu_min.min(snapshot.cpu_percent);
        self.cpu_max = self.cpu_max.max(snapshot.cpu_percent);
        self.memory_sum += snapshot.memory_percent;
        self.memory_min = self.memory_min.min(snapshot.memory_percent);
        self.memory_max = self.memory_max.max(snapshot.memory_percent);
        self.disk_sum += snapshot.disk_percent;
        self.disk_min = self.disk_min.min(snapshot.disk_percent);
        self.disk_max = self.disk_max.max(snapshot.disk_percent);
        self.storage_sum += snapshot.storage_bytes as u128;
        self.storage_min = self.storage_min.min(snapshot.storage_bytes);
        self.storage_max = self.storage_max.max(snapshot.storage_bytes);
    }

    fn into_point(self, timestamp: DateTime<Utc>) -> SystemMetricsHistoryPoint {
        SystemMetricsHistoryPoint {
            timestamp,
            cpu_percent: round2(self.cpu_sum / self.count as f64),
            cpu_percent_min: Some(self.cpu_min),
            cpu_percent_max: Some(self.cpu_max),
            memory_percent: round2(self.memory_sum / self.count as f64),
            memory_percent_min: Some(self.memory_min),
            memory_percent_max: Some(self.memory_max),
            disk_percent: round2(self.disk_sum / self.count as f64),
            disk_percent_min: Some(self.disk_min),
            disk_percent_max: Some(self.disk_max),
            storage_bytes: (self.storage_sum / self.count as u128) as u64,
            storage_bytes_min: Some(self.storage_min),
            storage_bytes_max: Some(self.storage_max),
        }
    }
}

fn aggregate_history(
    mut history: Vec<SystemMetricsSnapshot>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    target: usize,
) -> SystemMetricsHistory {
    history.sort_by_key(|item| item.timestamp);
    let sample_count = history.len();
    if sample_count <= target {
        return SystemMetricsHistory {
            history: history.into_iter().map(Into::into).collect(),
            aggregated: false,
            bucket_seconds: None,
            sample_count,
        };
    }

    let range_millis = (end - start).num_milliseconds().max(1);
    let mut buckets: Vec<Option<HistoryBucket>> = (0..target).map(|_| None).collect();
    for snapshot in &history {
        let elapsed = (snapshot.timestamp - start)
            .num_milliseconds()
            .clamp(0, range_millis);
        let index = ((elapsed as i128 * target as i128) / range_millis as i128)
            .min(target.saturating_sub(1) as i128) as usize;
        match &mut buckets[index] {
            Some(bucket) => bucket.add(snapshot),
            None => buckets[index] = Some(HistoryBucket::new(snapshot)),
        }
    }

    let points = buckets
        .into_iter()
        .enumerate()
        .filter_map(|(index, bucket)| {
            bucket.map(|bucket| {
                let offset = (range_millis as i128 * (index + 1) as i128 / target as i128) as i64;
                bucket.into_point(start + chrono::Duration::milliseconds(offset))
            })
        })
        .collect();

    SystemMetricsHistory {
        history: points,
        aggregated: true,
        bucket_seconds: Some(range_millis as f64 / 1000.0 / target as f64),
        sample_count,
    }
}

fn sample_system_now() -> (f64, f64) {
    let mut system = System::new();
    system.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    system.refresh_cpu_usage();
    system.refresh_memory();

    let cpu_percent = system.global_cpu_usage() as f64;
    let memory_percent = if system.total_memory() > 0 {
        (system.used_memory() as f64 / system.total_memory() as f64) * 100.0
    } else {
        0.0
    };
    (cpu_percent, memory_percent)
}

fn normalize_path_for_mount(path: &Path) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let raw = canonical.to_string_lossy().to_string();
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    stripped.to_lowercase()
}

pub fn sample_disk(path: &Path) -> (u64, u64) {
    let disks = Disks::new_with_refreshed_list();
    let path_str = normalize_path_for_mount(path);
    let mut best: Option<(usize, u64, u64)> = None;

    for disk in disks.list() {
        let mount_raw = disk.mount_point().to_string_lossy().to_string();
        let mount = mount_raw
            .strip_prefix(r"\\?\")
            .unwrap_or(&mount_raw)
            .to_lowercase();
        let total = disk.total_space();
        let free = disk.available_space();
        if path_str.starts_with(&mount) {
            let len = mount.len();
            match best {
                Some((best_len, _, _)) if len <= best_len => {}
                _ => best = Some((len, total, free)),
            }
        }
    }

    best.map(|(_, total, free)| (total, free)).unwrap_or((0, 0))
}

async fn collect_snapshot(
    storage_root: &Path,
    storage: &Arc<FsStorageBackend>,
    storage_bytes_cache: &Arc<RwLock<StorageBytesCache>>,
    storage_refresh_minutes: u64,
) -> SystemMetricsSnapshot {
    let root = storage_root.to_path_buf();
    let ((cpu_percent, memory_percent), (disk_total, disk_free)) =
        tokio::task::spawn_blocking(move || (sample_system_now(), sample_disk(&root)))
            .await
            .unwrap_or(((0.0, 0.0), (0, 0)));
    let disk_percent = if disk_total > 0 {
        ((disk_total - disk_free) as f64 / disk_total as f64) * 100.0
    } else {
        0.0
    };

    let storage_bytes =
        cached_storage_bytes(storage, storage_bytes_cache, storage_refresh_minutes).await;

    SystemMetricsSnapshot {
        timestamp: Utc::now(),
        cpu_percent: round2(cpu_percent),
        memory_percent: round2(memory_percent),
        disk_percent: round2(disk_percent),
        storage_bytes,
    }
}

async fn cached_storage_bytes(
    storage: &Arc<FsStorageBackend>,
    cache: &Arc<RwLock<StorageBytesCache>>,
    storage_refresh_minutes: u64,
) -> u64 {
    let refresh_minutes = storage_refresh_minutes.max(5);
    let now = Utc::now();
    {
        let cached = cache.read().await;
        if let Some(last_refresh) = cached.last_refresh {
            if now - last_refresh < chrono::Duration::minutes(refresh_minutes as i64) {
                return cached.bytes;
            }
        }
    }

    let previous = { cache.read().await.bytes };
    let storage = storage.clone();
    let handle = tokio::runtime::Handle::current();
    let refreshed = tokio::task::spawn_blocking(move || {
        handle.block_on(async move {
            let mut total = 0u64;
            let buckets = storage.list_buckets().await.unwrap_or_default();
            for bucket in buckets {
                if let Ok(stats) = storage.bucket_stats(&bucket.name).await {
                    total += stats.total_bytes();
                }
            }
            total
        })
    })
    .await
    .unwrap_or(previous);

    let mut cached = cache.write().await;
    cached.bytes = refreshed;
    cached.last_refresh = Some(now);
    refreshed
}

fn load_history(path: &Path) -> Vec<SystemMetricsSnapshot> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(value) => value
            .get("history")
            .and_then(|history| {
                serde_json::from_value::<Vec<SystemMetricsSnapshot>>(history.clone()).ok()
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
        .unwrap_or("metrics_history.json");
    let corrupt_path = path.with_file_name(format!("{name}.corrupt-{ts}"));
    match std::fs::rename(path, &corrupt_path) {
        Ok(()) => tracing::warn!(
            path = %path.display(),
            corrupt_path = %corrupt_path.display(),
            error = %error,
            "Renamed corrupt system metrics file"
        ),
        Err(rename_err) => tracing::warn!(
            path = %path.display(),
            error = %error,
            rename_error = %rename_err,
            "Failed to rename corrupt system metrics file"
        ),
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn service(root: &Path) -> SystemMetricsService {
        SystemMetricsService::new(
            root,
            Arc::new(FsStorageBackend::new(root.to_path_buf())),
            SystemMetricsConfig {
                interval_minutes: 5,
                retention_hours: 1,
                storage_refresh_minutes: 30,
            },
        )
    }

    fn history_snapshot(
        start: DateTime<Utc>,
        seconds: i64,
        cpu_percent: f64,
        memory_percent: f64,
        disk_percent: f64,
        storage_bytes: u64,
    ) -> SystemMetricsSnapshot {
        SystemMetricsSnapshot {
            timestamp: start + chrono::Duration::seconds(seconds),
            cpu_percent,
            memory_percent,
            disk_percent,
            storage_bytes,
        }
    }

    #[test]
    fn metrics_history_points_are_clamped() {
        assert_eq!(clamp_history_points(None), 240);
        assert_eq!(clamp_history_points(Some(1)), 50);
        assert_eq!(clamp_history_points(Some(500)), 500);
        assert_eq!(clamp_history_points(Some(2000)), 1000);
    }

    #[test]
    fn metrics_history_raw_samples_pass_through() {
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let history = vec![
            history_snapshot(start, 10, 10.0, 20.0, 30.0, 100),
            history_snapshot(start, 20, 40.0, 50.0, 60.0, 200),
        ];

        let result = aggregate_history(history, start, start + chrono::Duration::hours(1), 50);

        assert!(!result.aggregated);
        assert_eq!(result.bucket_seconds, None);
        assert_eq!(result.sample_count, 2);
        assert_eq!(result.history.len(), 2);
        assert_eq!(
            result.history[0].timestamp,
            start + chrono::Duration::seconds(10)
        );
        assert_eq!(result.history[0].cpu_percent, 10.0);
        assert_eq!(result.history[0].cpu_percent_min, None);
        assert_eq!(result.history[0].storage_bytes_max, None);
    }

    #[test]
    fn metrics_history_aggregates_average_min_and_max() {
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let history = vec![
            history_snapshot(start, 10, 10.0, 20.0, 30.0, 100),
            history_snapshot(start, 20, 30.0, 50.0, 70.0, 300),
            history_snapshot(start, 70, 40.0, 60.0, 80.0, 400),
            history_snapshot(start, 80, 80.0, 90.0, 100.0, 800),
        ];

        let result = aggregate_history(history, start, start + chrono::Duration::seconds(120), 2);

        assert!(result.aggregated);
        assert_eq!(result.bucket_seconds, Some(60.0));
        assert_eq!(result.sample_count, 4);
        assert_eq!(result.history.len(), 2);
        let first = &result.history[0];
        assert_eq!(first.timestamp, start + chrono::Duration::seconds(60));
        assert_eq!(first.cpu_percent, 20.0);
        assert_eq!(first.cpu_percent_min, Some(10.0));
        assert_eq!(first.cpu_percent_max, Some(30.0));
        assert_eq!(first.memory_percent, 35.0);
        assert_eq!(first.memory_percent_min, Some(20.0));
        assert_eq!(first.memory_percent_max, Some(50.0));
        assert_eq!(first.disk_percent, 50.0);
        assert_eq!(first.disk_percent_min, Some(30.0));
        assert_eq!(first.disk_percent_max, Some(70.0));
        assert_eq!(first.storage_bytes, 200);
        assert_eq!(first.storage_bytes_min, Some(100));
        assert_eq!(first.storage_bytes_max, Some(300));
    }

    #[test]
    fn metrics_history_skips_empty_buckets() {
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let history = vec![
            history_snapshot(start, 10, 10.0, 20.0, 30.0, 100),
            history_snapshot(start, 20, 20.0, 30.0, 40.0, 200),
            history_snapshot(start, 30, 30.0, 40.0, 50.0, 300),
            history_snapshot(start, 310, 40.0, 50.0, 60.0, 400),
            history_snapshot(start, 320, 50.0, 60.0, 70.0, 500),
        ];

        let result = aggregate_history(history, start, start + chrono::Duration::seconds(400), 4);

        assert!(result.aggregated);
        assert_eq!(result.sample_count, 5);
        assert_eq!(result.history.len(), 2);
        assert_eq!(
            result.history[0].timestamp,
            start + chrono::Duration::seconds(100)
        );
        assert_eq!(
            result.history[1].timestamp,
            start + chrono::Duration::seconds(400)
        );
    }

    #[tokio::test]
    async fn atomic_save_leaves_valid_json() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        metrics.take_snapshot().await;

        let path = metrics.history_path.clone();
        let raw = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["history"].as_array().unwrap().len(), 1);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[tokio::test]
    async fn corrupt_history_file_is_renamed_on_load() {
        let tmp = tempdir().unwrap();
        let path = tmp
            .path()
            .join(".myfsio.sys")
            .join("config")
            .join("metrics_history.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "{not json").unwrap();

        let metrics = service(tmp.path());
        assert!(metrics.get_history(None).await.is_empty());
        assert!(!path.exists());
        let entries: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert!(entries
            .iter()
            .any(|name| name.starts_with("metrics_history.json.corrupt-")));
    }

    #[tokio::test]
    async fn take_snapshot_records_single_startup_snapshot() {
        let tmp = tempdir().unwrap();
        let metrics = service(tmp.path());
        metrics.take_snapshot().await;
        let history = metrics.get_history(None).await;
        assert_eq!(history.len(), 1);
    }
}
