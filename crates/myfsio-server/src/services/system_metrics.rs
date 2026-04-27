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
}

impl Default for SystemMetricsConfig {
    fn default() -> Self {
        Self {
            interval_minutes: 5,
            retention_hours: 24,
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

pub struct SystemMetricsService {
    storage_root: PathBuf,
    storage: Arc<FsStorageBackend>,
    config: SystemMetricsConfig,
    history: Arc<RwLock<Vec<SystemMetricsSnapshot>>>,
    history_path: PathBuf,
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

        let mut history = if history_path.exists() {
            std::fs::read_to_string(&history_path)
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| {
                    v.get("history").and_then(|h| {
                        serde_json::from_value::<Vec<SystemMetricsSnapshot>>(h.clone()).ok()
                    })
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        prune_history(&mut history, config.retention_hours);

        Self {
            storage_root: storage_root.to_path_buf(),
            storage,
            config,
            history: Arc::new(RwLock::new(history)),
            history_path,
        }
    }

    pub async fn get_history(&self, hours: Option<u64>) -> Vec<SystemMetricsSnapshot> {
        let mut history = self.history.read().await.clone();
        prune_history(&mut history, hours.unwrap_or(self.config.retention_hours));
        history
    }

    async fn take_snapshot(&self) {
        let snapshot = collect_snapshot(&self.storage_root, &self.storage).await;
        let mut history = self.history.write().await;
        history.push(snapshot);
        prune_history(&mut history, self.config.retention_hours);
        drop(history);
        self.save_history().await;
    }

    async fn save_history(&self) {
        let history = self.history.read().await;
        let data = json!({ "history": *history });
        if let Some(parent) = self.history_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(
            &self.history_path,
            serde_json::to_string_pretty(&data).unwrap_or_default(),
        );
    }

    pub fn start_background(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval =
            std::time::Duration::from_secs(self.config.interval_minutes.saturating_mul(60));
        tokio::spawn(async move {
            self.take_snapshot().await;
            let mut timer = tokio::time::interval(interval);
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
) -> SystemMetricsSnapshot {
    let (cpu_percent, memory_percent) = sample_system_now();
    let (disk_total, disk_free) = sample_disk(storage_root);
    let disk_percent = if disk_total > 0 {
        ((disk_total - disk_free) as f64 / disk_total as f64) * 100.0
    } else {
        0.0
    };

    let mut storage_bytes = 0u64;
    let buckets = storage.list_buckets().await.unwrap_or_default();
    for bucket in buckets {
        if let Ok(stats) = storage.bucket_stats(&bucket.name).await {
            storage_bytes += stats.total_bytes();
        }
    }

    SystemMetricsSnapshot {
        timestamp: Utc::now(),
        cpu_percent: round2(cpu_percent),
        memory_percent: round2(memory_percent),
        disk_percent: round2(disk_percent),
        storage_bytes,
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
