from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from .storage import ObjectStorage

logger = logging.getLogger(__name__)


@dataclass
class SystemMetricsSnapshot:
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    storage_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cpu_percent": round(self.cpu_percent, 2),
            "memory_percent": round(self.memory_percent, 2),
            "disk_percent": round(self.disk_percent, 2),
            "storage_bytes": self.storage_bytes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemMetricsSnapshot":
        timestamp_str = data["timestamp"]
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str[:-1] + "+00:00"
        return cls(
            timestamp=datetime.fromisoformat(timestamp_str),
            cpu_percent=data.get("cpu_percent", 0.0),
            memory_percent=data.get("memory_percent", 0.0),
            disk_percent=data.get("disk_percent", 0.0),
            storage_bytes=data.get("storage_bytes", 0),
        )


class SystemMetricsCollector:
    def __init__(
        self,
        storage_root: Path,
        interval_minutes: int = 5,
        retention_hours: int = 24,
    ):
        self.storage_root = storage_root
        self.interval_seconds = interval_minutes * 60
        self.retention_hours = retention_hours
        self._lock = threading.Lock()
        self._shutdown = threading.Event()
        self._snapshots: List[SystemMetricsSnapshot] = []
        self._storage_ref: Optional["ObjectStorage"] = None

        self._load_history()

        self._snapshot_thread = threading.Thread(
            target=self._snapshot_loop,
            name="system-metrics-snapshot",
            daemon=True,
        )
        self._snapshot_thread.start()

    def set_storage(self, storage: "ObjectStorage") -> None:
        with self._lock:
            self._storage_ref = storage

    def _config_path(self) -> Path:
        return self.storage_root / ".myfsio.sys" / "config" / "metrics_history.json"

    def _load_history(self) -> None:
        config_path = self._config_path()
        if not config_path.exists():
            return
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            history_data = data.get("history", [])
            self._snapshots = [SystemMetricsSnapshot.from_dict(s) for s in history_data]
            self._prune_old_snapshots()
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.warning(f"Failed to load system metrics history: {e}")

    def _save_history(self) -> None:
        config_path = self._config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {"history": [s.to_dict() for s in self._snapshots]}
            config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as e:
            logger.warning(f"Failed to save system metrics history: {e}")

    def _prune_old_snapshots(self) -> None:
        if not self._snapshots:
            return
        cutoff = datetime.now(timezone.utc).timestamp() - (self.retention_hours * 3600)
        self._snapshots = [
            s for s in self._snapshots if s.timestamp.timestamp() > cutoff
        ]

    def _snapshot_loop(self) -> None:
        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=self.interval_seconds)
            if not self._shutdown.is_set():
                self._take_snapshot()

    def _take_snapshot(self) -> None:
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage(str(self.storage_root))

            storage_bytes = 0
            with self._lock:
                storage = self._storage_ref
            if storage:
                try:
                    buckets = storage.list_buckets()
                    for bucket in buckets:
                        stats = storage.bucket_stats(bucket.name, cache_ttl=60)
                        storage_bytes += stats.get("total_bytes", stats.get("bytes", 0))
                except Exception as e:
                    logger.warning(f"Failed to collect bucket stats: {e}")

            snapshot = SystemMetricsSnapshot(
                timestamp=datetime.now(timezone.utc),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_percent=disk.percent,
                storage_bytes=storage_bytes,
            )

            with self._lock:
                self._snapshots.append(snapshot)
                self._prune_old_snapshots()
                self._save_history()

            logger.debug(f"System metrics snapshot taken: CPU={cpu_percent:.1f}%, Memory={memory.percent:.1f}%")
        except Exception as e:
            logger.warning(f"Failed to take system metrics snapshot: {e}")

    def get_current(self) -> Dict[str, Any]:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage(str(self.storage_root))
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_days = int(uptime_seconds / 86400)

        total_buckets = 0
        total_objects = 0
        total_bytes_used = 0
        total_versions = 0

        with self._lock:
            storage = self._storage_ref
        if storage:
            try:
                buckets = storage.list_buckets()
                total_buckets = len(buckets)
                for bucket in buckets:
                    stats = storage.bucket_stats(bucket.name, cache_ttl=60)
                    total_objects += stats.get("total_objects", stats.get("objects", 0))
                    total_bytes_used += stats.get("total_bytes", stats.get("bytes", 0))
                    total_versions += stats.get("version_count", 0)
            except Exception as e:
                logger.warning(f"Failed to collect current bucket stats: {e}")

        return {
            "cpu_percent": round(cpu_percent, 2),
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "used": memory.used,
                "percent": round(memory.percent, 2),
            },
            "disk": {
                "total": disk.total,
                "free": disk.free,
                "used": disk.used,
                "percent": round(disk.percent, 2),
            },
            "app": {
                "buckets": total_buckets,
                "objects": total_objects,
                "versions": total_versions,
                "storage_bytes": total_bytes_used,
                "uptime_days": uptime_days,
            },
        }

    def get_history(self, hours: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            snapshots = list(self._snapshots)

        if hours:
            cutoff = datetime.now(timezone.utc).timestamp() - (hours * 3600)
            snapshots = [s for s in snapshots if s.timestamp.timestamp() > cutoff]

        return [s.to_dict() for s in snapshots]

    def shutdown(self) -> None:
        self._shutdown.set()
        self._take_snapshot()
        self._snapshot_thread.join(timeout=5.0)
