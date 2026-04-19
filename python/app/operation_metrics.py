from __future__ import annotations

import json
import logging
import random
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_LATENCY_SAMPLES = 5000

logger = logging.getLogger(__name__)


@dataclass
class OperationStats:
    count: int = 0
    success_count: int = 0
    error_count: int = 0
    latency_sum_ms: float = 0.0
    latency_min_ms: float = float("inf")
    latency_max_ms: float = 0.0
    bytes_in: int = 0
    bytes_out: int = 0
    latency_samples: List[float] = field(default_factory=list)

    @staticmethod
    def _compute_percentile(sorted_data: List[float], p: float) -> float:
        if not sorted_data:
            return 0.0
        k = (len(sorted_data) - 1) * (p / 100.0)
        f = int(k)
        c = min(f + 1, len(sorted_data) - 1)
        d = k - f
        return sorted_data[f] + d * (sorted_data[c] - sorted_data[f])

    def record(self, latency_ms: float, success: bool, bytes_in: int = 0, bytes_out: int = 0) -> None:
        self.count += 1
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
        self.latency_sum_ms += latency_ms
        if latency_ms < self.latency_min_ms:
            self.latency_min_ms = latency_ms
        if latency_ms > self.latency_max_ms:
            self.latency_max_ms = latency_ms
        self.bytes_in += bytes_in
        self.bytes_out += bytes_out
        if len(self.latency_samples) < MAX_LATENCY_SAMPLES:
            self.latency_samples.append(latency_ms)
        else:
            j = random.randint(0, self.count - 1)
            if j < MAX_LATENCY_SAMPLES:
                self.latency_samples[j] = latency_ms

    def to_dict(self) -> Dict[str, Any]:
        avg_latency = self.latency_sum_ms / self.count if self.count > 0 else 0.0
        min_latency = self.latency_min_ms if self.latency_min_ms != float("inf") else 0.0
        sorted_latencies = sorted(self.latency_samples)
        return {
            "count": self.count,
            "success_count": self.success_count,
            "error_count": self.error_count,
            "latency_avg_ms": round(avg_latency, 2),
            "latency_min_ms": round(min_latency, 2),
            "latency_max_ms": round(self.latency_max_ms, 2),
            "latency_p50_ms": round(self._compute_percentile(sorted_latencies, 50), 2),
            "latency_p95_ms": round(self._compute_percentile(sorted_latencies, 95), 2),
            "latency_p99_ms": round(self._compute_percentile(sorted_latencies, 99), 2),
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }

    def merge(self, other: "OperationStats") -> None:
        self.count += other.count
        self.success_count += other.success_count
        self.error_count += other.error_count
        self.latency_sum_ms += other.latency_sum_ms
        if other.latency_min_ms < self.latency_min_ms:
            self.latency_min_ms = other.latency_min_ms
        if other.latency_max_ms > self.latency_max_ms:
            self.latency_max_ms = other.latency_max_ms
        self.bytes_in += other.bytes_in
        self.bytes_out += other.bytes_out
        combined = self.latency_samples + other.latency_samples
        if len(combined) > MAX_LATENCY_SAMPLES:
            random.shuffle(combined)
            combined = combined[:MAX_LATENCY_SAMPLES]
        self.latency_samples = combined


@dataclass
class MetricsSnapshot:
    timestamp: datetime
    window_seconds: int
    by_method: Dict[str, Dict[str, Any]]
    by_endpoint: Dict[str, Dict[str, Any]]
    by_status_class: Dict[str, int]
    error_codes: Dict[str, int]
    totals: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "window_seconds": self.window_seconds,
            "by_method": self.by_method,
            "by_endpoint": self.by_endpoint,
            "by_status_class": self.by_status_class,
            "error_codes": self.error_codes,
            "totals": self.totals,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MetricsSnapshot":
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            window_seconds=data.get("window_seconds", 300),
            by_method=data.get("by_method", {}),
            by_endpoint=data.get("by_endpoint", {}),
            by_status_class=data.get("by_status_class", {}),
            error_codes=data.get("error_codes", {}),
            totals=data.get("totals", {}),
        )


class OperationMetricsCollector:
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
        self._by_method: Dict[str, OperationStats] = defaultdict(OperationStats)
        self._by_endpoint: Dict[str, OperationStats] = defaultdict(OperationStats)
        self._by_status_class: Dict[str, int] = {}
        self._error_codes: Dict[str, int] = {}
        self._totals = OperationStats()
        self._window_start = time.time()
        self._shutdown = threading.Event()
        self._snapshots: List[MetricsSnapshot] = []

        self._load_history()

        self._snapshot_thread = threading.Thread(
            target=self._snapshot_loop, name="operation-metrics-snapshot", daemon=True
        )
        self._snapshot_thread.start()

    def _config_path(self) -> Path:
        return self.storage_root / ".myfsio.sys" / "config" / "operation_metrics.json"

    def _load_history(self) -> None:
        config_path = self._config_path()
        if not config_path.exists():
            return
        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            snapshots_data = data.get("snapshots", [])
            self._snapshots = [MetricsSnapshot.from_dict(s) for s in snapshots_data]
            self._prune_old_snapshots()
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.warning(f"Failed to load operation metrics history: {e}")

    def _save_history(self) -> None:
        config_path = self._config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {"snapshots": [s.to_dict() for s in self._snapshots]}
            config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except OSError as e:
            logger.warning(f"Failed to save operation metrics history: {e}")

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
        with self._lock:
            now = datetime.now(timezone.utc)
            window_seconds = int(time.time() - self._window_start)

            snapshot = MetricsSnapshot(
                timestamp=now,
                window_seconds=window_seconds,
                by_method={k: v.to_dict() for k, v in self._by_method.items()},
                by_endpoint={k: v.to_dict() for k, v in self._by_endpoint.items()},
                by_status_class=dict(self._by_status_class),
                error_codes=dict(self._error_codes),
                totals=self._totals.to_dict(),
            )

            self._snapshots.append(snapshot)
            self._prune_old_snapshots()
            self._save_history()

            self._by_method = defaultdict(OperationStats)
            self._by_endpoint = defaultdict(OperationStats)
            self._by_status_class.clear()
            self._error_codes.clear()
            self._totals = OperationStats()
            self._window_start = time.time()

    def record_request(
        self,
        method: str,
        endpoint_type: str,
        status_code: int,
        latency_ms: float,
        bytes_in: int = 0,
        bytes_out: int = 0,
        error_code: Optional[str] = None,
    ) -> None:
        success = 200 <= status_code < 400
        status_class = f"{status_code // 100}xx"

        with self._lock:
            self._by_method[method].record(latency_ms, success, bytes_in, bytes_out)
            self._by_endpoint[endpoint_type].record(latency_ms, success, bytes_in, bytes_out)

            self._by_status_class[status_class] = self._by_status_class.get(status_class, 0) + 1

            if error_code:
                self._error_codes[error_code] = self._error_codes.get(error_code, 0) + 1

            self._totals.record(latency_ms, success, bytes_in, bytes_out)

    def get_current_stats(self) -> Dict[str, Any]:
        with self._lock:
            window_seconds = int(time.time() - self._window_start)
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "window_seconds": window_seconds,
                "by_method": {k: v.to_dict() for k, v in self._by_method.items()},
                "by_endpoint": {k: v.to_dict() for k, v in self._by_endpoint.items()},
                "by_status_class": dict(self._by_status_class),
                "error_codes": dict(self._error_codes),
                "totals": self._totals.to_dict(),
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


def classify_endpoint(path: str) -> str:
    if not path or path == "/":
        return "service"

    path = path.rstrip("/")

    if path.startswith("/ui"):
        return "ui"

    if path.startswith("/kms"):
        return "kms"

    if path.startswith("/myfsio"):
        return "service"

    parts = path.lstrip("/").split("/")
    if len(parts) == 0:
        return "service"
    elif len(parts) == 1:
        return "bucket"
    else:
        return "object"
