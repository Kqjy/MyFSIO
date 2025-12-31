from __future__ import annotations

import io
import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AccessLogEntry:
    bucket_owner: str = "-"
    bucket: str = "-"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    remote_ip: str = "-"
    requester: str = "-"
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16].upper())
    operation: str = "-"
    key: str = "-"
    request_uri: str = "-"
    http_status: int = 200
    error_code: str = "-"
    bytes_sent: int = 0
    object_size: int = 0
    total_time_ms: int = 0
    turn_around_time_ms: int = 0
    referrer: str = "-"
    user_agent: str = "-"
    version_id: str = "-"
    host_id: str = "-"
    signature_version: str = "SigV4"
    cipher_suite: str = "-"
    authentication_type: str = "AuthHeader"
    host_header: str = "-"
    tls_version: str = "-"

    def to_log_line(self) -> str:
        time_str = self.timestamp.strftime("[%d/%b/%Y:%H:%M:%S %z]")
        return (
            f'{self.bucket_owner} {self.bucket} {time_str} {self.remote_ip} '
            f'{self.requester} {self.request_id} {self.operation} {self.key} '
            f'"{self.request_uri}" {self.http_status} {self.error_code or "-"} '
            f'{self.bytes_sent or "-"} {self.object_size or "-"} {self.total_time_ms or "-"} '
            f'{self.turn_around_time_ms or "-"} "{self.referrer}" "{self.user_agent}" {self.version_id}'
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket_owner": self.bucket_owner,
            "bucket": self.bucket,
            "timestamp": self.timestamp.isoformat(),
            "remote_ip": self.remote_ip,
            "requester": self.requester,
            "request_id": self.request_id,
            "operation": self.operation,
            "key": self.key,
            "request_uri": self.request_uri,
            "http_status": self.http_status,
            "error_code": self.error_code,
            "bytes_sent": self.bytes_sent,
            "object_size": self.object_size,
            "total_time_ms": self.total_time_ms,
            "referrer": self.referrer,
            "user_agent": self.user_agent,
            "version_id": self.version_id,
        }


@dataclass
class LoggingConfiguration:
    target_bucket: str
    target_prefix: str = ""
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "LoggingEnabled": {
                "TargetBucket": self.target_bucket,
                "TargetPrefix": self.target_prefix,
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional["LoggingConfiguration"]:
        logging_enabled = data.get("LoggingEnabled")
        if not logging_enabled:
            return None
        return cls(
            target_bucket=logging_enabled.get("TargetBucket", ""),
            target_prefix=logging_enabled.get("TargetPrefix", ""),
            enabled=True,
        )


class AccessLoggingService:
    def __init__(self, storage_root: Path, flush_interval: int = 60, max_buffer_size: int = 1000):
        self.storage_root = storage_root
        self.flush_interval = flush_interval
        self.max_buffer_size = max_buffer_size
        self._configs: Dict[str, LoggingConfiguration] = {}
        self._buffer: Dict[str, List[AccessLogEntry]] = {}
        self._buffer_lock = threading.Lock()
        self._shutdown = threading.Event()
        self._storage = None

        self._flush_thread = threading.Thread(target=self._flush_loop, name="access-log-flush", daemon=True)
        self._flush_thread.start()

    def set_storage(self, storage: Any) -> None:
        self._storage = storage

    def _config_path(self, bucket_name: str) -> Path:
        return self.storage_root / ".myfsio.sys" / "buckets" / bucket_name / "logging.json"

    def get_bucket_logging(self, bucket_name: str) -> Optional[LoggingConfiguration]:
        if bucket_name in self._configs:
            return self._configs[bucket_name]

        config_path = self._config_path(bucket_name)
        if not config_path.exists():
            return None

        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            config = LoggingConfiguration.from_dict(data)
            if config:
                self._configs[bucket_name] = config
            return config
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load logging config for {bucket_name}: {e}")
            return None

    def set_bucket_logging(self, bucket_name: str, config: LoggingConfiguration) -> None:
        config_path = self._config_path(bucket_name)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config.to_dict(), indent=2), encoding="utf-8")
        self._configs[bucket_name] = config

    def delete_bucket_logging(self, bucket_name: str) -> None:
        config_path = self._config_path(bucket_name)
        try:
            if config_path.exists():
                config_path.unlink()
        except OSError:
            pass
        self._configs.pop(bucket_name, None)

    def log_request(
        self,
        bucket_name: str,
        *,
        operation: str,
        key: str = "-",
        remote_ip: str = "-",
        requester: str = "-",
        request_uri: str = "-",
        http_status: int = 200,
        error_code: str = "",
        bytes_sent: int = 0,
        object_size: int = 0,
        total_time_ms: int = 0,
        referrer: str = "-",
        user_agent: str = "-",
        version_id: str = "-",
        request_id: str = "",
    ) -> None:
        config = self.get_bucket_logging(bucket_name)
        if not config or not config.enabled:
            return

        entry = AccessLogEntry(
            bucket_owner="local-owner",
            bucket=bucket_name,
            remote_ip=remote_ip,
            requester=requester,
            request_id=request_id or uuid.uuid4().hex[:16].upper(),
            operation=operation,
            key=key,
            request_uri=request_uri,
            http_status=http_status,
            error_code=error_code,
            bytes_sent=bytes_sent,
            object_size=object_size,
            total_time_ms=total_time_ms,
            referrer=referrer,
            user_agent=user_agent,
            version_id=version_id,
        )

        target_key = f"{config.target_bucket}:{config.target_prefix}"
        with self._buffer_lock:
            if target_key not in self._buffer:
                self._buffer[target_key] = []
            self._buffer[target_key].append(entry)

            if len(self._buffer[target_key]) >= self.max_buffer_size:
                self._flush_buffer(target_key)

    def _flush_loop(self) -> None:
        while not self._shutdown.is_set():
            time.sleep(self.flush_interval)
            self._flush_all()

    def _flush_all(self) -> None:
        with self._buffer_lock:
            targets = list(self._buffer.keys())

        for target_key in targets:
            self._flush_buffer(target_key)

    def _flush_buffer(self, target_key: str) -> None:
        with self._buffer_lock:
            entries = self._buffer.pop(target_key, [])

        if not entries or not self._storage:
            return

        try:
            bucket_name, prefix = target_key.split(":", 1)
        except ValueError:
            logger.error(f"Invalid target key: {target_key}")
            return

        now = datetime.now(timezone.utc)
        log_key = f"{prefix}{now.strftime('%Y-%m-%d-%H-%M-%S')}-{uuid.uuid4().hex[:8]}"

        log_content = "\n".join(entry.to_log_line() for entry in entries) + "\n"

        try:
            stream = io.BytesIO(log_content.encode("utf-8"))
            self._storage.put_object(bucket_name, log_key, stream, enforce_quota=False)
            logger.info(f"Flushed {len(entries)} access log entries to {bucket_name}/{log_key}")
        except Exception as e:
            logger.error(f"Failed to write access log to {bucket_name}/{log_key}: {e}")
            with self._buffer_lock:
                if target_key not in self._buffer:
                    self._buffer[target_key] = []
                self._buffer[target_key] = entries + self._buffer[target_key]

    def flush(self) -> None:
        self._flush_all()

    def shutdown(self) -> None:
        self._shutdown.set()
        self._flush_all()
        self._flush_thread.join(timeout=5.0)

    def get_stats(self) -> Dict[str, Any]:
        with self._buffer_lock:
            buffered = sum(len(entries) for entries in self._buffer.values())
        return {
            "buffered_entries": buffered,
            "target_buckets": len(self._buffer),
        }
