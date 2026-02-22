from __future__ import annotations

import ipaddress
import json
import logging
import queue
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from urllib3.util.connection import create_connection as _urllib3_create_connection


def _resolve_and_check_url(url: str, allow_internal: bool = False) -> Optional[str]:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None
        cloud_metadata_hosts = {
            "metadata.google.internal",
            "169.254.169.254",
        }
        if hostname.lower() in cloud_metadata_hosts:
            return None
        if allow_internal:
            return hostname
        blocked_hosts = {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
        }
        if hostname.lower() in blocked_hosts:
            return None
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(resolved_ip)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return None
            return resolved_ip
        except (socket.gaierror, ValueError):
            return None
    except Exception:
        return None


def _is_safe_url(url: str, allow_internal: bool = False) -> bool:
    return _resolve_and_check_url(url, allow_internal) is not None


_dns_pin_lock = threading.Lock()


def _pinned_post(url: str, pinned_ip: str, **kwargs: Any) -> requests.Response:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    session = requests.Session()
    original_create = _urllib3_create_connection

    def _create_pinned(address: Any, *args: Any, **kw: Any) -> Any:
        host, req_port = address
        if host == hostname:
            return original_create((pinned_ip, req_port), *args, **kw)
        return original_create(address, *args, **kw)

    import urllib3.util.connection as _conn_mod
    with _dns_pin_lock:
        _conn_mod.create_connection = _create_pinned
        try:
            return session.post(url, **kwargs)
        finally:
            _conn_mod.create_connection = original_create


logger = logging.getLogger(__name__)


@dataclass
class NotificationEvent:
    event_name: str
    bucket_name: str
    object_key: str
    object_size: int = 0
    etag: str = ""
    version_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    source_ip: str = ""
    user_identity: str = ""

    def to_s3_event(self) -> Dict[str, Any]:
        return {
            "Records": [
                {
                    "eventVersion": "2.1",
                    "eventSource": "myfsio:s3",
                    "awsRegion": "local",
                    "eventTime": self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "eventName": self.event_name,
                    "userIdentity": {
                        "principalId": self.user_identity or "ANONYMOUS",
                    },
                    "requestParameters": {
                        "sourceIPAddress": self.source_ip or "127.0.0.1",
                    },
                    "responseElements": {
                        "x-amz-request-id": self.request_id,
                        "x-amz-id-2": self.request_id,
                    },
                    "s3": {
                        "s3SchemaVersion": "1.0",
                        "configurationId": "notification",
                        "bucket": {
                            "name": self.bucket_name,
                            "ownerIdentity": {"principalId": "local"},
                            "arn": f"arn:aws:s3:::{self.bucket_name}",
                        },
                        "object": {
                            "key": self.object_key,
                            "size": self.object_size,
                            "eTag": self.etag,
                            "versionId": self.version_id or "null",
                            "sequencer": f"{int(time.time() * 1000):016X}",
                        },
                    },
                }
            ]
        }


@dataclass
class WebhookDestination:
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 30
    retry_count: int = 3
    retry_delay_seconds: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "headers": self.headers,
            "timeout_seconds": self.timeout_seconds,
            "retry_count": self.retry_count,
            "retry_delay_seconds": self.retry_delay_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WebhookDestination":
        return cls(
            url=data.get("url", ""),
            headers=data.get("headers", {}),
            timeout_seconds=data.get("timeout_seconds", 30),
            retry_count=data.get("retry_count", 3),
            retry_delay_seconds=data.get("retry_delay_seconds", 1),
        )


@dataclass
class NotificationConfiguration:
    id: str
    events: List[str]
    destination: WebhookDestination
    prefix_filter: str = ""
    suffix_filter: str = ""

    def matches_event(self, event_name: str, object_key: str) -> bool:
        event_match = False
        for pattern in self.events:
            if pattern.endswith("*"):
                base = pattern[:-1]
                if event_name.startswith(base):
                    event_match = True
                    break
            elif pattern == event_name:
                event_match = True
                break

        if not event_match:
            return False

        if self.prefix_filter and not object_key.startswith(self.prefix_filter):
            return False
        if self.suffix_filter and not object_key.endswith(self.suffix_filter):
            return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Id": self.id,
            "Events": self.events,
            "Destination": self.destination.to_dict(),
            "Filter": {
                "Key": {
                    "FilterRules": [
                        {"Name": "prefix", "Value": self.prefix_filter},
                        {"Name": "suffix", "Value": self.suffix_filter},
                    ]
                }
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NotificationConfiguration":
        prefix = ""
        suffix = ""
        filter_data = data.get("Filter", {})
        key_filter = filter_data.get("Key", {})
        for rule in key_filter.get("FilterRules", []):
            if rule.get("Name") == "prefix":
                prefix = rule.get("Value", "")
            elif rule.get("Name") == "suffix":
                suffix = rule.get("Value", "")

        return cls(
            id=data.get("Id", uuid.uuid4().hex),
            events=data.get("Events", []),
            destination=WebhookDestination.from_dict(data.get("Destination", {})),
            prefix_filter=prefix,
            suffix_filter=suffix,
        )


class NotificationService:
    def __init__(self, storage_root: Path, worker_count: int = 2, allow_internal_endpoints: bool = False):
        self.storage_root = storage_root
        self._allow_internal_endpoints = allow_internal_endpoints
        self._configs: Dict[str, List[NotificationConfiguration]] = {}
        self._queue: queue.Queue[tuple[NotificationEvent, WebhookDestination]] = queue.Queue()
        self._workers: List[threading.Thread] = []
        self._shutdown = threading.Event()
        self._stats = {
            "events_queued": 0,
            "events_sent": 0,
            "events_failed": 0,
        }

        for i in range(worker_count):
            worker = threading.Thread(target=self._worker_loop, name=f"notification-worker-{i}", daemon=True)
            worker.start()
            self._workers.append(worker)

    def _config_path(self, bucket_name: str) -> Path:
        return self.storage_root / ".myfsio.sys" / "buckets" / bucket_name / "notifications.json"

    def get_bucket_notifications(self, bucket_name: str) -> List[NotificationConfiguration]:
        if bucket_name in self._configs:
            return self._configs[bucket_name]

        config_path = self._config_path(bucket_name)
        if not config_path.exists():
            return []

        try:
            data = json.loads(config_path.read_text(encoding="utf-8"))
            configs = [NotificationConfiguration.from_dict(c) for c in data.get("configurations", [])]
            self._configs[bucket_name] = configs
            return configs
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to load notification config for {bucket_name}: {e}")
            return []

    def set_bucket_notifications(
        self, bucket_name: str, configurations: List[NotificationConfiguration]
    ) -> None:
        config_path = self._config_path(bucket_name)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        data = {"configurations": [c.to_dict() for c in configurations]}
        config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self._configs[bucket_name] = configurations

    def delete_bucket_notifications(self, bucket_name: str) -> None:
        config_path = self._config_path(bucket_name)
        try:
            if config_path.exists():
                config_path.unlink()
        except OSError:
            pass
        self._configs.pop(bucket_name, None)

    def emit_event(self, event: NotificationEvent) -> None:
        configurations = self.get_bucket_notifications(event.bucket_name)
        if not configurations:
            return

        for config in configurations:
            if config.matches_event(event.event_name, event.object_key):
                self._queue.put((event, config.destination))
                self._stats["events_queued"] += 1
                logger.debug(
                    f"Queued notification for {event.event_name} on {event.bucket_name}/{event.object_key}"
                )

    def emit_object_created(
        self,
        bucket_name: str,
        object_key: str,
        *,
        size: int = 0,
        etag: str = "",
        version_id: Optional[str] = None,
        request_id: str = "",
        source_ip: str = "",
        user_identity: str = "",
        operation: str = "Put",
    ) -> None:
        event = NotificationEvent(
            event_name=f"s3:ObjectCreated:{operation}",
            bucket_name=bucket_name,
            object_key=object_key,
            object_size=size,
            etag=etag,
            version_id=version_id,
            request_id=request_id or uuid.uuid4().hex,
            source_ip=source_ip,
            user_identity=user_identity,
        )
        self.emit_event(event)

    def emit_object_removed(
        self,
        bucket_name: str,
        object_key: str,
        *,
        version_id: Optional[str] = None,
        request_id: str = "",
        source_ip: str = "",
        user_identity: str = "",
        operation: str = "Delete",
    ) -> None:
        event = NotificationEvent(
            event_name=f"s3:ObjectRemoved:{operation}",
            bucket_name=bucket_name,
            object_key=object_key,
            version_id=version_id,
            request_id=request_id or uuid.uuid4().hex,
            source_ip=source_ip,
            user_identity=user_identity,
        )
        self.emit_event(event)

    def _worker_loop(self) -> None:
        while not self._shutdown.is_set():
            try:
                event, destination = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                self._send_notification(event, destination)
                self._stats["events_sent"] += 1
            except Exception as e:
                self._stats["events_failed"] += 1
                logger.error(f"Failed to send notification: {e}")
            finally:
                self._queue.task_done()

    def _send_notification(self, event: NotificationEvent, destination: WebhookDestination) -> None:
        resolved_ip = _resolve_and_check_url(destination.url, allow_internal=self._allow_internal_endpoints)
        if not resolved_ip:
            raise RuntimeError(f"Blocked request (SSRF protection): {destination.url}")
        payload = event.to_s3_event()
        headers = {"Content-Type": "application/json", **destination.headers}

        last_error = None
        for attempt in range(destination.retry_count):
            try:
                response = _pinned_post(
                    destination.url,
                    resolved_ip,
                    json=payload,
                    headers=headers,
                    timeout=destination.timeout_seconds,
                )
                if response.status_code < 400:
                    logger.info(
                        f"Notification sent: {event.event_name} -> {destination.url} (status={response.status_code})"
                    )
                    return
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            except requests.RequestException as e:
                last_error = str(e)

            if attempt < destination.retry_count - 1:
                time.sleep(destination.retry_delay_seconds * (attempt + 1))

        raise RuntimeError(f"Failed after {destination.retry_count} attempts: {last_error}")

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def shutdown(self) -> None:
        self._shutdown.set()
        for worker in self._workers:
            worker.join(timeout=5.0)
