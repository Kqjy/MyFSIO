from __future__ import annotations

import json
import logging
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    from .connections import ConnectionStore, RemoteConnection
    from .replication import ReplicationManager, ReplicationRule
    from .storage import ObjectStorage

logger = logging.getLogger(__name__)

SITE_SYNC_USER_AGENT = "SiteSyncAgent/1.0"


@dataclass
class SyncedObjectInfo:
    last_synced_at: float
    remote_etag: str
    source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "last_synced_at": self.last_synced_at,
            "remote_etag": self.remote_etag,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SyncedObjectInfo":
        return cls(
            last_synced_at=data["last_synced_at"],
            remote_etag=data["remote_etag"],
            source=data["source"],
        )


@dataclass
class SyncState:
    synced_objects: Dict[str, SyncedObjectInfo] = field(default_factory=dict)
    last_full_sync: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "synced_objects": {k: v.to_dict() for k, v in self.synced_objects.items()},
            "last_full_sync": self.last_full_sync,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SyncState":
        synced_objects = {}
        for k, v in data.get("synced_objects", {}).items():
            synced_objects[k] = SyncedObjectInfo.from_dict(v)
        return cls(
            synced_objects=synced_objects,
            last_full_sync=data.get("last_full_sync"),
        )


@dataclass
class SiteSyncStats:
    last_sync_at: Optional[float] = None
    objects_pulled: int = 0
    objects_skipped: int = 0
    conflicts_resolved: int = 0
    deletions_applied: int = 0
    errors: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "last_sync_at": self.last_sync_at,
            "objects_pulled": self.objects_pulled,
            "objects_skipped": self.objects_skipped,
            "conflicts_resolved": self.conflicts_resolved,
            "deletions_applied": self.deletions_applied,
            "errors": self.errors,
        }


@dataclass
class RemoteObjectMeta:
    key: str
    size: int
    last_modified: datetime
    etag: str

    @classmethod
    def from_s3_object(cls, obj: Dict[str, Any]) -> "RemoteObjectMeta":
        return cls(
            key=obj["Key"],
            size=obj.get("Size", 0),
            last_modified=obj["LastModified"],
            etag=obj.get("ETag", "").strip('"'),
        )


def _create_sync_client(
    connection: "RemoteConnection",
    *,
    connect_timeout: int = 10,
    read_timeout: int = 120,
    max_retries: int = 2,
) -> Any:
    config = Config(
        user_agent_extra=SITE_SYNC_USER_AGENT,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={"max_attempts": max_retries},
        signature_version="s3v4",
        s3={"addressing_style": "path"},
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
    )
    return boto3.client(
        "s3",
        endpoint_url=connection.endpoint_url,
        aws_access_key_id=connection.access_key,
        aws_secret_access_key=connection.secret_key,
        region_name=connection.region or "us-east-1",
        config=config,
    )


class SiteSyncWorker:
    def __init__(
        self,
        storage: "ObjectStorage",
        connections: "ConnectionStore",
        replication_manager: "ReplicationManager",
        storage_root: Path,
        interval_seconds: int = 60,
        batch_size: int = 100,
        connect_timeout: int = 10,
        read_timeout: int = 120,
        max_retries: int = 2,
        clock_skew_tolerance_seconds: float = 1.0,
    ):
        self.storage = storage
        self.connections = connections
        self.replication_manager = replication_manager
        self.storage_root = storage_root
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_retries = max_retries
        self.clock_skew_tolerance_seconds = clock_skew_tolerance_seconds
        self._lock = threading.Lock()
        self._shutdown = threading.Event()
        self._sync_thread: Optional[threading.Thread] = None
        self._bucket_stats: Dict[str, SiteSyncStats] = {}

    def _create_client(self, connection: "RemoteConnection") -> Any:
        """Create an S3 client with the worker's configured timeouts."""
        return _create_sync_client(
            connection,
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            max_retries=self.max_retries,
        )

    def start(self) -> None:
        if self._sync_thread is not None and self._sync_thread.is_alive():
            return
        self._shutdown.clear()
        self._sync_thread = threading.Thread(
            target=self._sync_loop, name="site-sync-worker", daemon=True
        )
        self._sync_thread.start()
        logger.info("Site sync worker started (interval=%ds)", self.interval_seconds)

    def shutdown(self) -> None:
        self._shutdown.set()
        if self._sync_thread is not None:
            self._sync_thread.join(timeout=10.0)
        logger.info("Site sync worker shut down")

    def trigger_sync(self, bucket_name: str) -> Optional[SiteSyncStats]:
        from .replication import REPLICATION_MODE_BIDIRECTIONAL
        rule = self.replication_manager.get_rule(bucket_name)
        if not rule or rule.mode != REPLICATION_MODE_BIDIRECTIONAL or not rule.enabled:
            return None
        return self._sync_bucket(rule)

    def get_stats(self, bucket_name: str) -> Optional[SiteSyncStats]:
        with self._lock:
            return self._bucket_stats.get(bucket_name)

    def _sync_loop(self) -> None:
        while not self._shutdown.is_set():
            self._shutdown.wait(timeout=self.interval_seconds)
            if self._shutdown.is_set():
                break
            self._run_sync_cycle()

    def _run_sync_cycle(self) -> None:
        from .replication import REPLICATION_MODE_BIDIRECTIONAL
        for bucket_name, rule in list(self.replication_manager._rules.items()):
            if self._shutdown.is_set():
                break
            if rule.mode != REPLICATION_MODE_BIDIRECTIONAL or not rule.enabled:
                continue
            try:
                stats = self._sync_bucket(rule)
                with self._lock:
                    self._bucket_stats[bucket_name] = stats
            except Exception as e:
                logger.exception("Site sync failed for bucket %s: %s", bucket_name, e)

    def _sync_bucket(self, rule: "ReplicationRule") -> SiteSyncStats:
        stats = SiteSyncStats()
        connection = self.connections.get(rule.target_connection_id)
        if not connection:
            logger.warning("Connection %s not found for bucket %s", rule.target_connection_id, rule.bucket_name)
            stats.errors += 1
            return stats

        try:
            local_objects = self._list_local_objects(rule.bucket_name)
        except Exception as e:
            logger.error("Failed to list local objects for %s: %s", rule.bucket_name, e)
            stats.errors += 1
            return stats

        try:
            remote_objects = self._list_remote_objects(rule, connection)
        except Exception as e:
            logger.error("Failed to list remote objects for %s: %s", rule.bucket_name, e)
            stats.errors += 1
            return stats

        sync_state = self._load_sync_state(rule.bucket_name)
        local_keys = set(local_objects.keys())
        remote_keys = set(remote_objects.keys())

        to_pull = []
        for key in remote_keys:
            remote_meta = remote_objects[key]
            local_meta = local_objects.get(key)
            if local_meta is None:
                to_pull.append(key)
            else:
                resolution = self._resolve_conflict(local_meta, remote_meta)
                if resolution == "pull":
                    to_pull.append(key)
                    stats.conflicts_resolved += 1
                else:
                    stats.objects_skipped += 1

        pulled_count = 0
        for key in to_pull:
            if self._shutdown.is_set():
                break
            if pulled_count >= self.batch_size:
                break
            remote_meta = remote_objects[key]
            success = self._pull_object(rule, key, connection, remote_meta)
            if success:
                stats.objects_pulled += 1
                pulled_count += 1
                sync_state.synced_objects[key] = SyncedObjectInfo(
                    last_synced_at=time.time(),
                    remote_etag=remote_meta.etag,
                    source="remote",
                )
            else:
                stats.errors += 1

        if rule.sync_deletions:
            for key in list(sync_state.synced_objects.keys()):
                if key not in remote_keys and key in local_keys:
                    tracked = sync_state.synced_objects[key]
                    if tracked.source == "remote":
                        local_meta = local_objects.get(key)
                        if local_meta and local_meta.last_modified.timestamp() <= tracked.last_synced_at:
                            success = self._apply_remote_deletion(rule.bucket_name, key)
                            if success:
                                stats.deletions_applied += 1
                                del sync_state.synced_objects[key]

        sync_state.last_full_sync = time.time()
        self._save_sync_state(rule.bucket_name, sync_state)

        with self.replication_manager._stats_lock:
            rule.last_pull_at = time.time()
            self.replication_manager.save_rules()

        stats.last_sync_at = time.time()
        logger.info(
            "Site sync completed for %s: pulled=%d, skipped=%d, conflicts=%d, deletions=%d, errors=%d",
            rule.bucket_name,
            stats.objects_pulled,
            stats.objects_skipped,
            stats.conflicts_resolved,
            stats.deletions_applied,
            stats.errors,
        )
        return stats

    def _list_local_objects(self, bucket_name: str) -> Dict[str, Any]:
        from .storage import ObjectMeta
        objects = self.storage.list_objects_all(bucket_name)
        return {obj.key: obj for obj in objects}

    def _list_remote_objects(self, rule: "ReplicationRule", connection: "RemoteConnection") -> Dict[str, RemoteObjectMeta]:
        s3 = self._create_client(connection)
        result: Dict[str, RemoteObjectMeta] = {}
        paginator = s3.get_paginator("list_objects_v2")
        try:
            for page in paginator.paginate(Bucket=rule.target_bucket):
                for obj in page.get("Contents", []):
                    meta = RemoteObjectMeta.from_s3_object(obj)
                    result[meta.key] = meta
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":
                return {}
            raise
        return result

    def _resolve_conflict(self, local_meta: Any, remote_meta: RemoteObjectMeta) -> str:
        local_ts = local_meta.last_modified.timestamp()
        remote_ts = remote_meta.last_modified.timestamp()

        if abs(remote_ts - local_ts) < self.clock_skew_tolerance_seconds:
            local_etag = local_meta.etag or ""
            if remote_meta.etag == local_etag:
                return "skip"
            return "pull" if remote_meta.etag > local_etag else "keep"

        return "pull" if remote_ts > local_ts else "keep"

    def _pull_object(
        self,
        rule: "ReplicationRule",
        object_key: str,
        connection: "RemoteConnection",
        remote_meta: RemoteObjectMeta,
    ) -> bool:
        s3 = self._create_client(connection)
        tmp_path = None
        try:
            tmp_dir = self.storage_root / ".myfsio.sys" / "tmp"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=tmp_dir, delete=False) as tmp_file:
                tmp_path = Path(tmp_file.name)

            s3.download_file(rule.target_bucket, object_key, str(tmp_path))

            head_response = s3.head_object(Bucket=rule.target_bucket, Key=object_key)
            user_metadata = head_response.get("Metadata", {})

            with open(tmp_path, "rb") as f:
                self.storage.put_object(
                    rule.bucket_name,
                    object_key,
                    f,
                    metadata=user_metadata if user_metadata else None,
                )

            logger.debug("Pulled object %s/%s from remote", rule.bucket_name, object_key)
            return True

        except ClientError as e:
            logger.error("Failed to pull %s/%s: %s", rule.bucket_name, object_key, e)
            return False
        except Exception as e:
            logger.error("Failed to store pulled object %s/%s: %s", rule.bucket_name, object_key, e)
            return False
        finally:
            if tmp_path and tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    def _apply_remote_deletion(self, bucket_name: str, object_key: str) -> bool:
        try:
            self.storage.delete_object(bucket_name, object_key)
            logger.debug("Applied remote deletion for %s/%s", bucket_name, object_key)
            return True
        except Exception as e:
            logger.error("Failed to apply remote deletion for %s/%s: %s", bucket_name, object_key, e)
            return False

    def _sync_state_path(self, bucket_name: str) -> Path:
        return self.storage_root / ".myfsio.sys" / "buckets" / bucket_name / "site_sync_state.json"

    def _load_sync_state(self, bucket_name: str) -> SyncState:
        path = self._sync_state_path(bucket_name)
        if not path.exists():
            return SyncState()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return SyncState.from_dict(data)
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.warning("Failed to load sync state for %s: %s", bucket_name, e)
            return SyncState()

    def _save_sync_state(self, bucket_name: str, state: SyncState) -> None:
        path = self._sync_state_path(bucket_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")
        except OSError as e:
            logger.warning("Failed to save sync state for %s: %s", bucket_name, e)
