"""Background replication worker."""
from __future__ import annotations

import json
import logging
import mimetypes
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3.exceptions import S3UploadFailedError

from .connections import ConnectionStore, RemoteConnection
from .storage import ObjectStorage, StorageError

logger = logging.getLogger(__name__)

REPLICATION_USER_AGENT = "S3ReplicationAgent/1.0"
REPLICATION_CONNECT_TIMEOUT = 5
REPLICATION_READ_TIMEOUT = 30
STREAMING_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MiB - use streaming for larger files

REPLICATION_MODE_NEW_ONLY = "new_only"
REPLICATION_MODE_ALL = "all"


def _create_s3_client(connection: RemoteConnection, *, health_check: bool = False) -> Any:
    """Create a boto3 S3 client for the given connection.

    Args:
        connection: Remote S3 connection configuration
        health_check: If True, use minimal retries for quick health checks

    Returns:
        Configured boto3 S3 client
    """
    config = Config(
        user_agent_extra=REPLICATION_USER_AGENT,
        connect_timeout=REPLICATION_CONNECT_TIMEOUT,
        read_timeout=REPLICATION_READ_TIMEOUT,
        retries={'max_attempts': 1 if health_check else 2},
        signature_version='s3v4',
        s3={'addressing_style': 'path'},
        request_checksum_calculation='when_required',
        response_checksum_validation='when_required',
    )
    return boto3.client(
        "s3",
        endpoint_url=connection.endpoint_url,
        aws_access_key_id=connection.access_key,
        aws_secret_access_key=connection.secret_key,
        region_name=connection.region or 'us-east-1',
        config=config,
    )


@dataclass
class ReplicationStats:
    """Statistics for replication operations - computed dynamically."""
    objects_synced: int = 0
    objects_pending: int = 0
    objects_orphaned: int = 0
    bytes_synced: int = 0      
    last_sync_at: Optional[float] = None
    last_sync_key: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "objects_synced": self.objects_synced,
            "objects_pending": self.objects_pending,
            "objects_orphaned": self.objects_orphaned,
            "bytes_synced": self.bytes_synced,
            "last_sync_at": self.last_sync_at,
            "last_sync_key": self.last_sync_key,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ReplicationStats":
        return cls(
            objects_synced=data.get("objects_synced", 0),
            objects_pending=data.get("objects_pending", 0),
            objects_orphaned=data.get("objects_orphaned", 0),
            bytes_synced=data.get("bytes_synced", 0),
            last_sync_at=data.get("last_sync_at"),
            last_sync_key=data.get("last_sync_key"),
        )


@dataclass
class ReplicationRule:
    bucket_name: str
    target_connection_id: str
    target_bucket: str
    enabled: bool = True
    mode: str = REPLICATION_MODE_NEW_ONLY 
    created_at: Optional[float] = None
    stats: ReplicationStats = field(default_factory=ReplicationStats)
    
    def to_dict(self) -> dict:
        return {
            "bucket_name": self.bucket_name,
            "target_connection_id": self.target_connection_id,
            "target_bucket": self.target_bucket,
            "enabled": self.enabled,
            "mode": self.mode,
            "created_at": self.created_at,
            "stats": self.stats.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ReplicationRule":
        stats_data = data.pop("stats", {})
        if "mode" not in data:
            data["mode"] = REPLICATION_MODE_NEW_ONLY
        if "created_at" not in data:
            data["created_at"] = None
        rule = cls(**data)
        rule.stats = ReplicationStats.from_dict(stats_data) if stats_data else ReplicationStats()
        return rule


class ReplicationManager:
    def __init__(self, storage: ObjectStorage, connections: ConnectionStore, rules_path: Path) -> None:
        self.storage = storage
        self.connections = connections
        self.rules_path = rules_path
        self._rules: Dict[str, ReplicationRule] = {}
        self._stats_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ReplicationWorker")
        self._shutdown = False
        self.reload_rules()

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the replication executor gracefully.

        Args:
            wait: If True, wait for pending tasks to complete
        """
        self._shutdown = True
        self._executor.shutdown(wait=wait)
        logger.info("Replication manager shut down")

    def reload_rules(self) -> None:
        if not self.rules_path.exists():
            self._rules = {}
            return
        try:
            with open(self.rules_path, "r") as f:
                data = json.load(f)
                for bucket, rule_data in data.items():
                    self._rules[bucket] = ReplicationRule.from_dict(rule_data)
        except (OSError, ValueError) as e:
            logger.error(f"Failed to load replication rules: {e}")

    def save_rules(self) -> None:
        data = {b: rule.to_dict() for b, rule in self._rules.items()}
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.rules_path, "w") as f:
            json.dump(data, f, indent=2)

    def check_endpoint_health(self, connection: RemoteConnection) -> bool:
        """Check if a remote endpoint is reachable and responsive.

        Returns True if endpoint is healthy, False otherwise.
        Uses short timeouts to prevent blocking.
        """
        try:
            s3 = _create_s3_client(connection, health_check=True)
            s3.list_buckets()
            return True
        except Exception as e:
            logger.warning(f"Endpoint health check failed for {connection.name} ({connection.endpoint_url}): {e}")
            return False

    def get_rule(self, bucket_name: str) -> Optional[ReplicationRule]:
        return self._rules.get(bucket_name)

    def set_rule(self, rule: ReplicationRule) -> None:
        old_rule = self._rules.get(rule.bucket_name)
        was_all_mode = old_rule and old_rule.mode == REPLICATION_MODE_ALL if old_rule else False
        self._rules[rule.bucket_name] = rule
        self.save_rules()

        if rule.mode == REPLICATION_MODE_ALL and rule.enabled and not was_all_mode:
            logger.info(f"Replication mode ALL enabled for {rule.bucket_name}, triggering sync of existing objects")
            self._executor.submit(self.replicate_existing_objects, rule.bucket_name)

    def delete_rule(self, bucket_name: str) -> None:
        if bucket_name in self._rules:
            del self._rules[bucket_name]
            self.save_rules()
    
    def _update_last_sync(self, bucket_name: str, object_key: str = "") -> None:
        """Update last sync timestamp after a successful operation."""
        with self._stats_lock:
            rule = self._rules.get(bucket_name)
            if not rule:
                return
            rule.stats.last_sync_at = time.time()
            rule.stats.last_sync_key = object_key
            self.save_rules()
    
    def get_sync_status(self, bucket_name: str) -> Optional[ReplicationStats]:
        """Dynamically compute replication status by comparing source and destination buckets."""
        rule = self.get_rule(bucket_name)
        if not rule:
            return None
        
        connection = self.connections.get(rule.target_connection_id)
        if not connection:
            return rule.stats
        
        try:
            source_objects = self.storage.list_objects_all(bucket_name)
            source_keys = {obj.key: obj.size for obj in source_objects}

            s3 = _create_s3_client(connection)

            dest_keys = set()
            bytes_synced = 0
            paginator = s3.get_paginator('list_objects_v2')
            try:
                for page in paginator.paginate(Bucket=rule.target_bucket):
                    for obj in page.get('Contents', []):
                        dest_keys.add(obj['Key'])
                        if obj['Key'] in source_keys:
                            bytes_synced += obj.get('Size', 0)
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucket':
                    dest_keys = set()
                else:
                    raise
            
            synced = source_keys.keys() & dest_keys  
            orphaned = dest_keys - source_keys.keys() 
            
            if rule.mode == REPLICATION_MODE_ALL:
                pending = source_keys.keys() - dest_keys 
            else:
                pending = set()
            
            rule.stats.objects_synced = len(synced)
            rule.stats.objects_pending = len(pending)
            rule.stats.objects_orphaned = len(orphaned)
            rule.stats.bytes_synced = bytes_synced
            
            return rule.stats
            
        except (ClientError, StorageError) as e:
            logger.error(f"Failed to compute sync status for {bucket_name}: {e}")
            return rule.stats
    
    def replicate_existing_objects(self, bucket_name: str) -> None:
        """Trigger replication for all existing objects in a bucket."""
        rule = self.get_rule(bucket_name)
        if not rule or not rule.enabled:
            return
        
        connection = self.connections.get(rule.target_connection_id)
        if not connection:
            logger.warning(f"Cannot replicate existing objects: Connection {rule.target_connection_id} not found")
            return
        
        if not self.check_endpoint_health(connection):
            logger.warning(f"Cannot replicate existing objects: Endpoint {connection.name} ({connection.endpoint_url}) is not reachable")
            return
        
        try:
            objects = self.storage.list_objects_all(bucket_name)
            logger.info(f"Starting replication of {len(objects)} existing objects from {bucket_name}")
            for obj in objects:
                self._executor.submit(self._replicate_task, bucket_name, obj.key, rule, connection, "write")
        except StorageError as e:
            logger.error(f"Failed to list objects for replication: {e}")

    def create_remote_bucket(self, connection_id: str, bucket_name: str) -> None:
        """Create a bucket on the remote connection."""
        connection = self.connections.get(connection_id)
        if not connection:
            raise ValueError(f"Connection {connection_id} not found")

        try:
            s3 = _create_s3_client(connection)
            s3.create_bucket(Bucket=bucket_name)
        except ClientError as e:
            logger.error(f"Failed to create remote bucket {bucket_name}: {e}")
            raise

    def trigger_replication(self, bucket_name: str, object_key: str, action: str = "write") -> None:
        rule = self.get_rule(bucket_name)
        if not rule or not rule.enabled:
            return

        connection = self.connections.get(rule.target_connection_id)
        if not connection:
            logger.warning(f"Replication skipped for {bucket_name}/{object_key}: Connection {rule.target_connection_id} not found")
            return

        if not self.check_endpoint_health(connection):
            logger.warning(f"Replication skipped for {bucket_name}/{object_key}: Endpoint {connection.name} ({connection.endpoint_url}) is not reachable")
            return

        self._executor.submit(self._replicate_task, bucket_name, object_key, rule, connection, action)

    def _replicate_task(self, bucket_name: str, object_key: str, rule: ReplicationRule, conn: RemoteConnection, action: str) -> None:
        if self._shutdown:
            return

        # Re-check if rule is still enabled (may have been paused after task was submitted)
        current_rule = self.get_rule(bucket_name)
        if not current_rule or not current_rule.enabled:
            logger.debug(f"Replication skipped for {bucket_name}/{object_key}: rule disabled or removed")
            return

        if ".." in object_key or object_key.startswith("/") or object_key.startswith("\\"):
            logger.error(f"Invalid object key in replication (path traversal attempt): {object_key}")
            return

        try:
            from .storage import ObjectStorage
            ObjectStorage._sanitize_object_key(object_key)
        except StorageError as e:
            logger.error(f"Object key validation failed in replication: {e}")
            return

        try:
            s3 = _create_s3_client(conn)

            if action == "delete":
                try:
                    s3.delete_object(Bucket=rule.target_bucket, Key=object_key)
                    logger.info(f"Replicated DELETE {bucket_name}/{object_key} to {conn.name} ({rule.target_bucket})")
                    self._update_last_sync(bucket_name, object_key)
                except ClientError as e:
                    logger.error(f"Replication DELETE failed for {bucket_name}/{object_key}: {e}")
                return

            try:
                path = self.storage.get_object_path(bucket_name, object_key)
            except StorageError:
                logger.error(f"Source object not found: {bucket_name}/{object_key}")
                return

            content_type, _ = mimetypes.guess_type(path)
            file_size = path.stat().st_size

            logger.info(f"Replicating {bucket_name}/{object_key}: Size={file_size}, ContentType={content_type}")

            def do_upload() -> None:
                """Upload object using appropriate method based on file size.

                For small files (< 10 MiB): Read into memory for simpler handling
                For large files: Use streaming upload to avoid memory issues
                """
                extra_args = {}
                if content_type:
                    extra_args["ContentType"] = content_type

                if file_size >= STREAMING_THRESHOLD_BYTES:
                    # Use multipart upload for large files
                    s3.upload_file(
                        str(path),
                        rule.target_bucket,
                        object_key,
                        ExtraArgs=extra_args if extra_args else None,
                    )
                else:
                    # Read small files into memory
                    file_content = path.read_bytes()
                    put_kwargs = {
                        "Bucket": rule.target_bucket,
                        "Key": object_key,
                        "Body": file_content,
                        **extra_args,
                    }
                    s3.put_object(**put_kwargs)

            try:
                do_upload()
            except (ClientError, S3UploadFailedError) as e:
                error_code = None
                if isinstance(e, ClientError):
                    error_code = e.response['Error']['Code']
                elif isinstance(e, S3UploadFailedError):
                    if "NoSuchBucket" in str(e):
                        error_code = 'NoSuchBucket'

                if error_code == 'NoSuchBucket':
                    logger.info(f"Target bucket {rule.target_bucket} not found. Attempting to create it.")
                    bucket_ready = False
                    try:
                        s3.create_bucket(Bucket=rule.target_bucket)
                        bucket_ready = True
                        logger.info(f"Created target bucket {rule.target_bucket}")
                    except ClientError as bucket_err:
                        if bucket_err.response['Error']['Code'] in ('BucketAlreadyExists', 'BucketAlreadyOwnedByYou'):
                            logger.debug(f"Bucket {rule.target_bucket} already exists (created by another thread)")
                            bucket_ready = True
                        else:
                            logger.error(f"Failed to create target bucket {rule.target_bucket}: {bucket_err}")
                            raise e

                    if bucket_ready:
                        do_upload()
                else:
                    raise e

            logger.info(f"Replicated {bucket_name}/{object_key} to {conn.name} ({rule.target_bucket})")
            self._update_last_sync(bucket_name, object_key)

        except (ClientError, OSError, ValueError) as e:
            logger.error(f"Replication failed for {bucket_name}/{object_key}: {e}")
        except Exception:
            logger.exception(f"Unexpected error during replication for {bucket_name}/{object_key}")

