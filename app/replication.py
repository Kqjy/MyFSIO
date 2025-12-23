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
from typing import Dict, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from boto3.exceptions import S3UploadFailedError

from .connections import ConnectionStore, RemoteConnection
from .storage import ObjectStorage, StorageError

logger = logging.getLogger(__name__)

REPLICATION_USER_AGENT = "S3ReplicationAgent/1.0"
REPLICATION_CONNECT_TIMEOUT = 5  # seconds to wait for connection
REPLICATION_READ_TIMEOUT = 30   # seconds to wait for response

REPLICATION_MODE_NEW_ONLY = "new_only"
REPLICATION_MODE_ALL = "all"


@dataclass
class ReplicationStats:
    """Statistics for replication operations - computed dynamically."""
    objects_synced: int = 0          # Objects that exist in both source and destination
    objects_pending: int = 0         # Objects in source but not in destination
    objects_orphaned: int = 0        # Objects in destination but not in source (will be deleted)
    bytes_synced: int = 0            # Total bytes synced to destination
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
        # Handle old rules without mode/created_at
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
        self.reload_rules()

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
            config = Config(
                user_agent_extra=REPLICATION_USER_AGENT,
                connect_timeout=REPLICATION_CONNECT_TIMEOUT,
                read_timeout=REPLICATION_READ_TIMEOUT,
                retries={'max_attempts': 1}  # Don't retry for health checks
            )
            s3 = boto3.client(
                "s3",
                endpoint_url=connection.endpoint_url,
                aws_access_key_id=connection.access_key,
                aws_secret_access_key=connection.secret_key,
                region_name=connection.region,
                config=config,
            )
            # Simple list_buckets call to verify connectivity
            s3.list_buckets()
            return True
        except Exception as e:
            logger.warning(f"Endpoint health check failed for {connection.name} ({connection.endpoint_url}): {e}")
            return False

    def get_rule(self, bucket_name: str) -> Optional[ReplicationRule]:
        return self._rules.get(bucket_name)

    def set_rule(self, rule: ReplicationRule) -> None:
        self._rules[rule.bucket_name] = rule
        self.save_rules()

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
            return rule.stats  # Return cached stats if connection unavailable
        
        try:
            # Get source objects
            source_objects = self.storage.list_objects_all(bucket_name)
            source_keys = {obj.key: obj.size for obj in source_objects}
            
            # Get destination objects
            s3 = boto3.client(
                "s3",
                endpoint_url=connection.endpoint_url,
                aws_access_key_id=connection.access_key,
                aws_secret_access_key=connection.secret_key,
                region_name=connection.region,
            )
            
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
                    # Destination bucket doesn't exist yet
                    dest_keys = set()
                else:
                    raise
            
            # Compute stats
            synced = source_keys.keys() & dest_keys  # Objects in both
            orphaned = dest_keys - source_keys.keys()  # In dest but not source
            
            # For "new_only" mode, we can't determine pending since we don't know
            # which objects existed before replication was enabled. Only "all" mode
            # should show pending (objects that should be replicated but aren't yet).
            if rule.mode == REPLICATION_MODE_ALL:
                pending = source_keys.keys() - dest_keys  # In source but not dest
            else:
                pending = set()  # New-only mode: don't show pre-existing as pending
            
            # Update cached stats with computed values
            rule.stats.objects_synced = len(synced)
            rule.stats.objects_pending = len(pending)
            rule.stats.objects_orphaned = len(orphaned)
            rule.stats.bytes_synced = bytes_synced
            
            return rule.stats
            
        except (ClientError, StorageError) as e:
            logger.error(f"Failed to compute sync status for {bucket_name}: {e}")
            return rule.stats  # Return cached stats on error
    
    def replicate_existing_objects(self, bucket_name: str) -> None:
        """Trigger replication for all existing objects in a bucket."""
        rule = self.get_rule(bucket_name)
        if not rule or not rule.enabled:
            return
        
        connection = self.connections.get(rule.target_connection_id)
        if not connection:
            logger.warning(f"Cannot replicate existing objects: Connection {rule.target_connection_id} not found")
            return
        
        # Check endpoint health before starting bulk replication
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
            s3 = boto3.client(
                "s3",
                endpoint_url=connection.endpoint_url,
                aws_access_key_id=connection.access_key,
                aws_secret_access_key=connection.secret_key,
                region_name=connection.region,
            )
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

        # Check endpoint health before attempting replication to prevent hangs
        if not self.check_endpoint_health(connection):
            logger.warning(f"Replication skipped for {bucket_name}/{object_key}: Endpoint {connection.name} ({connection.endpoint_url}) is not reachable")
            return

        self._executor.submit(self._replicate_task, bucket_name, object_key, rule, connection, action)

    def _replicate_task(self, bucket_name: str, object_key: str, rule: ReplicationRule, conn: RemoteConnection, action: str) -> None:
        if ".." in object_key or object_key.startswith("/") or object_key.startswith("\\"):
            logger.error(f"Invalid object key in replication (path traversal attempt): {object_key}")
            return
        
        try:
            from .storage import ObjectStorage
            ObjectStorage._sanitize_object_key(object_key)
        except StorageError as e:
            logger.error(f"Object key validation failed in replication: {e}")
            return
        
        file_size = 0
        try:
            config = Config(
                user_agent_extra=REPLICATION_USER_AGENT,
                connect_timeout=REPLICATION_CONNECT_TIMEOUT,
                read_timeout=REPLICATION_READ_TIMEOUT,
                retries={'max_attempts': 2},  # Limited retries to prevent long hangs
                signature_version='s3v4',  # Force signature v4 for compatibility
                s3={'addressing_style': 'path'}  # Use path-style addressing for compatibility
            )
            s3 = boto3.client(
                "s3",
                endpoint_url=conn.endpoint_url,
                aws_access_key_id=conn.access_key,
                aws_secret_access_key=conn.secret_key,
                region_name=conn.region or 'us-east-1',  # Default region if not set
                config=config,
            )

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

            metadata = self.storage.get_object_metadata(bucket_name, object_key)

            extra_args = {}
            if metadata:
                extra_args["Metadata"] = metadata
            
            # Guess content type to prevent corruption/wrong handling
            content_type, _ = mimetypes.guess_type(path)
            file_size = path.stat().st_size

            logger.info(f"Replicating {bucket_name}/{object_key}: Size={file_size}, ContentType={content_type}")

            def do_put_object() -> None:
                """Helper to upload object.
                
                Reads the file content into memory first to avoid signature calculation
                issues with certain binary file types (like GIFs) when streaming.
                Do NOT set ContentLength explicitly - boto3 calculates it from the bytes
                and setting it manually can cause SignatureDoesNotMatch errors.
                """
                file_content = path.read_bytes()
                put_kwargs = {
                    "Bucket": rule.target_bucket,
                    "Key": object_key,
                    "Body": file_content,
                }
                if content_type:
                    put_kwargs["ContentType"] = content_type
                if metadata:
                    put_kwargs["Metadata"] = metadata
                
                # Debug logging for signature issues
                logger.debug(f"PUT request details: bucket={rule.target_bucket}, key={repr(object_key)}, "
                            f"content_type={content_type}, body_len={len(file_content)}, "
                            f"endpoint={conn.endpoint_url}")
                logger.debug(f"Key bytes: {object_key.encode('utf-8')}")
                
                s3.put_object(**put_kwargs)

            try:
                do_put_object()
            except (ClientError, S3UploadFailedError) as e:
                error_code = None
                if isinstance(e, ClientError):
                    error_code = e.response['Error']['Code']
                elif isinstance(e, S3UploadFailedError):
                    if "NoSuchBucket" in str(e):
                        error_code = 'NoSuchBucket'

                # Handle NoSuchBucket - create bucket and retry
                if error_code == 'NoSuchBucket':
                    logger.info(f"Target bucket {rule.target_bucket} not found. Attempting to create it.")
                    bucket_ready = False
                    try:
                        s3.create_bucket(Bucket=rule.target_bucket)
                        bucket_ready = True
                        logger.info(f"Created target bucket {rule.target_bucket}")
                    except ClientError as bucket_err:
                        # BucketAlreadyExists or BucketAlreadyOwnedByYou means another thread created it - that's OK!
                        if bucket_err.response['Error']['Code'] in ('BucketAlreadyExists', 'BucketAlreadyOwnedByYou'):
                            logger.debug(f"Bucket {rule.target_bucket} already exists (created by another thread)")
                            bucket_ready = True
                        else:
                            logger.error(f"Failed to create target bucket {rule.target_bucket}: {bucket_err}")
                            raise e  # Raise original NoSuchBucket error
                    
                    if bucket_ready:
                        # Retry the upload now that bucket exists
                        do_put_object()
                else:
                    raise e
            
            logger.info(f"Replicated {bucket_name}/{object_key} to {conn.name} ({rule.target_bucket})")
            self._update_last_sync(bucket_name, object_key)

        except (ClientError, OSError, ValueError) as e:
            logger.error(f"Replication failed for {bucket_name}/{object_key}: {e}")
            # Log additional debug info for signature errors
            if isinstance(e, ClientError):
                error_code = e.response.get('Error', {}).get('Code', '')
                if 'Signature' in str(e) or 'Signature' in error_code:
                    logger.error(f"Signature debug - Key repr: {repr(object_key)}, "
                                f"Endpoint: {conn.endpoint_url}, "
                                f"Region: {conn.region}, "
                                f"Target bucket: {rule.target_bucket}")
        except Exception:
            logger.exception(f"Unexpected error during replication for {bucket_name}/{object_key}")

