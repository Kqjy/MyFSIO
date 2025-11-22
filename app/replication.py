"""Background replication worker."""
from __future__ import annotations

import logging
import mimetypes
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError
from boto3.exceptions import S3UploadFailedError

from .connections import ConnectionStore, RemoteConnection
from .storage import ObjectStorage, StorageError

logger = logging.getLogger(__name__)


@dataclass
class ReplicationRule:
    bucket_name: str
    target_connection_id: str
    target_bucket: str
    enabled: bool = True


class ReplicationManager:
    def __init__(self, storage: ObjectStorage, connections: ConnectionStore, rules_path: Path) -> None:
        self.storage = storage
        self.connections = connections
        self.rules_path = rules_path
        self._rules: Dict[str, ReplicationRule] = {}
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ReplicationWorker")
        self.reload_rules()

    def reload_rules(self) -> None:
        if not self.rules_path.exists():
            self._rules = {}
            return
        try:
            import json
            with open(self.rules_path, "r") as f:
                data = json.load(f)
                for bucket, rule_data in data.items():
                    self._rules[bucket] = ReplicationRule(**rule_data)
        except (OSError, ValueError) as e:
            logger.error(f"Failed to load replication rules: {e}")

    def save_rules(self) -> None:
        import json
        data = {b: rule.__dict__ for b, rule in self._rules.items()}
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.rules_path, "w") as f:
            json.dump(data, f, indent=2)

    def get_rule(self, bucket_name: str) -> Optional[ReplicationRule]:
        return self._rules.get(bucket_name)

    def set_rule(self, rule: ReplicationRule) -> None:
        self._rules[rule.bucket_name] = rule
        self.save_rules()

    def delete_rule(self, bucket_name: str) -> None:
        if bucket_name in self._rules:
            del self._rules[bucket_name]
            self.save_rules()

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

    def trigger_replication(self, bucket_name: str, object_key: str) -> None:
        rule = self.get_rule(bucket_name)
        if not rule or not rule.enabled:
            return

        connection = self.connections.get(rule.target_connection_id)
        if not connection:
            logger.warning(f"Replication skipped for {bucket_name}/{object_key}: Connection {rule.target_connection_id} not found")
            return

        self._executor.submit(self._replicate_task, bucket_name, object_key, rule, connection)

    def _replicate_task(self, bucket_name: str, object_key: str, rule: ReplicationRule, conn: RemoteConnection) -> None:
        try:
            # 1. Get local file path
            # Note: We are accessing internal storage structure here. 
            # Ideally storage.py should expose a 'get_file_path' or we read the stream.
            # For efficiency, we'll try to read the file directly if we can, or use storage.get_object
            
            # Using boto3 to upload
            s3 = boto3.client(
                "s3",
                endpoint_url=conn.endpoint_url,
                aws_access_key_id=conn.access_key,
                aws_secret_access_key=conn.secret_key,
                region_name=conn.region,
            )

            # We need the file content. 
            # Since ObjectStorage is filesystem based, let's get the stream.
            # We need to be careful about closing it.
            try:
                path = self.storage.get_object_path(bucket_name, object_key)
            except StorageError:
                return

            metadata = self.storage.get_object_metadata(bucket_name, object_key)

            extra_args = {}
            if metadata:
                extra_args["Metadata"] = metadata
            
            # Guess content type to prevent corruption/wrong handling
            content_type, _ = mimetypes.guess_type(path)
            file_size = path.stat().st_size

            # Debug: Calculate MD5 of source file
            import hashlib
            md5_hash = hashlib.md5()
            with path.open("rb") as f:
                # Log first 32 bytes
                header = f.read(32)
                logger.info(f"Source first 32 bytes: {header.hex()}")
                md5_hash.update(header)
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
            source_md5 = md5_hash.hexdigest()
            logger.info(f"Replicating {bucket_name}/{object_key}: Size={file_size}, MD5={source_md5}, ContentType={content_type}")

            try:
                with path.open("rb") as f:
                    s3.put_object(
                        Bucket=rule.target_bucket,
                        Key=object_key,
                        Body=f,
                        ContentLength=file_size,
                        ContentType=content_type or "application/octet-stream",
                        Metadata=metadata or {}
                    )
            except (ClientError, S3UploadFailedError) as e:
                # Check if it's a NoSuchBucket error (either direct or wrapped)
                is_no_bucket = False
                if isinstance(e, ClientError):
                    if e.response['Error']['Code'] == 'NoSuchBucket':
                        is_no_bucket = True
                elif isinstance(e, S3UploadFailedError):
                    if "NoSuchBucket" in str(e):
                        is_no_bucket = True

                if is_no_bucket:
                    logger.info(f"Target bucket {rule.target_bucket} not found. Attempting to create it.")
                    try:
                        s3.create_bucket(Bucket=rule.target_bucket)
                        # Retry upload
                        with path.open("rb") as f:
                            s3.put_object(
                                Bucket=rule.target_bucket,
                                Key=object_key,
                                Body=f,
                                ContentLength=file_size,
                                ContentType=content_type or "application/octet-stream",
                                Metadata=metadata or {}
                            )
                    except Exception as create_err:
                        logger.error(f"Failed to create target bucket {rule.target_bucket}: {create_err}")
                        raise e # Raise original error
                else:
                    raise e
            
            logger.info(f"Replicated {bucket_name}/{object_key} to {conn.name} ({rule.target_bucket})")

        except (ClientError, OSError, ValueError) as e:
            logger.error(f"Replication failed for {bucket_name}/{object_key}: {e}")
        except Exception:
            logger.exception(f"Unexpected error during replication for {bucket_name}/{object_key}")
