"""Background replication worker."""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError

from .connections import ConnectionStore, RemoteConnection
from .storage import ObjectStorage

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
            meta = self.storage.get_object_meta(bucket_name, object_key)
            if not meta:
                return

            with self.storage.open_object(bucket_name, object_key) as f:
                extra_args = {}
                if meta.metadata:
                    extra_args["Metadata"] = meta.metadata
                
                s3.upload_fileobj(
                    f,
                    rule.target_bucket,
                    object_key,
                    ExtraArgs=extra_args
                )
            
            logger.info(f"Replicated {bucket_name}/{object_key} to {conn.name} ({rule.target_bucket})")

        except (ClientError, OSError, ValueError) as e:
            logger.error(f"Replication failed for {bucket_name}/{object_key}: {e}")
        except Exception:
            logger.exception(f"Unexpected error during replication for {bucket_name}/{object_key}")
