from __future__ import annotations

import io
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional

from .encryption import EncryptionManager, EncryptionMetadata, EncryptionError
from .storage import ObjectStorage, ObjectMeta, StorageError


class EncryptedObjectStorage:
    """Object storage with transparent server-side encryption.
    
    This class wraps ObjectStorage and provides transparent encryption/decryption
    of objects based on bucket encryption configuration.
    
    Encryption is applied when:
    1. Bucket has default encryption configured (SSE-S3 or SSE-KMS)
    2. Client explicitly requests encryption via headers
    
    The encryption metadata is stored alongside object metadata.
    """
    
    STREAMING_THRESHOLD = 64 * 1024
    
    def __init__(self, storage: ObjectStorage, encryption_manager: EncryptionManager):
        self.storage = storage
        self.encryption = encryption_manager
    
    @property
    def root(self) -> Path:
        return self.storage.root
    
    def _should_encrypt(self, bucket_name: str, 
                        server_side_encryption: str | None = None) -> tuple[bool, str, str | None]:
        """Determine if object should be encrypted.
        
        Returns:
            Tuple of (should_encrypt, algorithm, kms_key_id)
        """
        if not self.encryption.enabled:
            return False, "", None
        
        if server_side_encryption:
            if server_side_encryption == "AES256":
                return True, "AES256", None
            elif server_side_encryption.startswith("aws:kms"):
                parts = server_side_encryption.split(":")
                kms_key_id = parts[2] if len(parts) > 2 else None
                return True, "aws:kms", kms_key_id
        
        try:
            encryption_config = self.storage.get_bucket_encryption(bucket_name)
            if encryption_config and encryption_config.get("Rules"):
                rule = encryption_config["Rules"][0]
                # AWS format: Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm
                sse_default = rule.get("ApplyServerSideEncryptionByDefault", {})
                algorithm = sse_default.get("SSEAlgorithm", "AES256")
                kms_key_id = sse_default.get("KMSMasterKeyID")
                return True, algorithm, kms_key_id
        except StorageError:
            pass
        
        return False, "", None
    
    def _is_encrypted(self, metadata: Dict[str, str]) -> bool:
        """Check if object is encrypted based on its metadata."""
        return "x-amz-server-side-encryption" in metadata
    
    def put_object(
        self,
        bucket_name: str,
        object_key: str,
        stream: BinaryIO,
        *,
        metadata: Optional[Dict[str, str]] = None,
        server_side_encryption: Optional[str] = None,
        kms_key_id: Optional[str] = None,
    ) -> ObjectMeta:
        """Store an object, optionally with encryption.

        Args:
            bucket_name: Name of the bucket
            object_key: Key for the object
            stream: Binary stream of object data
            metadata: Optional user metadata
            server_side_encryption: Encryption algorithm ("AES256" or "aws:kms")
            kms_key_id: KMS key ID (for aws:kms encryption)

        Returns:
            ObjectMeta with object information

        Performance: Uses streaming encryption for large files to reduce memory usage.
        """
        should_encrypt, algorithm, detected_kms_key = self._should_encrypt(
            bucket_name, server_side_encryption
        )

        if kms_key_id is None:
            kms_key_id = detected_kms_key

        if should_encrypt:
            try:
                # Performance: Use streaming encryption to avoid loading entire file into memory
                encrypted_stream, enc_metadata = self.encryption.encrypt_stream(
                    stream,
                    algorithm=algorithm,
                    context={"bucket": bucket_name, "key": object_key},
                )

                combined_metadata = metadata.copy() if metadata else {}
                combined_metadata.update(enc_metadata.to_dict())

                result = self.storage.put_object(
                    bucket_name,
                    object_key,
                    encrypted_stream,
                    metadata=combined_metadata,
                )

                result.metadata = combined_metadata
                return result

            except EncryptionError as exc:
                raise StorageError(f"Encryption failed: {exc}") from exc
        else:
            return self.storage.put_object(
                bucket_name,
                object_key,
                stream,
                metadata=metadata,
            )
    
    def get_object_data(self, bucket_name: str, object_key: str) -> tuple[bytes, Dict[str, str]]:
        """Get object data, decrypting if necessary.

        Returns:
            Tuple of (data, metadata)

        Performance: Uses streaming decryption to reduce memory usage.
        """
        path = self.storage.get_object_path(bucket_name, object_key)
        metadata = self.storage.get_object_metadata(bucket_name, object_key)

        enc_metadata = EncryptionMetadata.from_dict(metadata)
        if enc_metadata:
            try:
                # Performance: Use streaming decryption to avoid loading entire file into memory
                with path.open("rb") as f:
                    decrypted_stream = self.encryption.decrypt_stream(f, enc_metadata)
                    data = decrypted_stream.read()
            except EncryptionError as exc:
                raise StorageError(f"Decryption failed: {exc}") from exc
        else:
            with path.open("rb") as f:
                data = f.read()

        clean_metadata = {
            k: v for k, v in metadata.items()
            if not k.startswith("x-amz-encryption")
            and k != "x-amz-encrypted-data-key"
        }

        return data, clean_metadata
    
    def get_object_stream(self, bucket_name: str, object_key: str) -> tuple[BinaryIO, Dict[str, str], int]:
        """Get object as a stream, decrypting if necessary.
        
        Returns:
            Tuple of (stream, metadata, original_size)
        """
        data, metadata = self.get_object_data(bucket_name, object_key)
        return io.BytesIO(data), metadata, len(data)
    
    def list_buckets(self):
        return self.storage.list_buckets()
    
    def bucket_exists(self, bucket_name: str) -> bool:
        return self.storage.bucket_exists(bucket_name)
    
    def create_bucket(self, bucket_name: str) -> None:
        return self.storage.create_bucket(bucket_name)
    
    def delete_bucket(self, bucket_name: str) -> None:
        return self.storage.delete_bucket(bucket_name)
    
    def bucket_stats(self, bucket_name: str, cache_ttl: int = 60):
        return self.storage.bucket_stats(bucket_name, cache_ttl)
    
    def list_objects(self, bucket_name: str, **kwargs):
        return self.storage.list_objects(bucket_name, **kwargs)
    
    def list_objects_all(self, bucket_name: str):
        return self.storage.list_objects_all(bucket_name)
    
    def get_object_path(self, bucket_name: str, object_key: str):
        return self.storage.get_object_path(bucket_name, object_key)
    
    def get_object_metadata(self, bucket_name: str, object_key: str):
        return self.storage.get_object_metadata(bucket_name, object_key)
    
    def delete_object(self, bucket_name: str, object_key: str) -> None:
        return self.storage.delete_object(bucket_name, object_key)
    
    def purge_object(self, bucket_name: str, object_key: str) -> None:
        return self.storage.purge_object(bucket_name, object_key)
    
    def is_versioning_enabled(self, bucket_name: str) -> bool:
        return self.storage.is_versioning_enabled(bucket_name)
    
    def set_bucket_versioning(self, bucket_name: str, enabled: bool) -> None:
        return self.storage.set_bucket_versioning(bucket_name, enabled)
    
    def get_bucket_tags(self, bucket_name: str):
        return self.storage.get_bucket_tags(bucket_name)
    
    def set_bucket_tags(self, bucket_name: str, tags):
        return self.storage.set_bucket_tags(bucket_name, tags)
    
    def get_bucket_cors(self, bucket_name: str):
        return self.storage.get_bucket_cors(bucket_name)
    
    def set_bucket_cors(self, bucket_name: str, rules):
        return self.storage.set_bucket_cors(bucket_name, rules)
    
    def get_bucket_encryption(self, bucket_name: str):
        return self.storage.get_bucket_encryption(bucket_name)
    
    def set_bucket_encryption(self, bucket_name: str, config_payload):
        return self.storage.set_bucket_encryption(bucket_name, config_payload)
    
    def get_bucket_lifecycle(self, bucket_name: str):
        return self.storage.get_bucket_lifecycle(bucket_name)
    
    def set_bucket_lifecycle(self, bucket_name: str, rules):
        return self.storage.set_bucket_lifecycle(bucket_name, rules)
    
    def get_object_tags(self, bucket_name: str, object_key: str):
        return self.storage.get_object_tags(bucket_name, object_key)
    
    def set_object_tags(self, bucket_name: str, object_key: str, tags):
        return self.storage.set_object_tags(bucket_name, object_key, tags)
    
    def delete_object_tags(self, bucket_name: str, object_key: str):
        return self.storage.delete_object_tags(bucket_name, object_key)
    
    def list_object_versions(self, bucket_name: str, object_key: str):
        return self.storage.list_object_versions(bucket_name, object_key)
    
    def restore_object_version(self, bucket_name: str, object_key: str, version_id: str):
        return self.storage.restore_object_version(bucket_name, object_key, version_id)
    
    def list_orphaned_objects(self, bucket_name: str):
        return self.storage.list_orphaned_objects(bucket_name)
    
    def initiate_multipart_upload(self, bucket_name: str, object_key: str, *, metadata=None) -> str:
        return self.storage.initiate_multipart_upload(bucket_name, object_key, metadata=metadata)
    
    def upload_multipart_part(self, bucket_name: str, upload_id: str, part_number: int, stream: BinaryIO) -> str:
        return self.storage.upload_multipart_part(bucket_name, upload_id, part_number, stream)
    
    def complete_multipart_upload(self, bucket_name: str, upload_id: str, ordered_parts):
        return self.storage.complete_multipart_upload(bucket_name, upload_id, ordered_parts)
    
    def abort_multipart_upload(self, bucket_name: str, upload_id: str) -> None:
        return self.storage.abort_multipart_upload(bucket_name, upload_id)
    
    def list_multipart_parts(self, bucket_name: str, upload_id: str):
        return self.storage.list_multipart_parts(bucket_name, upload_id)
    
    def get_bucket_quota(self, bucket_name: str):
        return self.storage.get_bucket_quota(bucket_name)

    def set_bucket_quota(self, bucket_name: str, *, max_bytes=None, max_objects=None):
        return self.storage.set_bucket_quota(bucket_name, max_bytes=max_bytes, max_objects=max_objects)

    def get_bucket_website(self, bucket_name: str):
        return self.storage.get_bucket_website(bucket_name)

    def set_bucket_website(self, bucket_name: str, website_config):
        return self.storage.set_bucket_website(bucket_name, website_config)
    
    def _compute_etag(self, path: Path) -> str:
        return self.storage._compute_etag(path)
