"""Encryption providers for server-side and client-side encryption."""
from __future__ import annotations

import base64
import io
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Generator, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""


@dataclass
class EncryptionResult:
    """Result of encrypting data."""
    ciphertext: bytes
    nonce: bytes
    key_id: str
    encrypted_data_key: bytes


@dataclass
class EncryptionMetadata:
    """Metadata stored with encrypted objects."""
    algorithm: str
    key_id: str
    nonce: bytes
    encrypted_data_key: bytes
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "x-amz-server-side-encryption": self.algorithm,
            "x-amz-encryption-key-id": self.key_id,
            "x-amz-encryption-nonce": base64.b64encode(self.nonce).decode(),
            "x-amz-encrypted-data-key": base64.b64encode(self.encrypted_data_key).decode(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> Optional["EncryptionMetadata"]:
        algorithm = data.get("x-amz-server-side-encryption")
        if not algorithm:
            return None
        try:
            return cls(
                algorithm=algorithm,
                key_id=data.get("x-amz-encryption-key-id", "local"),
                nonce=base64.b64decode(data.get("x-amz-encryption-nonce", "")),
                encrypted_data_key=base64.b64decode(data.get("x-amz-encrypted-data-key", "")),
            )
        except Exception:
            return None


class EncryptionProvider:
    """Base class for encryption providers."""
    
    def encrypt(self, plaintext: bytes, context: Dict[str, str] | None = None) -> EncryptionResult:
        raise NotImplementedError
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, encrypted_data_key: bytes,
                key_id: str, context: Dict[str, str] | None = None) -> bytes:
        raise NotImplementedError
    
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Generate a data key and its encrypted form.
        
        Returns:
            Tuple of (plaintext_key, encrypted_key)
        """
        raise NotImplementedError


class LocalKeyEncryption(EncryptionProvider):
    """SSE-S3 style encryption using a local master key.
    
    Uses envelope encryption:
    1. Generate a unique data key for each object
    2. Encrypt the data with the data key (AES-256-GCM)
    3. Encrypt the data key with the master key
    4. Store the encrypted data key alongside the ciphertext
    """
    
    KEY_ID = "local"
    
    def __init__(self, master_key_path: Path):
        self.master_key_path = master_key_path
        self._master_key: bytes | None = None
    
    @property
    def master_key(self) -> bytes:
        if self._master_key is None:
            self._master_key = self._load_or_create_master_key()
        return self._master_key
    
    def _load_or_create_master_key(self) -> bytes:
        """Load master key from file or generate a new one."""
        if self.master_key_path.exists():
            try:
                return base64.b64decode(self.master_key_path.read_text().strip())
            except Exception as exc:
                raise EncryptionError(f"Failed to load master key: {exc}") from exc
        
        key = secrets.token_bytes(32)
        try:
            self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
            self.master_key_path.write_text(base64.b64encode(key).decode())
        except OSError as exc:
            raise EncryptionError(f"Failed to save master key: {exc}") from exc
        return key
    
    def _encrypt_data_key(self, data_key: bytes) -> bytes:
        """Encrypt the data key with the master key."""
        aesgcm = AESGCM(self.master_key)
        nonce = secrets.token_bytes(12)
        encrypted = aesgcm.encrypt(nonce, data_key, None)
        return nonce + encrypted
    
    def _decrypt_data_key(self, encrypted_data_key: bytes) -> bytes:
        """Decrypt the data key using the master key."""
        if len(encrypted_data_key) < 12 + 32 + 16:  # nonce + key + tag
            raise EncryptionError("Invalid encrypted data key")
        aesgcm = AESGCM(self.master_key)
        nonce = encrypted_data_key[:12]
        ciphertext = encrypted_data_key[12:]
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise EncryptionError(f"Failed to decrypt data key: {exc}") from exc
    
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Generate a data key and its encrypted form."""
        plaintext_key = secrets.token_bytes(32)
        encrypted_key = self._encrypt_data_key(plaintext_key)
        return plaintext_key, encrypted_key
    
    def encrypt(self, plaintext: bytes, context: Dict[str, str] | None = None) -> EncryptionResult:
        """Encrypt data using envelope encryption."""
        data_key, encrypted_data_key = self.generate_data_key()
        
        aesgcm = AESGCM(data_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            key_id=self.KEY_ID,
            encrypted_data_key=encrypted_data_key,
        )
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, encrypted_data_key: bytes,
                key_id: str, context: Dict[str, str] | None = None) -> bytes:
        """Decrypt data using envelope encryption."""
        # Decrypt the data key
        data_key = self._decrypt_data_key(encrypted_data_key)
        
        # Decrypt the data
        aesgcm = AESGCM(data_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise EncryptionError(f"Failed to decrypt data: {exc}") from exc


class StreamingEncryptor:
    """Encrypts/decrypts data in streaming fashion for large files.
    
    For large files, we encrypt in chunks. Each chunk is encrypted with the
    same data key but a unique nonce derived from the base nonce + chunk index.
    """
    
    CHUNK_SIZE = 64 * 1024  
    HEADER_SIZE = 4  
    
    def __init__(self, provider: EncryptionProvider, chunk_size: int = CHUNK_SIZE):
        self.provider = provider
        self.chunk_size = chunk_size
    
    def _derive_chunk_nonce(self, base_nonce: bytes, chunk_index: int) -> bytes:
        """Derive a unique nonce for each chunk.

        Performance: Use direct byte manipulation instead of full int conversion.
        """
        # Performance: Only modify last 4 bytes instead of full 12-byte conversion
        return base_nonce[:8] + (chunk_index ^ int.from_bytes(base_nonce[8:], "big")).to_bytes(4, "big")

    def encrypt_stream(self, stream: BinaryIO,
                       context: Dict[str, str] | None = None) -> tuple[BinaryIO, EncryptionMetadata]:
        """Encrypt a stream and return encrypted stream + metadata.

        Performance: Writes chunks directly to output buffer instead of accumulating in list.
        """
        data_key, encrypted_data_key = self.provider.generate_data_key()
        base_nonce = secrets.token_bytes(12)

        aesgcm = AESGCM(data_key)
        # Performance: Write directly to BytesIO instead of accumulating chunks
        output = io.BytesIO()
        output.write(b"\x00\x00\x00\x00")  # Placeholder for chunk count
        chunk_index = 0

        while True:
            chunk = stream.read(self.chunk_size)
            if not chunk:
                break

            chunk_nonce = self._derive_chunk_nonce(base_nonce, chunk_index)
            encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)

            # Write size prefix + encrypted chunk directly
            output.write(len(encrypted_chunk).to_bytes(self.HEADER_SIZE, "big"))
            output.write(encrypted_chunk)
            chunk_index += 1

        # Write actual chunk count to header
        output.seek(0)
        output.write(chunk_index.to_bytes(4, "big"))
        output.seek(0)

        metadata = EncryptionMetadata(
            algorithm="AES256",
            key_id=self.provider.KEY_ID if hasattr(self.provider, "KEY_ID") else "local",
            nonce=base_nonce,
            encrypted_data_key=encrypted_data_key,
        )

        return output, metadata

    def decrypt_stream(self, stream: BinaryIO, metadata: EncryptionMetadata) -> BinaryIO:
        """Decrypt a stream using the provided metadata.

        Performance: Writes chunks directly to output buffer instead of accumulating in list.
        """
        if isinstance(self.provider, LocalKeyEncryption):
            data_key = self.provider._decrypt_data_key(metadata.encrypted_data_key)
        else:
            raise EncryptionError("Unsupported provider for streaming decryption")

        aesgcm = AESGCM(data_key)
        base_nonce = metadata.nonce

        chunk_count_bytes = stream.read(4)
        if len(chunk_count_bytes) < 4:
            raise EncryptionError("Invalid encrypted stream: missing header")
        chunk_count = int.from_bytes(chunk_count_bytes, "big")

        # Performance: Write directly to BytesIO instead of accumulating chunks
        output = io.BytesIO()
        for chunk_index in range(chunk_count):
            size_bytes = stream.read(self.HEADER_SIZE)
            if len(size_bytes) < self.HEADER_SIZE:
                raise EncryptionError(f"Invalid encrypted stream: truncated at chunk {chunk_index}")
            chunk_size = int.from_bytes(size_bytes, "big")

            encrypted_chunk = stream.read(chunk_size)
            if len(encrypted_chunk) < chunk_size:
                raise EncryptionError(f"Invalid encrypted stream: incomplete chunk {chunk_index}")

            chunk_nonce = self._derive_chunk_nonce(base_nonce, chunk_index)
            try:
                decrypted_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, None)
                output.write(decrypted_chunk)  # Write directly instead of appending to list
            except Exception as exc:
                raise EncryptionError(f"Failed to decrypt chunk {chunk_index}: {exc}") from exc

        output.seek(0)
        return output


class EncryptionManager:
    """Manages encryption providers and operations."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._local_provider: LocalKeyEncryption | None = None
        self._kms_provider: Any = None  # Set by KMS module
        self._streaming_encryptor: StreamingEncryptor | None = None
    
    @property
    def enabled(self) -> bool:
        return self.config.get("encryption_enabled", False)
    
    @property
    def default_algorithm(self) -> str:
        return self.config.get("default_encryption_algorithm", "AES256")
    
    def get_local_provider(self) -> LocalKeyEncryption:
        if self._local_provider is None:
            key_path = Path(self.config.get("encryption_master_key_path", "data/.myfsio.sys/keys/master.key"))
            self._local_provider = LocalKeyEncryption(key_path)
        return self._local_provider
    
    def set_kms_provider(self, kms_provider: Any) -> None:
        """Set the KMS provider (injected from kms module)."""
        self._kms_provider = kms_provider
    
    def get_provider(self, algorithm: str, kms_key_id: str | None = None) -> EncryptionProvider:
        """Get the appropriate encryption provider for the algorithm."""
        if algorithm == "AES256":
            return self.get_local_provider()
        elif algorithm == "aws:kms":
            if self._kms_provider is None:
                raise EncryptionError("KMS is not configured")
            return self._kms_provider.get_provider(kms_key_id)
        else:
            raise EncryptionError(f"Unsupported encryption algorithm: {algorithm}")
    
    def get_streaming_encryptor(self) -> StreamingEncryptor:
        if self._streaming_encryptor is None:
            self._streaming_encryptor = StreamingEncryptor(self.get_local_provider())
        return self._streaming_encryptor
    
    def encrypt_object(self, data: bytes, algorithm: str = "AES256",
                       kms_key_id: str | None = None,
                       context: Dict[str, str] | None = None) -> tuple[bytes, EncryptionMetadata]:
        """Encrypt object data."""
        provider = self.get_provider(algorithm, kms_key_id)
        result = provider.encrypt(data, context)
        
        metadata = EncryptionMetadata(
            algorithm=algorithm,
            key_id=result.key_id,
            nonce=result.nonce,
            encrypted_data_key=result.encrypted_data_key,
        )
        
        return result.ciphertext, metadata
    
    def decrypt_object(self, ciphertext: bytes, metadata: EncryptionMetadata,
                       context: Dict[str, str] | None = None) -> bytes:
        """Decrypt object data."""
        provider = self.get_provider(metadata.algorithm, metadata.key_id)
        return provider.decrypt(
            ciphertext,
            metadata.nonce,
            metadata.encrypted_data_key,
            metadata.key_id,
            context,
        )
    
    def encrypt_stream(self, stream: BinaryIO, algorithm: str = "AES256",
                       context: Dict[str, str] | None = None) -> tuple[BinaryIO, EncryptionMetadata]:
        """Encrypt a stream for large files."""
        encryptor = self.get_streaming_encryptor()
        return encryptor.encrypt_stream(stream, context)
    
    def decrypt_stream(self, stream: BinaryIO, metadata: EncryptionMetadata) -> BinaryIO:
        """Decrypt a stream."""
        encryptor = self.get_streaming_encryptor()
        return encryptor.decrypt_stream(stream, metadata)


class ClientEncryptionHelper:
    """Helpers for client-side encryption.
    
    Client-side encryption is performed by the client, but this helper
    provides key generation and materials for clients that need them.
    """
    
    @staticmethod
    def generate_client_key() -> Dict[str, str]:
        """Generate a new client encryption key."""
        from datetime import datetime, timezone
        key = secrets.token_bytes(32)
        return {
            "key": base64.b64encode(key).decode(),
            "algorithm": "AES-256-GCM",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    
    @staticmethod
    def encrypt_with_key(plaintext: bytes, key_b64: str) -> Dict[str, str]:
        """Encrypt data with a client-provided key."""
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise EncryptionError("Key must be 256 bits (32 bytes)")
        
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": "AES-256-GCM",
        }
    
    @staticmethod
    def decrypt_with_key(ciphertext_b64: str, nonce_b64: str, key_b64: str) -> bytes:
        """Decrypt data with a client-provided key."""
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        
        if len(key) != 32:
            raise EncryptionError("Key must be 256 bits (32 bytes)")
        
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise EncryptionError(f"Decryption failed: {exc}") from exc
