from __future__ import annotations

import base64
import io
import json
import logging
import os
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Generator, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

if sys.platform != "win32":
    import fcntl

try:
    import myfsio_core as _rc
    _HAS_RUST = True
except ImportError:
    _rc = None
    _HAS_RUST = False

logger = logging.getLogger(__name__)


def _set_secure_file_permissions(file_path: Path) -> None:
    """Set restrictive file permissions (owner read/write only)."""
    if sys.platform == "win32":
        try:
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    ["icacls", str(file_path), "/inheritance:r",
                     "/grant:r", f"{username}:F"],
                    check=True, capture_output=True
                )
            else:
                logger.warning("Could not set secure permissions on %s: USERNAME not set", file_path)
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("Failed to set secure permissions on %s: %s", file_path, exc)
    else:
        os.chmod(file_path, 0o600)


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

    def decrypt_data_key(self, encrypted_data_key: bytes, key_id: str | None = None) -> bytes:
        """Decrypt an encrypted data key.

        Args:
            encrypted_data_key: The encrypted data key bytes
            key_id: Optional key identifier (used by KMS providers)

        Returns:
            The decrypted data key
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
        """Load master key from file or generate a new one (with file locking)."""
        lock_path = self.master_key_path.with_suffix(".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(lock_path, "w") as lock_file:
                if sys.platform == "win32":
                    import msvcrt
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    if self.master_key_path.exists():
                        try:
                            return base64.b64decode(self.master_key_path.read_text().strip())
                        except Exception as exc:
                            raise EncryptionError(f"Failed to load master key: {exc}") from exc
                    key = secrets.token_bytes(32)
                    try:
                        self.master_key_path.write_text(base64.b64encode(key).decode())
                        _set_secure_file_permissions(self.master_key_path)
                    except OSError as exc:
                        raise EncryptionError(f"Failed to save master key: {exc}") from exc
                    return key
                finally:
                    if sys.platform == "win32":
                        import msvcrt
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise EncryptionError(f"Failed to acquire lock for master key: {exc}") from exc
    
    DATA_KEY_AAD = b'{"purpose":"data_key","version":1}'

    def _encrypt_data_key(self, data_key: bytes) -> bytes:
        """Encrypt the data key with the master key."""
        aesgcm = AESGCM(self.master_key)
        nonce = secrets.token_bytes(12)
        encrypted = aesgcm.encrypt(nonce, data_key, self.DATA_KEY_AAD)
        return nonce + encrypted

    def _decrypt_data_key(self, encrypted_data_key: bytes) -> bytes:
        """Decrypt the data key using the master key."""
        if len(encrypted_data_key) < 12 + 32 + 16:  # nonce + key + tag
            raise EncryptionError("Invalid encrypted data key")
        aesgcm = AESGCM(self.master_key)
        nonce = encrypted_data_key[:12]
        ciphertext = encrypted_data_key[12:]
        try:
            return aesgcm.decrypt(nonce, ciphertext, self.DATA_KEY_AAD)
        except Exception:
            try:
                return aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as exc:
                raise EncryptionError(f"Failed to decrypt data key: {exc}") from exc

    def decrypt_data_key(self, encrypted_data_key: bytes, key_id: str | None = None) -> bytes:
        """Decrypt an encrypted data key (key_id ignored for local encryption)."""
        return self._decrypt_data_key(encrypted_data_key)

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
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            key_id=self.KEY_ID,
            encrypted_data_key=encrypted_data_key,
        )
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, encrypted_data_key: bytes,
                key_id: str, context: Dict[str, str] | None = None) -> bytes:
        """Decrypt data using envelope encryption."""
        data_key = self._decrypt_data_key(encrypted_data_key)
        aesgcm = AESGCM(data_key)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise EncryptionError("Failed to decrypt data") from exc


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
        """Derive a unique nonce for each chunk using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=base_nonce,
            info=chunk_index.to_bytes(4, "big"),
        )
        return hkdf.derive(b"chunk_nonce")

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
        data_key = self.provider.decrypt_data_key(metadata.encrypted_data_key, metadata.key_id)

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

    def encrypt_file(self, input_path: str, output_path: str) -> EncryptionMetadata:
        data_key, encrypted_data_key = self.provider.generate_data_key()
        base_nonce = secrets.token_bytes(12)

        if _HAS_RUST:
            _rc.encrypt_stream_chunked(
                input_path, output_path, data_key, base_nonce, self.chunk_size
            )
        else:
            with open(input_path, "rb") as stream:
                aesgcm = AESGCM(data_key)
                with open(output_path, "wb") as out:
                    out.write(b"\x00\x00\x00\x00")
                    chunk_index = 0
                    while True:
                        chunk = stream.read(self.chunk_size)
                        if not chunk:
                            break
                        chunk_nonce = self._derive_chunk_nonce(base_nonce, chunk_index)
                        encrypted_chunk = aesgcm.encrypt(chunk_nonce, chunk, None)
                        out.write(len(encrypted_chunk).to_bytes(self.HEADER_SIZE, "big"))
                        out.write(encrypted_chunk)
                        chunk_index += 1
                    out.seek(0)
                    out.write(chunk_index.to_bytes(4, "big"))

        return EncryptionMetadata(
            algorithm="AES256",
            key_id=self.provider.KEY_ID if hasattr(self.provider, "KEY_ID") else "local",
            nonce=base_nonce,
            encrypted_data_key=encrypted_data_key,
        )

    def decrypt_file(self, input_path: str, output_path: str,
                     metadata: EncryptionMetadata) -> None:
        data_key = self.provider.decrypt_data_key(metadata.encrypted_data_key, metadata.key_id)
        base_nonce = metadata.nonce

        if _HAS_RUST:
            _rc.decrypt_stream_chunked(input_path, output_path, data_key, base_nonce)
        else:
            with open(input_path, "rb") as stream:
                chunk_count_bytes = stream.read(4)
                if len(chunk_count_bytes) < 4:
                    raise EncryptionError("Invalid encrypted stream: missing header")
                chunk_count = int.from_bytes(chunk_count_bytes, "big")
                aesgcm = AESGCM(data_key)
                with open(output_path, "wb") as out:
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
                            out.write(decrypted_chunk)
                        except Exception as exc:
                            raise EncryptionError(f"Failed to decrypt chunk {chunk_index}: {exc}") from exc


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
            chunk_size = self.config.get("encryption_chunk_size_bytes", 64 * 1024)
            self._streaming_encryptor = StreamingEncryptor(self.get_local_provider(), chunk_size=chunk_size)
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


class SSECEncryption(EncryptionProvider):
    """SSE-C: Server-Side Encryption with Customer-Provided Keys.

    The client provides the encryption key with each request.
    Server encrypts/decrypts but never stores the key.

    Required headers for PUT:
    - x-amz-server-side-encryption-customer-algorithm: AES256
    - x-amz-server-side-encryption-customer-key: Base64-encoded 256-bit key
    - x-amz-server-side-encryption-customer-key-MD5: Base64-encoded MD5 of key
    """

    KEY_ID = "customer-provided"

    def __init__(self, customer_key: bytes):
        if len(customer_key) != 32:
            raise EncryptionError("Customer key must be exactly 256 bits (32 bytes)")
        self.customer_key = customer_key

    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> "SSECEncryption":
        algorithm = headers.get("x-amz-server-side-encryption-customer-algorithm", "")
        if algorithm.upper() != "AES256":
            raise EncryptionError(f"Unsupported SSE-C algorithm: {algorithm}. Only AES256 is supported.")

        key_b64 = headers.get("x-amz-server-side-encryption-customer-key", "")
        if not key_b64:
            raise EncryptionError("Missing x-amz-server-side-encryption-customer-key header")

        key_md5_b64 = headers.get("x-amz-server-side-encryption-customer-key-md5", "")

        try:
            customer_key = base64.b64decode(key_b64)
        except Exception as e:
            raise EncryptionError(f"Invalid base64 in customer key: {e}") from e

        if len(customer_key) != 32:
            raise EncryptionError(f"Customer key must be 256 bits, got {len(customer_key) * 8} bits")

        if key_md5_b64:
            import hashlib
            expected_md5 = base64.b64encode(hashlib.md5(customer_key).digest()).decode()
            if key_md5_b64 != expected_md5:
                raise EncryptionError("Customer key MD5 mismatch")

        return cls(customer_key)

    def encrypt(self, plaintext: bytes, context: Dict[str, str] | None = None) -> EncryptionResult:
        aesgcm = AESGCM(self.customer_key)
        nonce = secrets.token_bytes(12)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            key_id=self.KEY_ID,
            encrypted_data_key=b"",
        )

    def decrypt(self, ciphertext: bytes, nonce: bytes, encrypted_data_key: bytes,
                key_id: str, context: Dict[str, str] | None = None) -> bytes:
        aesgcm = AESGCM(self.customer_key)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise EncryptionError("SSE-C decryption failed") from exc

    def generate_data_key(self) -> tuple[bytes, bytes]:
        return self.customer_key, b""


@dataclass
class SSECMetadata:
    algorithm: str = "AES256"
    nonce: bytes = b""
    key_md5: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "x-amz-server-side-encryption-customer-algorithm": self.algorithm,
            "x-amz-encryption-nonce": base64.b64encode(self.nonce).decode(),
            "x-amz-server-side-encryption-customer-key-MD5": self.key_md5,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> Optional["SSECMetadata"]:
        algorithm = data.get("x-amz-server-side-encryption-customer-algorithm")
        if not algorithm:
            return None
        try:
            nonce = base64.b64decode(data.get("x-amz-encryption-nonce", ""))
            return cls(
                algorithm=algorithm,
                nonce=nonce,
                key_md5=data.get("x-amz-server-side-encryption-customer-key-MD5", ""),
            )
        except Exception:
            return None


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
    def encrypt_with_key(plaintext: bytes, key_b64: str, context: Dict[str, str] | None = None) -> Dict[str, str]:
        """Encrypt data with a client-provided key."""
        key = base64.b64decode(key_b64)
        if len(key) != 32:
            raise EncryptionError("Key must be 256 bits (32 bytes)")

        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "algorithm": "AES-256-GCM",
        }

    @staticmethod
    def decrypt_with_key(ciphertext_b64: str, nonce_b64: str, key_b64: str, context: Dict[str, str] | None = None) -> bytes:
        """Decrypt data with a client-provided key."""
        key = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        if len(key) != 32:
            raise EncryptionError("Key must be 256 bits (32 bytes)")

        aesgcm = AESGCM(key)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise EncryptionError("Decryption failed") from exc
