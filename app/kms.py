from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .encryption import EncryptionError, EncryptionProvider, EncryptionResult

logger = logging.getLogger(__name__)


@dataclass
class KMSKey:
    """Represents a KMS encryption key."""
    key_id: str
    description: str
    created_at: str
    enabled: bool = True
    key_material: bytes = field(default_factory=lambda: b"", repr=False)
    
    @property
    def arn(self) -> str:
        return f"arn:aws:kms:local:000000000000:key/{self.key_id}"
    
    def to_dict(self, include_key: bool = False) -> Dict[str, Any]:
        data = {
            "KeyId": self.key_id,
            "Arn": self.arn,
            "Description": self.description,
            "CreationDate": self.created_at,
            "Enabled": self.enabled,
            "KeyState": "Enabled" if self.enabled else "Disabled",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "KeySpec": "SYMMETRIC_DEFAULT",
        }
        if include_key:
            data["KeyMaterial"] = base64.b64encode(self.key_material).decode()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KMSKey":
        key_material = b""
        if "KeyMaterial" in data:
            key_material = base64.b64decode(data["KeyMaterial"])
        return cls(
            key_id=data["KeyId"],
            description=data.get("Description", ""),
            created_at=data.get("CreationDate", datetime.now(timezone.utc).isoformat()),
            enabled=data.get("Enabled", True),
            key_material=key_material,
        )


class KMSEncryptionProvider(EncryptionProvider):
    """Encryption provider using a specific KMS key."""
    
    def __init__(self, kms: "KMSManager", key_id: str):
        self.kms = kms
        self.key_id = key_id
    
    @property
    def KEY_ID(self) -> str:
        return self.key_id
    
    def generate_data_key(self) -> tuple[bytes, bytes]:
        """Generate a data key encrypted with the KMS key."""
        return self.kms.generate_data_key(self.key_id)
    
    def encrypt(self, plaintext: bytes, context: Dict[str, str] | None = None) -> EncryptionResult:
        """Encrypt data using envelope encryption with KMS."""
        data_key, encrypted_data_key = self.generate_data_key()

        aesgcm = AESGCM(data_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext,
                                     json.dumps(context, sort_keys=True).encode() if context else None)
        
        return EncryptionResult(
            ciphertext=ciphertext,
            nonce=nonce,
            key_id=self.key_id,
            encrypted_data_key=encrypted_data_key,
        )
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, encrypted_data_key: bytes,
                key_id: str, context: Dict[str, str] | None = None) -> bytes:
        """Decrypt data using envelope encryption with KMS."""
        data_key = self.kms.decrypt_data_key(key_id, encrypted_data_key, context=None)
        if len(data_key) != 32:
            raise EncryptionError("Invalid data key size")

        aesgcm = AESGCM(data_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext,
                                  json.dumps(context, sort_keys=True).encode() if context else None)
        except Exception as exc:
            logger.debug("KMS decryption failed: %s", exc)
            raise EncryptionError("Failed to decrypt data") from exc


class KMSManager:
    """Manages KMS keys and operations.
    
    This is a local implementation that mimics AWS KMS functionality.
    Keys are stored encrypted on disk.
    """
    
    def __init__(
        self,
        keys_path: Path,
        master_key_path: Path,
        generate_data_key_min_bytes: int = 1,
        generate_data_key_max_bytes: int = 1024,
    ):
        self.keys_path = keys_path
        self.master_key_path = master_key_path
        self.generate_data_key_min_bytes = generate_data_key_min_bytes
        self.generate_data_key_max_bytes = generate_data_key_max_bytes
        self._keys: Dict[str, KMSKey] = {}
        self._master_key: bytes | None = None
        self._loaded = False
    
    @property
    def master_key(self) -> bytes:
        """Load or create the master key for encrypting KMS keys."""
        if self._master_key is None:
            if self.master_key_path.exists():
                self._master_key = base64.b64decode(
                    self.master_key_path.read_text().strip()
                )
            else:
                self._master_key = secrets.token_bytes(32)
                self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
                self.master_key_path.write_text(
                    base64.b64encode(self._master_key).decode()
                )
                if sys.platform != "win32":
                    os.chmod(self.master_key_path, 0o600)
        return self._master_key
    
    def _load_keys(self) -> None:
        """Load keys from disk."""
        if self._loaded:
            return
        
        if self.keys_path.exists():
            try:
                data = json.loads(self.keys_path.read_text(encoding="utf-8"))
                for key_data in data.get("keys", []):
                    key = KMSKey.from_dict(key_data)
                    if key_data.get("EncryptedKeyMaterial"):
                        encrypted = base64.b64decode(key_data["EncryptedKeyMaterial"])
                        key.key_material = self._decrypt_key_material(encrypted)
                    self._keys[key.key_id] = key
            except json.JSONDecodeError as exc:
                logger.error("Failed to parse KMS keys file: %s", exc)
            except (ValueError, KeyError) as exc:
                logger.error("Invalid KMS key data: %s", exc)
        
        self._loaded = True
    
    def _save_keys(self) -> None:
        """Save keys to disk (with encrypted key material)."""
        keys_data = []
        for key in self._keys.values():
            data = key.to_dict(include_key=False)
            encrypted = self._encrypt_key_material(key.key_material)
            data["EncryptedKeyMaterial"] = base64.b64encode(encrypted).decode()
            keys_data.append(data)
        
        self.keys_path.parent.mkdir(parents=True, exist_ok=True)
        self.keys_path.write_text(
            json.dumps({"keys": keys_data}, indent=2),
            encoding="utf-8"
        )
    
    def _encrypt_key_material(self, key_material: bytes) -> bytes:
        """Encrypt key material with the master key."""
        aesgcm = AESGCM(self.master_key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, key_material, None)
        return nonce + ciphertext
    
    def _decrypt_key_material(self, encrypted: bytes) -> bytes:
        """Decrypt key material with the master key."""
        aesgcm = AESGCM(self.master_key)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def create_key(self, description: str = "", key_id: str | None = None) -> KMSKey:
        """Create a new KMS key."""
        self._load_keys()
        
        if key_id is None:
            key_id = str(uuid.uuid4())
        
        if key_id in self._keys:
            raise EncryptionError(f"Key already exists: {key_id}")
        
        key = KMSKey(
            key_id=key_id,
            description=description,
            created_at=datetime.now(timezone.utc).isoformat(),
            enabled=True,
            key_material=secrets.token_bytes(32),
        )
        
        self._keys[key_id] = key
        self._save_keys()
        return key
    
    def get_key(self, key_id: str) -> KMSKey | None:
        """Get a key by ID."""
        self._load_keys()
        return self._keys.get(key_id)
    
    def list_keys(self) -> List[KMSKey]:
        """List all keys."""
        self._load_keys()
        return list(self._keys.values())

    def get_default_key_id(self) -> str:
        """Get the default KMS key ID, creating one if none exist."""
        self._load_keys()
        for key in self._keys.values():
            if key.enabled:
                return key.key_id
        default_key = self.create_key(description="Default KMS Key")
        return default_key.key_id

    def get_provider(self, key_id: str | None = None) -> "KMSEncryptionProvider":
        """Get a KMS encryption provider for the specified key."""
        if key_id is None:
            key_id = self.get_default_key_id()
        key = self.get_key(key_id)
        if not key:
            raise EncryptionError(f"Key not found: {key_id}")
        if not key.enabled:
            raise EncryptionError(f"Key is disabled: {key_id}")
        return KMSEncryptionProvider(self, key_id)

    def enable_key(self, key_id: str) -> None:
        """Enable a key."""
        self._load_keys()
        key = self._keys.get(key_id)
        if not key:
            raise EncryptionError(f"Key not found: {key_id}")
        key.enabled = True
        self._save_keys()
    
    def disable_key(self, key_id: str) -> None:
        """Disable a key."""
        self._load_keys()
        key = self._keys.get(key_id)
        if not key:
            raise EncryptionError(f"Key not found: {key_id}")
        key.enabled = False
        self._save_keys()
    
    def delete_key(self, key_id: str) -> None:
        """Delete a key (schedule for deletion in real KMS)."""
        self._load_keys()
        if key_id not in self._keys:
            raise EncryptionError(f"Key not found: {key_id}")
        del self._keys[key_id]
        self._save_keys()
    
    def encrypt(self, key_id: str, plaintext: bytes,
                context: Dict[str, str] | None = None) -> bytes:
        """Encrypt data directly with a KMS key."""
        self._load_keys()
        key = self._keys.get(key_id)
        if not key:
            raise EncryptionError(f"Key not found: {key_id}")
        if not key.enabled:
            raise EncryptionError(f"Key is disabled: {key_id}")
        
        aesgcm = AESGCM(key.key_material)
        nonce = secrets.token_bytes(12)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        
        key_id_bytes = key_id.encode("utf-8")
        return len(key_id_bytes).to_bytes(2, "big") + key_id_bytes + nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes,
                context: Dict[str, str] | None = None) -> tuple[bytes, str]:
        """Decrypt data directly with a KMS key.
        
        Returns:
            Tuple of (plaintext, key_id)
        """
        self._load_keys()
        
        key_id_len = int.from_bytes(ciphertext[:2], "big")
        key_id = ciphertext[2:2 + key_id_len].decode("utf-8")
        rest = ciphertext[2 + key_id_len:]
        
        key = self._keys.get(key_id)
        if not key:
            raise EncryptionError(f"Key not found: {key_id}")
        if not key.enabled:
            raise EncryptionError(f"Key is disabled: {key_id}")
        
        nonce = rest[:12]
        encrypted = rest[12:]
        
        aesgcm = AESGCM(key.key_material)
        aad = json.dumps(context, sort_keys=True).encode() if context else None
        try:
            plaintext = aesgcm.decrypt(nonce, encrypted, aad)
            return plaintext, key_id
        except Exception as exc:
            logger.debug("KMS decrypt operation failed: %s", exc)
            raise EncryptionError("Decryption failed") from exc
    
    def generate_data_key(self, key_id: str,
                          context: Dict[str, str] | None = None,
                          key_spec: str = "AES_256") -> tuple[bytes, bytes]:
        """Generate a data key and return both plaintext and encrypted versions.

        Args:
            key_id: The KMS key ID to use for encryption
            context: Optional encryption context
            key_spec: Key specification - AES_128 or AES_256 (default)

        Returns:
            Tuple of (plaintext_key, encrypted_key)
        """
        self._load_keys()
        key = self._keys.get(key_id)
        if not key:
            raise EncryptionError(f"Key not found: {key_id}")
        if not key.enabled:
            raise EncryptionError(f"Key is disabled: {key_id}")

        key_bytes = 32 if key_spec == "AES_256" else 16
        plaintext_key = secrets.token_bytes(key_bytes)

        encrypted_key = self.encrypt(key_id, plaintext_key, context)

        return plaintext_key, encrypted_key
    
    def decrypt_data_key(self, key_id: str, encrypted_key: bytes,
                         context: Dict[str, str] | None = None) -> bytes:
        """Decrypt a data key."""
        plaintext, _ = self.decrypt(encrypted_key, context)
        return plaintext
    
    def get_provider(self, key_id: str | None = None) -> KMSEncryptionProvider:
        """Get an encryption provider for a specific key."""
        self._load_keys()
        
        if key_id is None:
            if not self._keys:
                key = self.create_key("Default KMS Key")
                key_id = key.key_id
            else:
                key_id = next(iter(self._keys.keys()))
        
        if key_id not in self._keys:
            raise EncryptionError(f"Key not found: {key_id}")
        
        return KMSEncryptionProvider(self, key_id)
    
    def re_encrypt(self, ciphertext: bytes, destination_key_id: str,
                   source_context: Dict[str, str] | None = None,
                   destination_context: Dict[str, str] | None = None) -> bytes:
        """Re-encrypt data with a different key."""

        plaintext, source_key_id = self.decrypt(ciphertext, source_context)
        
        return self.encrypt(destination_key_id, plaintext, destination_context)
    
    def generate_random(self, num_bytes: int = 32) -> bytes:
        """Generate cryptographically secure random bytes."""
        if num_bytes < self.generate_data_key_min_bytes or num_bytes > self.generate_data_key_max_bytes:
            raise EncryptionError(
                f"Number of bytes must be between {self.generate_data_key_min_bytes} and {self.generate_data_key_max_bytes}"
            )
        return secrets.token_bytes(num_bytes)
