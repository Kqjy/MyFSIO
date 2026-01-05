"""Tests for encryption functionality."""
from __future__ import annotations

import base64
import io
import json
import os
import secrets
import tempfile
from pathlib import Path

import pytest


class TestLocalKeyEncryption:
    """Tests for LocalKeyEncryption provider."""
    
    def test_create_master_key(self, tmp_path):
        """Test that master key is created if it doesn't exist."""
        from app.encryption import LocalKeyEncryption
        
        key_path = tmp_path / "keys" / "master.key"
        provider = LocalKeyEncryption(key_path)

        key = provider.master_key

        assert key_path.exists()
        assert len(key) == 32
    
    def test_load_existing_master_key(self, tmp_path):
        """Test loading an existing master key."""
        from app.encryption import LocalKeyEncryption
        
        key_path = tmp_path / "master.key"
        original_key = secrets.token_bytes(32)
        key_path.write_text(base64.b64encode(original_key).decode())
        
        provider = LocalKeyEncryption(key_path)
        loaded_key = provider.master_key
        
        assert loaded_key == original_key
    
    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        """Test that data can be encrypted and decrypted correctly."""
        from app.encryption import LocalKeyEncryption
        
        key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(key_path)
        
        plaintext = b"Hello, World! This is a test message."

        result = provider.encrypt(plaintext)

        assert result.ciphertext != plaintext
        assert result.key_id == "local"
        assert len(result.nonce) == 12
        assert len(result.encrypted_data_key) > 0

        decrypted = provider.decrypt(
            result.ciphertext,
            result.nonce,
            result.encrypted_data_key,
            result.key_id,
        )
        
        assert decrypted == plaintext
    
    def test_different_data_keys_per_encryption(self, tmp_path):
        """Test that each encryption uses a different data key."""
        from app.encryption import LocalKeyEncryption
        
        key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(key_path)
        
        plaintext = b"Same message"
        
        result1 = provider.encrypt(plaintext)
        result2 = provider.encrypt(plaintext)

        assert result1.encrypted_data_key != result2.encrypted_data_key
        assert result1.nonce != result2.nonce
        assert result1.ciphertext != result2.ciphertext
    
    def test_generate_data_key(self, tmp_path):
        """Test data key generation."""
        from app.encryption import LocalKeyEncryption
        
        key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(key_path)
        
        plaintext_key, encrypted_key = provider.generate_data_key()

        assert len(plaintext_key) == 32
        assert len(encrypted_key) > 32

        decrypted_key = provider._decrypt_data_key(encrypted_key)
        assert decrypted_key == plaintext_key
    
    def test_decrypt_with_wrong_key_fails(self, tmp_path):
        """Test that decryption fails with wrong master key."""
        from app.encryption import LocalKeyEncryption, EncryptionError

        key_path1 = tmp_path / "master1.key"
        key_path2 = tmp_path / "master2.key"

        provider1 = LocalKeyEncryption(key_path1)
        provider2 = LocalKeyEncryption(key_path2)

        plaintext = b"Secret message"
        result = provider1.encrypt(plaintext)

        with pytest.raises(EncryptionError):
            provider2.decrypt(
                result.ciphertext,
                result.nonce,
                result.encrypted_data_key,
                result.key_id,
            )


class TestEncryptionMetadata:
    """Tests for EncryptionMetadata class."""
    
    def test_to_dict(self):
        """Test converting metadata to dictionary."""
        from app.encryption import EncryptionMetadata
        
        nonce = secrets.token_bytes(12)
        encrypted_key = secrets.token_bytes(60)
        
        metadata = EncryptionMetadata(
            algorithm="AES256",
            key_id="local",
            nonce=nonce,
            encrypted_data_key=encrypted_key,
        )
        
        result = metadata.to_dict()
        
        assert result["x-amz-server-side-encryption"] == "AES256"
        assert result["x-amz-encryption-key-id"] == "local"
        assert base64.b64decode(result["x-amz-encryption-nonce"]) == nonce
        assert base64.b64decode(result["x-amz-encrypted-data-key"]) == encrypted_key
    
    def test_from_dict(self):
        """Test creating metadata from dictionary."""
        from app.encryption import EncryptionMetadata
        
        nonce = secrets.token_bytes(12)
        encrypted_key = secrets.token_bytes(60)
        
        data = {
            "x-amz-server-side-encryption": "AES256",
            "x-amz-encryption-key-id": "local",
            "x-amz-encryption-nonce": base64.b64encode(nonce).decode(),
            "x-amz-encrypted-data-key": base64.b64encode(encrypted_key).decode(),
        }
        
        metadata = EncryptionMetadata.from_dict(data)
        
        assert metadata is not None
        assert metadata.algorithm == "AES256"
        assert metadata.key_id == "local"
        assert metadata.nonce == nonce
        assert metadata.encrypted_data_key == encrypted_key
    
    def test_from_dict_returns_none_for_unencrypted(self):
        """Test that from_dict returns None for unencrypted objects."""
        from app.encryption import EncryptionMetadata
        
        data = {"some-other-key": "value"}
        
        metadata = EncryptionMetadata.from_dict(data)
        
        assert metadata is None


class TestStreamingEncryptor:
    """Tests for streaming encryption."""
    
    def test_encrypt_decrypt_stream(self, tmp_path):
        """Test streaming encryption and decryption."""
        from app.encryption import LocalKeyEncryption, StreamingEncryptor
        
        key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(key_path)
        encryptor = StreamingEncryptor(provider, chunk_size=1024)

        original_data = b"A" * 5000 + b"B" * 5000 + b"C" * 5000
        stream = io.BytesIO(original_data)

        encrypted_stream, metadata = encryptor.encrypt_stream(stream)
        encrypted_data = encrypted_stream.read()

        assert encrypted_data != original_data
        assert metadata.algorithm == "AES256"

        encrypted_stream = io.BytesIO(encrypted_data)
        decrypted_stream = encryptor.decrypt_stream(encrypted_stream, metadata)
        decrypted_data = decrypted_stream.read()
        
        assert decrypted_data == original_data
    
    def test_encrypt_small_data(self, tmp_path):
        """Test encrypting data smaller than chunk size."""
        from app.encryption import LocalKeyEncryption, StreamingEncryptor
        
        key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(key_path)
        encryptor = StreamingEncryptor(provider, chunk_size=1024)
        
        original_data = b"Small data"
        stream = io.BytesIO(original_data)
        
        encrypted_stream, metadata = encryptor.encrypt_stream(stream)
        encrypted_stream.seek(0)
        
        decrypted_stream = encryptor.decrypt_stream(encrypted_stream, metadata)
        decrypted_data = decrypted_stream.read()
        
        assert decrypted_data == original_data
    
    def test_encrypt_empty_data(self, tmp_path):
        """Test encrypting empty data."""
        from app.encryption import LocalKeyEncryption, StreamingEncryptor
        
        key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(key_path)
        encryptor = StreamingEncryptor(provider)
        
        stream = io.BytesIO(b"")
        
        encrypted_stream, metadata = encryptor.encrypt_stream(stream)
        encrypted_stream.seek(0)
        
        decrypted_stream = encryptor.decrypt_stream(encrypted_stream, metadata)
        decrypted_data = decrypted_stream.read()
        
        assert decrypted_data == b""


class TestEncryptionManager:
    """Tests for EncryptionManager."""
    
    def test_encryption_disabled_by_default(self, tmp_path):
        """Test that encryption is disabled by default."""
        from app.encryption import EncryptionManager
        
        config = {
            "encryption_enabled": False,
            "encryption_master_key_path": str(tmp_path / "master.key"),
        }
        
        manager = EncryptionManager(config)
        
        assert not manager.enabled
    
    def test_encryption_enabled(self, tmp_path):
        """Test enabling encryption."""
        from app.encryption import EncryptionManager
        
        config = {
            "encryption_enabled": True,
            "encryption_master_key_path": str(tmp_path / "master.key"),
            "default_encryption_algorithm": "AES256",
        }
        
        manager = EncryptionManager(config)
        
        assert manager.enabled
        assert manager.default_algorithm == "AES256"
    
    def test_encrypt_decrypt_object(self, tmp_path):
        """Test encrypting and decrypting an object."""
        from app.encryption import EncryptionManager
        
        config = {
            "encryption_enabled": True,
            "encryption_master_key_path": str(tmp_path / "master.key"),
        }
        
        manager = EncryptionManager(config)
        
        plaintext = b"Object data to encrypt"
        
        ciphertext, metadata = manager.encrypt_object(plaintext)
        
        assert ciphertext != plaintext
        assert metadata.algorithm == "AES256"
        
        decrypted = manager.decrypt_object(ciphertext, metadata)
        
        assert decrypted == plaintext


class TestClientEncryptionHelper:
    """Tests for client-side encryption helpers."""
    
    def test_generate_client_key(self):
        """Test generating a client encryption key."""
        from app.encryption import ClientEncryptionHelper
        
        key_info = ClientEncryptionHelper.generate_client_key()
        
        assert "key" in key_info
        assert key_info["algorithm"] == "AES-256-GCM"
        assert "created_at" in key_info

        key = base64.b64decode(key_info["key"])
        assert len(key) == 32
    
    def test_encrypt_with_key(self):
        """Test encrypting data with a client key."""
        from app.encryption import ClientEncryptionHelper
        
        key = base64.b64encode(secrets.token_bytes(32)).decode()
        plaintext = b"Client-side encrypted data"
        
        result = ClientEncryptionHelper.encrypt_with_key(plaintext, key)
        
        assert "ciphertext" in result
        assert "nonce" in result
        assert result["algorithm"] == "AES-256-GCM"
    
    def test_encrypt_decrypt_with_key(self):
        """Test round-trip client-side encryption."""
        from app.encryption import ClientEncryptionHelper
        
        key = base64.b64encode(secrets.token_bytes(32)).decode()
        plaintext = b"Client-side encrypted data"
        
        encrypted = ClientEncryptionHelper.encrypt_with_key(plaintext, key)
        
        decrypted = ClientEncryptionHelper.decrypt_with_key(
            encrypted["ciphertext"],
            encrypted["nonce"],
            key,
        )
        
        assert decrypted == plaintext
    
    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails."""
        from app.encryption import ClientEncryptionHelper, EncryptionError
        
        key1 = base64.b64encode(secrets.token_bytes(32)).decode()
        key2 = base64.b64encode(secrets.token_bytes(32)).decode()
        plaintext = b"Secret data"
        
        encrypted = ClientEncryptionHelper.encrypt_with_key(plaintext, key1)
        
        with pytest.raises(EncryptionError):
            ClientEncryptionHelper.decrypt_with_key(
                encrypted["ciphertext"],
                encrypted["nonce"],
                key2,
            )


class TestKMSManager:
    """Tests for KMS key management."""
    
    def test_create_key(self, tmp_path):
        """Test creating a KMS key."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        key = kms.create_key("Test key", key_id="test-key-1")
        
        assert key.key_id == "test-key-1"
        assert key.description == "Test key"
        assert key.enabled
        assert keys_path.exists()
    
    def test_list_keys(self, tmp_path):
        """Test listing KMS keys."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Key 1", key_id="key-1")
        kms.create_key("Key 2", key_id="key-2")
        
        keys = kms.list_keys()
        
        assert len(keys) == 2
        key_ids = {k.key_id for k in keys}
        assert "key-1" in key_ids
        assert "key-2" in key_ids
    
    def test_get_key(self, tmp_path):
        """Test getting a specific key."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Test key", key_id="test-key")
        
        key = kms.get_key("test-key")
        
        assert key is not None
        assert key.key_id == "test-key"

        assert kms.get_key("non-existent") is None
    
    def test_enable_disable_key(self, tmp_path):
        """Test enabling and disabling keys."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Test key", key_id="test-key")

        assert kms.get_key("test-key").enabled

        kms.disable_key("test-key")
        assert not kms.get_key("test-key").enabled

        kms.enable_key("test-key")
        assert kms.get_key("test-key").enabled
    
    def test_delete_key(self, tmp_path):
        """Test deleting a key."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Test key", key_id="test-key")
        assert kms.get_key("test-key") is not None
        
        kms.delete_key("test-key")
        assert kms.get_key("test-key") is None
    
    def test_encrypt_decrypt(self, tmp_path):
        """Test KMS encrypt and decrypt."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        key = kms.create_key("Test key", key_id="test-key")
        
        plaintext = b"Secret data to encrypt"
        
        ciphertext = kms.encrypt("test-key", plaintext)
        
        assert ciphertext != plaintext
        
        decrypted, key_id = kms.decrypt(ciphertext)
        
        assert decrypted == plaintext
        assert key_id == "test-key"
    
    def test_encrypt_with_context(self, tmp_path):
        """Test encryption with encryption context."""
        from app.kms import KMSManager, EncryptionError
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Test key", key_id="test-key")
        
        plaintext = b"Secret data"
        context = {"bucket": "test-bucket", "key": "test-key"}
        
        ciphertext = kms.encrypt("test-key", plaintext, context)

        decrypted, _ = kms.decrypt(ciphertext, context)
        assert decrypted == plaintext

        with pytest.raises(EncryptionError):
            kms.decrypt(ciphertext, {"different": "context"})
    
    def test_generate_data_key(self, tmp_path):
        """Test generating a data key."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Test key", key_id="test-key")
        
        plaintext_key, encrypted_key = kms.generate_data_key("test-key")
        
        assert len(plaintext_key) == 32
        assert len(encrypted_key) > 0

        decrypted_key = kms.decrypt_data_key("test-key", encrypted_key)
        
        assert decrypted_key == plaintext_key
    
    def test_disabled_key_cannot_encrypt(self, tmp_path):
        """Test that disabled keys cannot be used for encryption."""
        from app.kms import KMSManager, EncryptionError
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Test key", key_id="test-key")
        kms.disable_key("test-key")
        
        with pytest.raises(EncryptionError, match="disabled"):
            kms.encrypt("test-key", b"data")
    
    def test_re_encrypt(self, tmp_path):
        """Test re-encrypting data with a different key."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        kms.create_key("Key 1", key_id="key-1")
        kms.create_key("Key 2", key_id="key-2")
        
        plaintext = b"Data to re-encrypt"

        ciphertext1 = kms.encrypt("key-1", plaintext)
        ciphertext2 = kms.re_encrypt(ciphertext1, "key-2")
        decrypted, key_id = kms.decrypt(ciphertext2)
        
        assert decrypted == plaintext
        assert key_id == "key-2"
    
    def test_generate_random(self, tmp_path):
        """Test generating random bytes."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        
        random1 = kms.generate_random(32)
        random2 = kms.generate_random(32)
        
        assert len(random1) == 32
        assert len(random2) == 32
        assert random1 != random2
    
    def test_keys_persist_across_instances(self, tmp_path):
        """Test that keys persist and can be loaded by new instances."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"

        kms1 = KMSManager(keys_path, master_key_path)
        kms1.create_key("Test key", key_id="test-key")

        plaintext = b"Persistent encryption test"
        ciphertext = kms1.encrypt("test-key", plaintext)

        kms2 = KMSManager(keys_path, master_key_path)
        
        decrypted, key_id = kms2.decrypt(ciphertext)
        
        assert decrypted == plaintext
        assert key_id == "test-key"


class TestKMSEncryptionProvider:
    """Tests for KMS encryption provider."""
    
    def test_kms_encryption_provider(self, tmp_path):
        """Test using KMS as an encryption provider."""
        from app.kms import KMSManager
        
        keys_path = tmp_path / "kms_keys.json"
        master_key_path = tmp_path / "master.key"
        
        kms = KMSManager(keys_path, master_key_path)
        kms.create_key("Test key", key_id="test-key")
        
        provider = kms.get_provider("test-key")
        
        plaintext = b"Data encrypted with KMS provider"
        
        result = provider.encrypt(plaintext)
        
        assert result.key_id == "test-key"
        assert result.ciphertext != plaintext
        
        decrypted = provider.decrypt(
            result.ciphertext,
            result.nonce,
            result.encrypted_data_key,
            result.key_id,
        )
        
        assert decrypted == plaintext


class TestEncryptedStorage:
    """Tests for encrypted storage layer."""
    
    def test_put_and_get_encrypted_object(self, tmp_path):
        """Test storing and retrieving an encrypted object."""
        from app.storage import ObjectStorage
        from app.encryption import EncryptionManager
        from app.encrypted_storage import EncryptedObjectStorage
        
        storage_root = tmp_path / "storage"
        storage = ObjectStorage(storage_root)
        
        config = {
            "encryption_enabled": True,
            "encryption_master_key_path": str(tmp_path / "master.key"),
            "default_encryption_algorithm": "AES256",
        }
        encryption = EncryptionManager(config)
        
        encrypted_storage = EncryptedObjectStorage(storage, encryption)

        storage.create_bucket("test-bucket")
        storage.set_bucket_encryption("test-bucket", {
            "Rules": [{"SSEAlgorithm": "AES256"}]
        })

        original_data = b"This is secret data that should be encrypted"
        stream = io.BytesIO(original_data)

        meta = encrypted_storage.put_object(
            "test-bucket",
            "secret.txt",
            stream,
        )

        assert meta is not None

        file_path = storage_root / "test-bucket" / "secret.txt"
        stored_data = file_path.read_bytes()
        assert stored_data != original_data

        data, metadata = encrypted_storage.get_object_data("test-bucket", "secret.txt")
        
        assert data == original_data
    
    def test_no_encryption_without_config(self, tmp_path):
        """Test that objects are not encrypted without bucket config."""
        from app.storage import ObjectStorage
        from app.encryption import EncryptionManager
        from app.encrypted_storage import EncryptedObjectStorage
        
        storage_root = tmp_path / "storage"
        storage = ObjectStorage(storage_root)
        
        config = {
            "encryption_enabled": True,
            "encryption_master_key_path": str(tmp_path / "master.key"),
        }
        encryption = EncryptionManager(config)
        
        encrypted_storage = EncryptedObjectStorage(storage, encryption)
        
        storage.create_bucket("test-bucket")

        original_data = b"Unencrypted data"
        stream = io.BytesIO(original_data)

        encrypted_storage.put_object("test-bucket", "plain.txt", stream)

        file_path = storage_root / "test-bucket" / "plain.txt"
        stored_data = file_path.read_bytes()
        assert stored_data == original_data
    
    def test_explicit_encryption_request(self, tmp_path):
        """Test explicitly requesting encryption."""
        from app.storage import ObjectStorage
        from app.encryption import EncryptionManager
        from app.encrypted_storage import EncryptedObjectStorage
        
        storage_root = tmp_path / "storage"
        storage = ObjectStorage(storage_root)
        
        config = {
            "encryption_enabled": True,
            "encryption_master_key_path": str(tmp_path / "master.key"),
        }
        encryption = EncryptionManager(config)
        
        encrypted_storage = EncryptedObjectStorage(storage, encryption)
        
        storage.create_bucket("test-bucket")
        
        original_data = b"Explicitly encrypted data"
        stream = io.BytesIO(original_data)

        encrypted_storage.put_object(
            "test-bucket",
            "encrypted.txt",
            stream,
            server_side_encryption="AES256",
        )

        file_path = storage_root / "test-bucket" / "encrypted.txt"
        stored_data = file_path.read_bytes()
        assert stored_data != original_data

        data, _ = encrypted_storage.get_object_data("test-bucket", "encrypted.txt")
        assert data == original_data
