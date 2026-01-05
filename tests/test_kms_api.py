"""Tests for KMS API endpoints."""
from __future__ import annotations

import base64
import json
import secrets

import pytest


@pytest.fixture
def kms_client(tmp_path):
    """Create a test client with KMS enabled."""
    from app import create_app
    
    app = create_app({
        "TESTING": True,
        "STORAGE_ROOT": str(tmp_path / "storage"),
        "IAM_CONFIG": str(tmp_path / "iam.json"),
        "BUCKET_POLICY_PATH": str(tmp_path / "policies.json"),
        "ENCRYPTION_ENABLED": True,
        "KMS_ENABLED": True,
        "ENCRYPTION_MASTER_KEY_PATH": str(tmp_path / "master.key"),
        "KMS_KEYS_PATH": str(tmp_path / "kms_keys.json"),
    })

    iam_config = {
        "users": [
            {
                "access_key": "test-access-key",
                "secret_key": "test-secret-key",
                "display_name": "Test User",
                "permissions": ["*"]
            }
        ]
    }
    (tmp_path / "iam.json").write_text(json.dumps(iam_config))
    
    return app.test_client()


@pytest.fixture
def auth_headers():
    """Get authentication headers."""
    return {
        "X-Access-Key": "test-access-key",
        "X-Secret-Key": "test-secret-key",
    }


class TestKMSKeyManagement:
    """Tests for KMS key management endpoints."""
    
    def test_create_key(self, kms_client, auth_headers):
        """Test creating a KMS key."""
        response = kms_client.post(
            "/kms/keys",
            json={"Description": "Test encryption key"},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "KeyMetadata" in data
        assert data["KeyMetadata"]["Description"] == "Test encryption key"
        assert data["KeyMetadata"]["Enabled"] is True
        assert "KeyId" in data["KeyMetadata"]
    
    def test_create_key_with_custom_id(self, kms_client, auth_headers):
        """Test creating a key with a custom ID."""
        response = kms_client.post(
            "/kms/keys",
            json={"KeyId": "my-custom-key", "Description": "Custom key"},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data["KeyMetadata"]["KeyId"] == "my-custom-key"
    
    def test_list_keys(self, kms_client, auth_headers):
        """Test listing KMS keys."""
        kms_client.post("/kms/keys", json={"Description": "Key 1"}, headers=auth_headers)
        kms_client.post("/kms/keys", json={"Description": "Key 2"}, headers=auth_headers)
        
        response = kms_client.get("/kms/keys", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "Keys" in data
        assert len(data["Keys"]) == 2
    
    def test_get_key(self, kms_client, auth_headers):
        """Test getting a specific key."""
        create_response = kms_client.post(
            "/kms/keys",
            json={"KeyId": "test-key", "Description": "Test key"},
            headers=auth_headers,
        )
        
        response = kms_client.get("/kms/keys/test-key", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert data["KeyMetadata"]["KeyId"] == "test-key"
        assert data["KeyMetadata"]["Description"] == "Test key"
    
    def test_get_nonexistent_key(self, kms_client, auth_headers):
        """Test getting a key that doesn't exist."""
        response = kms_client.get("/kms/keys/nonexistent", headers=auth_headers)
        
        assert response.status_code == 404
    
    def test_delete_key(self, kms_client, auth_headers):
        """Test deleting a key."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)

        response = kms_client.delete("/kms/keys/test-key", headers=auth_headers)

        assert response.status_code == 204

        get_response = kms_client.get("/kms/keys/test-key", headers=auth_headers)
        assert get_response.status_code == 404
    
    def test_enable_disable_key(self, kms_client, auth_headers):
        """Test enabling and disabling a key."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)

        response = kms_client.post("/kms/keys/test-key/disable", headers=auth_headers)
        assert response.status_code == 200

        get_response = kms_client.get("/kms/keys/test-key", headers=auth_headers)
        assert get_response.get_json()["KeyMetadata"]["Enabled"] is False

        response = kms_client.post("/kms/keys/test-key/enable", headers=auth_headers)
        assert response.status_code == 200

        get_response = kms_client.get("/kms/keys/test-key", headers=auth_headers)
        assert get_response.get_json()["KeyMetadata"]["Enabled"] is True


class TestKMSEncryption:
    """Tests for KMS encryption operations."""
    
    def test_encrypt_decrypt(self, kms_client, auth_headers):
        """Test encrypting and decrypting data."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)

        plaintext = b"Hello, World!"
        plaintext_b64 = base64.b64encode(plaintext).decode()

        encrypt_response = kms_client.post(
            "/kms/encrypt",
            json={"KeyId": "test-key", "Plaintext": plaintext_b64},
            headers=auth_headers,
        )
        
        assert encrypt_response.status_code == 200
        encrypt_data = encrypt_response.get_json()
        
        assert "CiphertextBlob" in encrypt_data
        assert encrypt_data["KeyId"] == "test-key"

        decrypt_response = kms_client.post(
            "/kms/decrypt",
            json={"CiphertextBlob": encrypt_data["CiphertextBlob"]},
            headers=auth_headers,
        )
        
        assert decrypt_response.status_code == 200
        decrypt_data = decrypt_response.get_json()
        
        decrypted = base64.b64decode(decrypt_data["Plaintext"])
        assert decrypted == plaintext
    
    def test_encrypt_with_context(self, kms_client, auth_headers):
        """Test encryption with encryption context."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)
        
        plaintext = b"Contextualized data"
        plaintext_b64 = base64.b64encode(plaintext).decode()
        context = {"purpose": "testing", "bucket": "my-bucket"}

        encrypt_response = kms_client.post(
            "/kms/encrypt",
            json={
                "KeyId": "test-key",
                "Plaintext": plaintext_b64,
                "EncryptionContext": context,
            },
            headers=auth_headers,
        )
        
        assert encrypt_response.status_code == 200
        ciphertext = encrypt_response.get_json()["CiphertextBlob"]

        decrypt_response = kms_client.post(
            "/kms/decrypt",
            json={
                "CiphertextBlob": ciphertext,
                "EncryptionContext": context,
            },
            headers=auth_headers,
        )
        
        assert decrypt_response.status_code == 200

        wrong_context_response = kms_client.post(
            "/kms/decrypt",
            json={
                "CiphertextBlob": ciphertext,
                "EncryptionContext": {"wrong": "context"},
            },
            headers=auth_headers,
        )
        
        assert wrong_context_response.status_code == 400
    
    def test_encrypt_missing_key_id(self, kms_client, auth_headers):
        """Test encryption without KeyId."""
        response = kms_client.post(
            "/kms/encrypt",
            json={"Plaintext": base64.b64encode(b"data").decode()},
            headers=auth_headers,
        )
        
        assert response.status_code == 400
        assert "KeyId is required" in response.get_json()["message"]
    
    def test_encrypt_missing_plaintext(self, kms_client, auth_headers):
        """Test encryption without Plaintext."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)
        
        response = kms_client.post(
            "/kms/encrypt",
            json={"KeyId": "test-key"},
            headers=auth_headers,
        )
        
        assert response.status_code == 400
        assert "Plaintext is required" in response.get_json()["message"]


class TestKMSDataKey:
    """Tests for KMS data key generation."""
    
    def test_generate_data_key(self, kms_client, auth_headers):
        """Test generating a data key."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)
        
        response = kms_client.post(
            "/kms/generate-data-key",
            json={"KeyId": "test-key"},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "Plaintext" in data
        assert "CiphertextBlob" in data
        assert data["KeyId"] == "test-key"
        
        # Verify plaintext key is 256 bits (32 bytes)
        plaintext_key = base64.b64decode(data["Plaintext"])
        assert len(plaintext_key) == 32
    
    def test_generate_data_key_aes_128(self, kms_client, auth_headers):
        """Test generating an AES-128 data key."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)
        
        response = kms_client.post(
            "/kms/generate-data-key",
            json={"KeyId": "test-key", "KeySpec": "AES_128"},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        # Verify plaintext key is 128 bits (16 bytes)
        plaintext_key = base64.b64decode(data["Plaintext"])
        assert len(plaintext_key) == 16
    
    def test_generate_data_key_without_plaintext(self, kms_client, auth_headers):
        """Test generating a data key without plaintext."""
        kms_client.post("/kms/keys", json={"KeyId": "test-key"}, headers=auth_headers)
        
        response = kms_client.post(
            "/kms/generate-data-key-without-plaintext",
            json={"KeyId": "test-key"},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "CiphertextBlob" in data
        assert "Plaintext" not in data


class TestKMSReEncrypt:
    """Tests for KMS re-encryption."""
    
    def test_re_encrypt(self, kms_client, auth_headers):
        """Test re-encrypting data with a different key."""
        kms_client.post("/kms/keys", json={"KeyId": "key-1"}, headers=auth_headers)
        kms_client.post("/kms/keys", json={"KeyId": "key-2"}, headers=auth_headers)

        plaintext = b"Data to re-encrypt"
        encrypt_response = kms_client.post(
            "/kms/encrypt",
            json={
                "KeyId": "key-1",
                "Plaintext": base64.b64encode(plaintext).decode(),
            },
            headers=auth_headers,
        )
        
        ciphertext = encrypt_response.get_json()["CiphertextBlob"]

        re_encrypt_response = kms_client.post(
            "/kms/re-encrypt",
            json={
                "CiphertextBlob": ciphertext,
                "DestinationKeyId": "key-2",
            },
            headers=auth_headers,
        )
        
        assert re_encrypt_response.status_code == 200
        data = re_encrypt_response.get_json()
        
        assert data["SourceKeyId"] == "key-1"
        assert data["KeyId"] == "key-2"

        decrypt_response = kms_client.post(
            "/kms/decrypt",
            json={"CiphertextBlob": data["CiphertextBlob"]},
            headers=auth_headers,
        )
        
        decrypted = base64.b64decode(decrypt_response.get_json()["Plaintext"])
        assert decrypted == plaintext


class TestKMSRandom:
    """Tests for random number generation."""
    
    def test_generate_random(self, kms_client, auth_headers):
        """Test generating random bytes."""
        response = kms_client.post(
            "/kms/generate-random",
            json={"NumberOfBytes": 64},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        random_bytes = base64.b64decode(data["Plaintext"])
        assert len(random_bytes) == 64
    
    def test_generate_random_default_size(self, kms_client, auth_headers):
        """Test generating random bytes with default size."""
        response = kms_client.post(
            "/kms/generate-random",
            json={},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        random_bytes = base64.b64decode(data["Plaintext"])
        assert len(random_bytes) == 32


class TestClientSideEncryption:
    """Tests for client-side encryption helpers."""
    
    def test_generate_client_key(self, kms_client, auth_headers):
        """Test generating a client encryption key."""
        response = kms_client.post(
            "/kms/client/generate-key",
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "key" in data
        assert data["algorithm"] == "AES-256-GCM"
        
        key = base64.b64decode(data["key"])
        assert len(key) == 32
    
    def test_client_encrypt_decrypt(self, kms_client, auth_headers):
        """Test client-side encryption and decryption."""
        key_response = kms_client.post("/kms/client/generate-key", headers=auth_headers)
        key = key_response.get_json()["key"]

        plaintext = b"Client-side encrypted data"
        encrypt_response = kms_client.post(
            "/kms/client/encrypt",
            json={
                "Plaintext": base64.b64encode(plaintext).decode(),
                "Key": key,
            },
            headers=auth_headers,
        )
        
        assert encrypt_response.status_code == 200
        encrypted = encrypt_response.get_json()

        decrypt_response = kms_client.post(
            "/kms/client/decrypt",
            json={
                "Ciphertext": encrypted["ciphertext"],
                "Nonce": encrypted["nonce"],
                "Key": key,
            },
            headers=auth_headers,
        )
        
        assert decrypt_response.status_code == 200
        decrypted = base64.b64decode(decrypt_response.get_json()["Plaintext"])
        assert decrypted == plaintext


class TestEncryptionMaterials:
    """Tests for S3 encryption materials endpoint."""
    
    def test_get_encryption_materials(self, kms_client, auth_headers):
        """Test getting encryption materials for client-side S3 encryption."""
        kms_client.post("/kms/keys", json={"KeyId": "s3-key"}, headers=auth_headers)
        
        response = kms_client.post(
            "/kms/materials/s3-key",
            json={},
            headers=auth_headers,
        )
        
        assert response.status_code == 200
        data = response.get_json()
        
        assert "PlaintextKey" in data
        assert "EncryptedKey" in data
        assert data["KeyId"] == "s3-key"
        assert data["Algorithm"] == "AES-256-GCM"

        key = base64.b64decode(data["PlaintextKey"])
        assert len(key) == 32


class TestKMSAuthentication:
    """Tests for KMS authentication requirements."""
    
    def test_unauthenticated_request_fails(self, kms_client):
        """Test that unauthenticated requests are rejected."""
        response = kms_client.get("/kms/keys")

        assert response.status_code == 403
    
    def test_invalid_credentials_fail(self, kms_client):
        """Test that invalid credentials are rejected."""
        response = kms_client.get(
            "/kms/keys",
            headers={
                "X-Access-Key": "wrong-key",
                "X-Secret-Key": "wrong-secret",
            },
        )
        
        assert response.status_code == 403
