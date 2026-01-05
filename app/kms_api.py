from __future__ import annotations

import base64
import uuid
from typing import Any, Dict

from flask import Blueprint, Response, current_app, jsonify, request

from .encryption import ClientEncryptionHelper, EncryptionError
from .extensions import limiter
from .iam import IamError

kms_api_bp = Blueprint("kms_api", __name__, url_prefix="/kms")


def _require_principal():
    """Require authentication for KMS operations."""
    from .s3_api import _require_principal as s3_require_principal
    return s3_require_principal()


def _kms():
    """Get KMS manager from app extensions."""
    return current_app.extensions.get("kms")


def _encryption():
    """Get encryption manager from app extensions."""
    return current_app.extensions.get("encryption")


def _error_response(code: str, message: str, status: int) -> tuple[Dict[str, Any], int]:
    return {"__type": code, "message": message}, status

@kms_api_bp.route("/keys", methods=["GET", "POST"])
@limiter.limit("30 per minute")
def list_or_create_keys():
    """List all KMS keys or create a new key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        key_id = payload.get("KeyId") or payload.get("key_id")
        description = payload.get("Description") or payload.get("description", "")
        
        try:
            key = kms.create_key(description=description, key_id=key_id)
            current_app.logger.info(
                "KMS key created",
                extra={"key_id": key.key_id, "principal": principal.access_key},
            )
            return jsonify({
                "KeyMetadata": key.to_dict(),
            })
        except EncryptionError as exc:
            return _error_response("KMSInternalException", str(exc), 400)
    
    keys = kms.list_keys()
    return jsonify({
        "Keys": [{"KeyId": k.key_id, "KeyArn": k.arn} for k in keys],
        "Truncated": False,
    })


@kms_api_bp.route("/keys/<key_id>", methods=["GET", "DELETE"])
@limiter.limit("30 per minute")
def get_or_delete_key(key_id: str):
    """Get or delete a specific KMS key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    if request.method == "DELETE":
        try:
            kms.delete_key(key_id)
            current_app.logger.info(
                "KMS key deleted",
                extra={"key_id": key_id, "principal": principal.access_key},
            )
            return Response(status=204)
        except EncryptionError as exc:
            return _error_response("NotFoundException", str(exc), 404)
    
    key = kms.get_key(key_id)
    if not key:
        return _error_response("NotFoundException", f"Key not found: {key_id}", 404)
    
    return jsonify({"KeyMetadata": key.to_dict()})


@kms_api_bp.route("/keys/<key_id>/enable", methods=["POST"])
@limiter.limit("30 per minute")
def enable_key(key_id: str):
    """Enable a KMS key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    try:
        kms.enable_key(key_id)
        current_app.logger.info(
            "KMS key enabled",
            extra={"key_id": key_id, "principal": principal.access_key},
        )
        return Response(status=200)
    except EncryptionError as exc:
        return _error_response("NotFoundException", str(exc), 404)


@kms_api_bp.route("/keys/<key_id>/disable", methods=["POST"])
@limiter.limit("30 per minute")
def disable_key(key_id: str):
    """Disable a KMS key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    try:
        kms.disable_key(key_id)
        current_app.logger.info(
            "KMS key disabled",
            extra={"key_id": key_id, "principal": principal.access_key},
        )
        return Response(status=200)
    except EncryptionError as exc:
        return _error_response("NotFoundException", str(exc), 404)

@kms_api_bp.route("/encrypt", methods=["POST"])
@limiter.limit("60 per minute")
def encrypt_data():
    """Encrypt data using a KMS key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    key_id = payload.get("KeyId")
    plaintext_b64 = payload.get("Plaintext")
    context = payload.get("EncryptionContext")
    
    if not key_id:
        return _error_response("ValidationException", "KeyId is required", 400)
    if not plaintext_b64:
        return _error_response("ValidationException", "Plaintext is required", 400)
    
    try:
        plaintext = base64.b64decode(plaintext_b64)
    except Exception:
        return _error_response("ValidationException", "Plaintext must be base64 encoded", 400)
    
    try:
        ciphertext = kms.encrypt(key_id, plaintext, context)
        return jsonify({
            "CiphertextBlob": base64.b64encode(ciphertext).decode(),
            "KeyId": key_id,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        })
    except EncryptionError as exc:
        return _error_response("KMSInternalException", str(exc), 400)


@kms_api_bp.route("/decrypt", methods=["POST"])
@limiter.limit("60 per minute")
def decrypt_data():
    """Decrypt data using a KMS key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    ciphertext_b64 = payload.get("CiphertextBlob")
    context = payload.get("EncryptionContext")
    
    if not ciphertext_b64:
        return _error_response("ValidationException", "CiphertextBlob is required", 400)
    
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        return _error_response("ValidationException", "CiphertextBlob must be base64 encoded", 400)
    
    try:
        plaintext, key_id = kms.decrypt(ciphertext, context)
        return jsonify({
            "Plaintext": base64.b64encode(plaintext).decode(),
            "KeyId": key_id,
            "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
        })
    except EncryptionError as exc:
        return _error_response("InvalidCiphertextException", str(exc), 400)


@kms_api_bp.route("/generate-data-key", methods=["POST"])
@limiter.limit("60 per minute")
def generate_data_key():
    """Generate a data encryption key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    key_id = payload.get("KeyId")
    context = payload.get("EncryptionContext")
    key_spec = payload.get("KeySpec", "AES_256")
    
    if not key_id:
        return _error_response("ValidationException", "KeyId is required", 400)
    
    if key_spec not in {"AES_256", "AES_128"}:
        return _error_response("ValidationException", "KeySpec must be AES_256 or AES_128", 400)
    
    try:
        plaintext_key, encrypted_key = kms.generate_data_key(key_id, context)
        
        if key_spec == "AES_128":
            plaintext_key = plaintext_key[:16]
        
        return jsonify({
            "Plaintext": base64.b64encode(plaintext_key).decode(),
            "CiphertextBlob": base64.b64encode(encrypted_key).decode(),
            "KeyId": key_id,
        })
    except EncryptionError as exc:
        return _error_response("KMSInternalException", str(exc), 400)


@kms_api_bp.route("/generate-data-key-without-plaintext", methods=["POST"])
@limiter.limit("60 per minute")
def generate_data_key_without_plaintext():
    """Generate a data encryption key without returning the plaintext."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    key_id = payload.get("KeyId")
    context = payload.get("EncryptionContext")
    
    if not key_id:
        return _error_response("ValidationException", "KeyId is required", 400)
    
    try:
        _, encrypted_key = kms.generate_data_key(key_id, context)
        return jsonify({
            "CiphertextBlob": base64.b64encode(encrypted_key).decode(),
            "KeyId": key_id,
        })
    except EncryptionError as exc:
        return _error_response("KMSInternalException", str(exc), 400)


@kms_api_bp.route("/re-encrypt", methods=["POST"])
@limiter.limit("30 per minute")
def re_encrypt():
    """Re-encrypt data with a different key."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    ciphertext_b64 = payload.get("CiphertextBlob")
    destination_key_id = payload.get("DestinationKeyId")
    source_context = payload.get("SourceEncryptionContext")
    destination_context = payload.get("DestinationEncryptionContext")
    
    if not ciphertext_b64:
        return _error_response("ValidationException", "CiphertextBlob is required", 400)
    if not destination_key_id:
        return _error_response("ValidationException", "DestinationKeyId is required", 400)
    
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception:
        return _error_response("ValidationException", "CiphertextBlob must be base64 encoded", 400)
    
    try:
        plaintext, source_key_id = kms.decrypt(ciphertext, source_context)
        new_ciphertext = kms.encrypt(destination_key_id, plaintext, destination_context)
        
        return jsonify({
            "CiphertextBlob": base64.b64encode(new_ciphertext).decode(),
            "SourceKeyId": source_key_id,
            "KeyId": destination_key_id,
        })
    except EncryptionError as exc:
        return _error_response("KMSInternalException", str(exc), 400)


@kms_api_bp.route("/generate-random", methods=["POST"])
@limiter.limit("60 per minute")
def generate_random():
    """Generate random bytes."""
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    num_bytes = payload.get("NumberOfBytes", 32)
    
    try:
        num_bytes = int(num_bytes)
    except (TypeError, ValueError):
        return _error_response("ValidationException", "NumberOfBytes must be an integer", 400)
    
    try:
        random_bytes = kms.generate_random(num_bytes)
        return jsonify({
            "Plaintext": base64.b64encode(random_bytes).decode(),
        })
    except EncryptionError as exc:
        return _error_response("ValidationException", str(exc), 400)

@kms_api_bp.route("/client/generate-key", methods=["POST"])
@limiter.limit("30 per minute")
def generate_client_key():
    """Generate a client-side encryption key."""
    principal, error = _require_principal()
    if error:
        return error
    
    key_info = ClientEncryptionHelper.generate_client_key()
    return jsonify(key_info)


@kms_api_bp.route("/client/encrypt", methods=["POST"])
@limiter.limit("60 per minute")
def client_encrypt():
    """Encrypt data using client-side encryption."""
    principal, error = _require_principal()
    if error:
        return error
    
    payload = request.get_json(silent=True) or {}
    plaintext_b64 = payload.get("Plaintext")
    key_b64 = payload.get("Key")
    
    if not plaintext_b64 or not key_b64:
        return _error_response("ValidationException", "Plaintext and Key are required", 400)
    
    try:
        plaintext = base64.b64decode(plaintext_b64)
        result = ClientEncryptionHelper.encrypt_with_key(plaintext, key_b64)
        return jsonify(result)
    except Exception as exc:
        return _error_response("EncryptionError", str(exc), 400)


@kms_api_bp.route("/client/decrypt", methods=["POST"])
@limiter.limit("60 per minute")
def client_decrypt():
    """Decrypt data using client-side encryption."""
    principal, error = _require_principal()
    if error:
        return error
    
    payload = request.get_json(silent=True) or {}
    ciphertext_b64 = payload.get("Ciphertext") or payload.get("ciphertext")
    nonce_b64 = payload.get("Nonce") or payload.get("nonce")
    key_b64 = payload.get("Key") or payload.get("key")
    
    if not ciphertext_b64 or not nonce_b64 or not key_b64:
        return _error_response("ValidationException", "Ciphertext, Nonce, and Key are required", 400)
    
    try:
        plaintext = ClientEncryptionHelper.decrypt_with_key(ciphertext_b64, nonce_b64, key_b64)
        return jsonify({
            "Plaintext": base64.b64encode(plaintext).decode(),
        })
    except Exception as exc:
        return _error_response("DecryptionError", str(exc), 400)

@kms_api_bp.route("/materials/<key_id>", methods=["POST"])
@limiter.limit("60 per minute")
def get_encryption_materials(key_id: str):
    """Get encryption materials for client-side S3 encryption.
    
    This is used by S3 encryption clients that want to use KMS for
    key management but perform encryption client-side.
    """
    principal, error = _require_principal()
    if error:
        return error
    
    kms = _kms()
    if not kms:
        return _error_response("KMSNotEnabled", "KMS is not configured", 400)
    
    payload = request.get_json(silent=True) or {}
    context = payload.get("EncryptionContext")
    
    try:
        plaintext_key, encrypted_key = kms.generate_data_key(key_id, context)
        
        return jsonify({
            "PlaintextKey": base64.b64encode(plaintext_key).decode(),
            "EncryptedKey": base64.b64encode(encrypted_key).decode(),
            "KeyId": key_id,
            "Algorithm": "AES-256-GCM",
            "KeyWrapAlgorithm": "kms",
        })
    except EncryptionError as exc:
        return _error_response("KMSInternalException", str(exc), 400)
