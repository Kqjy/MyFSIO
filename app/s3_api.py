"""Flask blueprint exposing a subset of the S3 REST API."""
from __future__ import annotations

import hashlib
import hmac
import mimetypes
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from urllib.parse import quote, urlencode, urlparse
from xml.etree.ElementTree import Element, SubElement, tostring, fromstring, ParseError

from flask import Blueprint, Response, current_app, jsonify, request, g
from werkzeug.http import http_date

from .bucket_policies import BucketPolicyStore
from .extensions import limiter
from .iam import IamError, Principal
from .replication import ReplicationManager
from .storage import ObjectStorage, StorageError

s3_api_bp = Blueprint("s3_api", __name__)


# ---------------------- helpers ----------------------
def _storage() -> ObjectStorage:
    return current_app.extensions["object_storage"]


def _iam():
    return current_app.extensions["iam"]


def _replication_manager() -> ReplicationManager:
    return current_app.extensions["replication"]


def _bucket_policies() -> BucketPolicyStore:
    store: BucketPolicyStore = current_app.extensions["bucket_policies"]
    store.maybe_reload()
    return store


def _xml_response(element: Element, status: int = 200) -> Response:
    xml_bytes = tostring(element, encoding="utf-8")
    return Response(xml_bytes, status=status, mimetype="application/xml")


def _error_response(code: str, message: str, status: int) -> Response:
    error = Element("Error")
    SubElement(error, "Code").text = code
    SubElement(error, "Message").text = message
    SubElement(error, "Resource").text = request.path
    SubElement(error, "RequestId").text = uuid.uuid4().hex
    return _xml_response(error, status)


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


def _verify_sigv4_header(req: Any, auth_header: str) -> Principal | None:
    # Parse Authorization header
    # AWS4-HMAC-SHA256 Credential=AKIA.../20230101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=...
    match = re.match(
        r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), Signature=(.+)",
        auth_header,
    )
    if not match:
        return None

    access_key, date_stamp, region, service, signed_headers_str, signature = match.groups()

    # Get secret key
    secret_key = _iam().get_secret_key(access_key)
    if not secret_key:
        raise IamError("Invalid access key")

    # Canonical Request
    method = req.method
    canonical_uri = quote(req.path, safe="/-_.~")
    
    # Canonical Query String
    query_args = []
    for key, value in req.args.items(multi=True):
        query_args.append((key, value))
    query_args.sort(key=lambda x: (x[0], x[1]))
    
    canonical_query_parts = []
    for k, v in query_args:
        canonical_query_parts.append(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}")
    canonical_query_string = "&".join(canonical_query_parts)

    # Canonical Headers
    signed_headers_list = signed_headers_str.split(";")
    canonical_headers_parts = []
    for header in signed_headers_list:
        header_val = req.headers.get(header)
        if header_val is None:
             header_val = ""
        
        header_val = " ".join(header_val.split())
        canonical_headers_parts.append(f"{header.lower()}:{header_val}\n")
    canonical_headers = "".join(canonical_headers_parts)

    # Payload Hash
    payload_hash = req.headers.get("X-Amz-Content-Sha256")
    if not payload_hash:
        payload_hash = hashlib.sha256(req.get_data()).hexdigest()

    canonical_request = f"{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers_str}\n{payload_hash}"

    # String to Sign
    amz_date = req.headers.get("X-Amz-Date")
    if not amz_date:
        amz_date = req.headers.get("Date")
    
    if not amz_date:
        raise IamError("Missing Date header")

    try:
        request_time = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise IamError("Invalid X-Amz-Date format")

    now = datetime.now(timezone.utc)
    time_diff = abs((now - request_time).total_seconds())
    if time_diff > 900:  # 15 minutes
        raise IamError("Request timestamp too old or too far in the future")

    required_headers = {'host', 'x-amz-date'}
    signed_headers_set = set(signed_headers_str.split(';'))
    if not required_headers.issubset(signed_headers_set):
        # Some clients might sign 'date' instead of 'x-amz-date'
        if 'date' in signed_headers_set:
            required_headers.remove('x-amz-date')
            required_headers.add('date')
        
        if not required_headers.issubset(signed_headers_set):
             raise IamError("Required headers not signed")

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    signing_key = _get_signature_key(secret_key, date_stamp, region, service)
    calculated_signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(calculated_signature, signature):
        raise IamError("SignatureDoesNotMatch")

    return _iam().get_principal(access_key)


def _verify_sigv4_query(req: Any) -> Principal | None:
    credential = req.args.get("X-Amz-Credential")
    signed_headers_str = req.args.get("X-Amz-SignedHeaders")
    signature = req.args.get("X-Amz-Signature")
    amz_date = req.args.get("X-Amz-Date")
    expires = req.args.get("X-Amz-Expires")

    if not (credential and signed_headers_str and signature and amz_date and expires):
        return None

    try:
        access_key, date_stamp, region, service, _ = credential.split("/")
    except ValueError:
        raise IamError("Invalid Credential format")

    try:
        req_time = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise IamError("Invalid Date format")
    
    now = datetime.now(timezone.utc)
    if now > req_time + timedelta(seconds=int(expires)):
        raise IamError("Request expired")

    secret_key = _iam().get_secret_key(access_key)
    if not secret_key:
        raise IamError("Invalid access key")

    # Canonical Request
    method = req.method
    canonical_uri = quote(req.path, safe="/-_.~")
    
    # Canonical Query String
    query_args = []
    for key, value in req.args.items(multi=True):
        if key != "X-Amz-Signature":
            query_args.append((key, value))
    query_args.sort(key=lambda x: (x[0], x[1]))
    
    canonical_query_parts = []
    for k, v in query_args:
        canonical_query_parts.append(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}")
    canonical_query_string = "&".join(canonical_query_parts)
    
    # Canonical Headers
    signed_headers_list = signed_headers_str.split(";")
    canonical_headers_parts = []
    for header in signed_headers_list:
        val = req.headers.get(header, "").strip()
        val = " ".join(val.split())
        canonical_headers_parts.append(f"{header}:{val}\n")
    canonical_headers = "".join(canonical_headers_parts)
    
    # Payload Hash
    payload_hash = "UNSIGNED-PAYLOAD"
    
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_query_string,
        canonical_headers,
        signed_headers_str,
        payload_hash
    ])
    
    # String to Sign
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    hashed_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    string_to_sign = "\n".join([
        algorithm,
        amz_date,
        credential_scope,
        hashed_request
    ])
    
    # Signature
    signing_key = _get_signature_key(secret_key, date_stamp, region, service)
    calculated_signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(calculated_signature, signature):
        raise IamError("SignatureDoesNotMatch")
    
    return _iam().get_principal(access_key)


def _verify_sigv4(req: Any) -> Principal | None:
    auth_header = req.headers.get("Authorization")
    if auth_header and auth_header.startswith("AWS4-HMAC-SHA256"):
        return _verify_sigv4_header(req, auth_header)
    
    if req.args.get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256":
        return _verify_sigv4_query(req)
        
    return None


def _require_principal():
    if ("Authorization" in request.headers and request.headers["Authorization"].startswith("AWS4-HMAC-SHA256")) or \
       (request.args.get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"):
        try:
            principal = _verify_sigv4(request)
            if principal:
                return principal, None
        except IamError as exc:
            return None, _error_response("AccessDenied", str(exc), 403)
        except (ValueError, TypeError):
             return None, _error_response("AccessDenied", "Signature verification failed", 403)

    access_key = request.headers.get("X-Access-Key")
    secret_key = request.headers.get("X-Secret-Key")
    if not access_key or not secret_key:
        return None, _error_response("AccessDenied", "Missing credentials", 403)
    try:
        principal = _iam().authenticate(access_key, secret_key)
        return principal, None
    except IamError as exc:
        return None, _error_response("AccessDenied", str(exc), 403)


def _authorize_action(principal: Principal | None, bucket_name: str | None, action: str, *, object_key: str | None = None) -> None:
    iam_allowed = False
    iam_error: IamError | None = None
    if principal is not None:
        try:
            _iam().authorize(principal, bucket_name, action)
            iam_allowed = True
        except IamError as exc:
            iam_error = exc
    else:
        iam_error = IamError("Missing credentials")

    policy_decision = None
    access_key = principal.access_key if principal else None
    if bucket_name:
        policy_decision = _bucket_policies().evaluate(access_key, bucket_name, object_key, action)
        if policy_decision == "deny":
            raise IamError("Access denied by bucket policy")

    if iam_allowed:
        return
    if policy_decision == "allow":
        return
    raise iam_error or IamError("Access denied")


def _enforce_bucket_policy(principal: Principal | None, bucket_name: str | None, object_key: str | None, action: str) -> None:
    if not bucket_name:
        return
    decision = _bucket_policies().evaluate(
        principal.access_key if principal else None,
        bucket_name,
        object_key,
        action,
    )
    if decision == "deny":
        raise IamError("Access denied by bucket policy")


def _object_principal(action: str, bucket_name: str, object_key: str):
    principal, error = _require_principal()
    try:
        _authorize_action(principal, bucket_name, action, object_key=object_key)
        return principal, None
    except IamError as exc:
        if not error:
            return None, _error_response("AccessDenied", str(exc), 403)
    if not _has_presign_params():
        return None, error
    try:
        principal = _validate_presigned_request(action, bucket_name, object_key)
        _enforce_bucket_policy(principal, bucket_name, object_key, action)
        return principal, None
    except IamError as exc:
        return None, _error_response("AccessDenied", str(exc), 403)


def _has_presign_params() -> bool:
    return bool(request.args.get("X-Amz-Algorithm"))


def _validate_presigned_request(action: str, bucket_name: str, object_key: str) -> Principal:
    algorithm = request.args.get("X-Amz-Algorithm")
    credential = request.args.get("X-Amz-Credential")
    amz_date = request.args.get("X-Amz-Date")
    signed_headers = request.args.get("X-Amz-SignedHeaders")
    expires = request.args.get("X-Amz-Expires")
    signature = request.args.get("X-Amz-Signature")
    if not all([algorithm, credential, amz_date, signed_headers, expires, signature]):
        raise IamError("Malformed presigned URL")
    if algorithm != "AWS4-HMAC-SHA256":
        raise IamError("Unsupported signing algorithm")

    parts = credential.split("/")
    if len(parts) != 5:
        raise IamError("Invalid credential scope")
    access_key, date_stamp, region, service, terminal = parts
    if terminal != "aws4_request":
        raise IamError("Invalid credential scope")
    config_region = current_app.config["AWS_REGION"]
    config_service = current_app.config["AWS_SERVICE"]
    if region != config_region or service != config_service:
        raise IamError("Credential scope mismatch")

    try:
        expiry = int(expires)
    except ValueError as exc:
        raise IamError("Invalid expiration") from exc
    if expiry < 1 or expiry > 7 * 24 * 3600:
        raise IamError("Expiration must be between 1 second and 7 days")

    try:
        request_time = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IamError("Invalid X-Amz-Date") from exc
    if datetime.now(timezone.utc) > request_time + timedelta(seconds=expiry):
        raise IamError("Presigned URL expired")

    signed_headers_list = [header.strip().lower() for header in signed_headers.split(";") if header]
    signed_headers_list.sort()
    canonical_headers = _canonical_headers_from_request(signed_headers_list)
    canonical_query = _canonical_query_from_request()
    payload_hash = request.args.get("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
    canonical_request = "\n".join(
        [
            request.method,
            _canonical_uri(bucket_name, object_key),
            canonical_query,
            canonical_headers,
            ";".join(signed_headers_list),
            payload_hash,
        ]
    )
    hashed_request = hashlib.sha256(canonical_request.encode()).hexdigest()
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashed_request,
    ])
    secret = _iam().secret_for_key(access_key)
    signing_key = _derive_signing_key(secret, date_stamp, region, service)
    expected = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise IamError("Signature mismatch")
    return _iam().principal_for_key(access_key)


def _canonical_query_from_request() -> str:
    parts = []
    for key in sorted(request.args.keys()):
        if key == "X-Amz-Signature":
            continue
        values = request.args.getlist(key)
        encoded_key = quote(str(key), safe="-_.~")
        for value in sorted(values):
            encoded_value = quote(str(value), safe="-_.~")
            parts.append(f"{encoded_key}={encoded_value}")
    return "&".join(parts)


def _canonical_headers_from_request(headers: list[str]) -> str:
    lines = []
    for header in headers:
        if header == "host":
            api_base = current_app.config.get("API_BASE_URL")
            if api_base:
                value = urlparse(api_base).netloc
            else:
                value = request.host
        else:
            value = request.headers.get(header, "")
        canonical_value = " ".join(value.strip().split()) if value else ""
        lines.append(f"{header}:{canonical_value}")
    return "\n".join(lines) + "\n"


def _canonical_uri(bucket_name: str, object_key: str | None) -> str:
    segments = [bucket_name]
    if object_key:
        segments.extend(object_key.split("/"))
    encoded = [quote(segment, safe="-_.~") for segment in segments]
    return "/" + "/".join(encoded)


def _extract_request_metadata() -> Dict[str, str]:
    metadata: Dict[str, str] = {}
    for header, value in request.headers.items():
        if header.lower().startswith("x-amz-meta-"):
            key = header[11:]
            if key:
                metadata[key] = value
    return metadata


def _derive_signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def _generate_presigned_url(
    *,
    principal: Principal,
    secret_key: str,
    method: str,
    bucket_name: str,
    object_key: str,
    expires_in: int,
) -> str:
    region = current_app.config["AWS_REGION"]
    service = current_app.config["AWS_SERVICE"]
    algorithm = "AWS4-HMAC-SHA256"
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    credential = f"{principal.access_key}/{credential_scope}"

    query_params = {
        "X-Amz-Algorithm": algorithm,
        "X-Amz-Credential": credential,
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires_in),
        "X-Amz-SignedHeaders": "host",
        "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
    }
    canonical_query = _encode_query_params(query_params)

    # Determine host and scheme from config or request
    api_base = current_app.config.get("API_BASE_URL")
    if api_base:
        parsed = urlparse(api_base)
        host = parsed.netloc
        scheme = parsed.scheme
    else:
        host = request.headers.get("X-Forwarded-Host", request.host)
        scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http")

    canonical_headers = f"host:{host}\n"
    canonical_request = "\n".join(
        [
            method,
            _canonical_uri(bucket_name, object_key),
            canonical_query,
            canonical_headers,
            "host",
            "UNSIGNED-PAYLOAD",
        ]
    )
    hashed_request = hashlib.sha256(canonical_request.encode()).hexdigest()
    string_to_sign = "\n".join(
        [
            algorithm,
            amz_date,
            credential_scope,
            hashed_request,
        ]
    )
    signing_key = _derive_signing_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    query_with_sig = canonical_query + f"&X-Amz-Signature={signature}"
    return f"{scheme}://{host}{_canonical_uri(bucket_name, object_key)}?{query_with_sig}"


def _encode_query_params(params: dict[str, str]) -> str:
    parts = []
    for key in sorted(params.keys()):
        value = params[key]
        encoded_key = quote(str(key), safe="-_.~")
        encoded_value = quote(str(value), safe="-_.~")
        parts.append(f"{encoded_key}={encoded_value}")
    return "&".join(parts)


def _strip_ns(tag: str | None) -> str:
    if not tag:
        return ""
    return tag.split("}")[-1]


def _parse_tagging_document(payload: bytes) -> list[dict[str, str]]:
    try:
        root = fromstring(payload)
    except ParseError as exc:
        raise ValueError("Malformed XML") from exc
    if _strip_ns(root.tag) != "Tagging":
        raise ValueError("Root element must be Tagging")
    tagset = root.find(".//{*}TagSet")
    if tagset is None:
        tagset = root.find("TagSet")
    if tagset is None:
        return []
    tags: list[dict[str, str]] = []
    for tag_el in list(tagset):
        if _strip_ns(tag_el.tag) != "Tag":
            continue
        key_el = tag_el.find("{*}Key")
        if key_el is None:
            key_el = tag_el.find("Key")
        value_el = tag_el.find("{*}Value")
        if value_el is None:
            value_el = tag_el.find("Value")
        key = (key_el.text or "").strip() if key_el is not None else ""
        if not key:
            continue
        value = value_el.text if value_el is not None else ""
        tags.append({"Key": key, "Value": value or ""})
    return tags


def _render_tagging_document(tags: list[dict[str, str]]) -> Element:
    root = Element("Tagging")
    tagset_el = SubElement(root, "TagSet")
    for tag in tags:
        tag_el = SubElement(tagset_el, "Tag")
        SubElement(tag_el, "Key").text = tag.get("Key", "")
        SubElement(tag_el, "Value").text = tag.get("Value", "")
    return root


def _parse_cors_document(payload: bytes) -> list[dict[str, Any]]:
    try:
        root = fromstring(payload)
    except ParseError as exc:
        raise ValueError("Malformed XML") from exc
    if _strip_ns(root.tag) != "CORSConfiguration":
        raise ValueError("Root element must be CORSConfiguration")
    rules: list[dict[str, Any]] = []
    for rule_el in list(root):
        if _strip_ns(rule_el.tag) != "CORSRule":
            continue
        rule: dict[str, Any] = {
            "AllowedOrigins": [],
            "AllowedMethods": [],
            "AllowedHeaders": [],
            "ExposeHeaders": [],
        }
        for child in list(rule_el):
            name = _strip_ns(child.tag)
            if name == "AllowedOrigin":
                rule["AllowedOrigins"].append((child.text or ""))
            elif name == "AllowedMethod":
                rule["AllowedMethods"].append((child.text or ""))
            elif name == "AllowedHeader":
                rule["AllowedHeaders"].append((child.text or ""))
            elif name == "ExposeHeader":
                rule["ExposeHeaders"].append((child.text or ""))
            elif name == "MaxAgeSeconds":
                try:
                    rule["MaxAgeSeconds"] = int(child.text or 0)
                except ValueError:
                    raise ValueError("MaxAgeSeconds must be an integer") from None
        rules.append(rule)
    return rules


def _render_cors_document(rules: list[dict[str, Any]]) -> Element:
    root = Element("CORSConfiguration")
    for rule in rules:
        rule_el = SubElement(root, "CORSRule")
        for origin in rule.get("AllowedOrigins", []):
            SubElement(rule_el, "AllowedOrigin").text = origin
        for method in rule.get("AllowedMethods", []):
            SubElement(rule_el, "AllowedMethod").text = method
        for header in rule.get("AllowedHeaders", []):
            SubElement(rule_el, "AllowedHeader").text = header
        for header in rule.get("ExposeHeaders", []):
            SubElement(rule_el, "ExposeHeader").text = header
        if "MaxAgeSeconds" in rule and rule["MaxAgeSeconds"] is not None:
            SubElement(rule_el, "MaxAgeSeconds").text = str(rule["MaxAgeSeconds"])
    return root


def _parse_encryption_document(payload: bytes) -> dict[str, Any]:
    try:
        root = fromstring(payload)
    except ParseError as exc:
        raise ValueError("Malformed XML") from exc
    if _strip_ns(root.tag) != "ServerSideEncryptionConfiguration":
        raise ValueError("Root element must be ServerSideEncryptionConfiguration")
    rules: list[dict[str, Any]] = []
    for rule_el in list(root):
        if _strip_ns(rule_el.tag) != "Rule":
            continue
        default_el = None
        bucket_key_el = None
        for child in list(rule_el):
            name = _strip_ns(child.tag)
            if name == "ApplyServerSideEncryptionByDefault":
                default_el = child
            elif name == "BucketKeyEnabled":
                bucket_key_el = child
        if default_el is None:
            continue
        algo_el = default_el.find("{*}SSEAlgorithm")
        if algo_el is None:
            algo_el = default_el.find("SSEAlgorithm")
        if algo_el is None or not (algo_el.text or "").strip():
            raise ValueError("SSEAlgorithm is required")
        rule: dict[str, Any] = {"SSEAlgorithm": algo_el.text.strip()}
        kms_el = default_el.find("{*}KMSMasterKeyID")
        if kms_el is None:
            kms_el = default_el.find("KMSMasterKeyID")
        if kms_el is not None and kms_el.text:
            rule["KMSMasterKeyID"] = kms_el.text.strip()
        if bucket_key_el is not None and bucket_key_el.text:
            rule["BucketKeyEnabled"] = bucket_key_el.text.strip().lower() in {"true", "1"}
        rules.append(rule)
    if not rules:
        raise ValueError("At least one Rule is required")
    return {"Rules": rules}


def _render_encryption_document(config: dict[str, Any]) -> Element:
    root = Element("ServerSideEncryptionConfiguration")
    for rule in config.get("Rules", []):
        rule_el = SubElement(root, "Rule")
        default_el = SubElement(rule_el, "ApplyServerSideEncryptionByDefault")
        SubElement(default_el, "SSEAlgorithm").text = rule.get("SSEAlgorithm", "")
        if rule.get("KMSMasterKeyID"):
            SubElement(default_el, "KMSMasterKeyID").text = rule["KMSMasterKeyID"]
        if "BucketKeyEnabled" in rule:
            SubElement(rule_el, "BucketKeyEnabled").text = "true" if rule["BucketKeyEnabled"] else "false"
    return root


def _stream_file(path, chunk_size: int = 64 * 1024):
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def _method_not_allowed(allowed: list[str]) -> Response:
    response = _error_response(
        "MethodNotAllowed",
        "The specified method is not allowed for this resource",
        405,
    )
    response.headers["Allow"] = ", ".join(sorted({method.upper() for method in allowed}))
    return response


def _apply_object_headers(
    response: Response,
    *,
    file_stat,
    metadata: Dict[str, str] | None,
    etag: str,
) -> None:
    response.headers["Content-Length"] = str(file_stat.st_size)
    response.headers["Last-Modified"] = http_date(file_stat.st_mtime)
    response.headers["ETag"] = f'"{etag}"'
    response.headers["Accept-Ranges"] = "bytes"
    for key, value in (metadata or {}).items():
        response.headers[f"X-Amz-Meta-{key}"] = value


def _maybe_handle_bucket_subresource(bucket_name: str) -> Response | None:
    handlers = {
        "versioning": _bucket_versioning_handler,
        "tagging": _bucket_tagging_handler,
        "cors": _bucket_cors_handler,
        "encryption": _bucket_encryption_handler,
    }
    requested = [key for key in handlers if key in request.args]
    if not requested:
        return None
    if len(requested) > 1:
        return _error_response(
            "InvalidRequest",
            "Only a single bucket subresource can be requested at a time",
            400,
        )
    handler = handlers[requested[0]]
    return handler(bucket_name)


def _bucket_versioning_handler(bucket_name: str) -> Response:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "policy")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    try:
        enabled = storage.is_versioning_enabled(bucket_name)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    root = Element("VersioningConfiguration")
    SubElement(root, "Status").text = "Enabled" if enabled else "Suspended"
    return _xml_response(root)


def _bucket_tagging_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "policy")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if request.method == "GET":
        try:
            tags = storage.get_bucket_tags(bucket_name)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        if not tags:
            return _error_response("NoSuchTagSet", "No tags are configured for this bucket", 404)
        return _xml_response(_render_tagging_document(tags))
    payload = request.get_data(cache=False) or b""
    try:
        tags = _parse_tagging_document(payload)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    if len(tags) > 50:
        return _error_response("InvalidTag", "A maximum of 50 tags is supported", 400)
    try:
        storage.set_bucket_tags(bucket_name, tags)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    current_app.logger.info("Bucket tags updated", extra={"bucket": bucket_name, "tags": len(tags)})
    return Response(status=204)


def _sanitize_cors_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for rule in rules:
        allowed_origins = [origin.strip() for origin in rule.get("AllowedOrigins", []) if origin and origin.strip()]
        allowed_methods = [method.strip().upper() for method in rule.get("AllowedMethods", []) if method and method.strip()]
        allowed_headers = [header.strip() for header in rule.get("AllowedHeaders", []) if header and header.strip()]
        expose_headers = [header.strip() for header in rule.get("ExposeHeaders", []) if header and header.strip()]
        if not allowed_origins or not allowed_methods:
            raise ValueError("Each CORSRule must include AllowedOrigin and AllowedMethod entries")
        sanitized_rule: dict[str, Any] = {
            "AllowedOrigins": allowed_origins,
            "AllowedMethods": allowed_methods,
        }
        if allowed_headers:
            sanitized_rule["AllowedHeaders"] = allowed_headers
        if expose_headers:
            sanitized_rule["ExposeHeaders"] = expose_headers
        if "MaxAgeSeconds" in rule and rule["MaxAgeSeconds"] is not None:
            sanitized_rule["MaxAgeSeconds"] = int(rule["MaxAgeSeconds"])
        sanitized.append(sanitized_rule)
    return sanitized


def _bucket_cors_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "policy")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if request.method == "GET":
        try:
            rules = storage.get_bucket_cors(bucket_name)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        if not rules:
            return _error_response("NoSuchCORSConfiguration", "No CORS configuration found", 404)
        return _xml_response(_render_cors_document(rules))
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        try:
            storage.set_bucket_cors(bucket_name, None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket CORS cleared", extra={"bucket": bucket_name})
        return Response(status=204)
    try:
        rules = _parse_cors_document(payload)
        sanitized = _sanitize_cors_rules(rules)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    if not sanitized:
        return _error_response("InvalidRequest", "At least one CORSRule must be supplied", 400)
    try:
        storage.set_bucket_cors(bucket_name, sanitized)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    current_app.logger.info("Bucket CORS updated", extra={"bucket": bucket_name, "rules": len(sanitized)})
    return Response(status=204)


def _bucket_encryption_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "policy")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if request.method == "GET":
        try:
            config = storage.get_bucket_encryption(bucket_name)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        if not config:
            return _error_response(
                "ServerSideEncryptionConfigurationNotFoundError",
                "No server-side encryption configuration found",
                404,
            )
        return _xml_response(_render_encryption_document(config))
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        try:
            storage.set_bucket_encryption(bucket_name, None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket encryption cleared", extra={"bucket": bucket_name})
        return Response(status=204)
    try:
        config = _parse_encryption_document(payload)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    try:
        storage.set_bucket_encryption(bucket_name, config)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    current_app.logger.info("Bucket encryption updated", extra={"bucket": bucket_name})
    return Response(status=204)


def _bulk_delete_handler(bucket_name: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "delete")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body must include a Delete specification", 400)
    try:
        root = fromstring(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)
    if _strip_ns(root.tag) != "Delete":
        return _error_response("MalformedXML", "Root element must be Delete", 400)

    quiet = False
    objects: list[dict[str, str | None]] = []
    for child in list(root):
        name = _strip_ns(child.tag)
        if name == "Quiet":
            quiet = (child.text or "").strip().lower() in {"true", "1"}
            continue
        if name != "Object":
            continue
        key_text = ""
        version_text: str | None = None
        for entry in list(child):
            entry_name = _strip_ns(entry.tag)
            if entry_name == "Key":
                key_text = (entry.text or "").strip()
            elif entry_name == "VersionId":
                version_text = (entry.text or "").strip() or None
        if not key_text:
            continue
        objects.append({"Key": key_text, "VersionId": version_text})

    if not objects:
        return _error_response("MalformedXML", "At least one Object entry is required", 400)
    if len(objects) > 1000:
        return _error_response("MalformedXML", "A maximum of 1000 objects can be deleted per request", 400)

    storage = _storage()
    deleted: list[str] = []
    errors: list[dict[str, str]] = []
    for entry in objects:
        key = entry["Key"] or ""
        version_id = entry.get("VersionId")
        if version_id:
            errors.append({
                "Key": key,
                "Code": "InvalidRequest",
                "Message": "VersionId is not supported for bulk deletes",
            })
            continue
        try:
            storage.delete_object(bucket_name, key)
            deleted.append(key)
        except StorageError as exc:
            errors.append({"Key": key, "Code": "InvalidRequest", "Message": str(exc)})

    result = Element("DeleteResult")
    if not quiet:
        for key in deleted:
            deleted_el = SubElement(result, "Deleted")
            SubElement(deleted_el, "Key").text = key
    for err in errors:
        error_el = SubElement(result, "Error")
        SubElement(error_el, "Key").text = err.get("Key", "")
        SubElement(error_el, "Code").text = err.get("Code", "InvalidRequest")
        SubElement(error_el, "Message").text = err.get("Message", "Request failed")

    current_app.logger.info(
        "Bulk object delete",
        extra={"bucket": bucket_name, "deleted": len(deleted), "errors": len(errors)},
    )
    return _xml_response(result, status=200)


# ---------------------- routes ----------------------
@s3_api_bp.get("/")
@limiter.limit("60 per minute")
def list_buckets() -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, None, "list")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    root = Element("ListAllMyBucketsResult")
    owner = SubElement(root, "Owner")
    SubElement(owner, "ID").text = principal.access_key
    SubElement(owner, "DisplayName").text = principal.display_name
    buckets_el = SubElement(root, "Buckets")

    storage_buckets = _storage().list_buckets()
    allowed = set(_iam().buckets_for_principal(principal, [b.name for b in storage_buckets]))
    for bucket in storage_buckets:
        if bucket.name not in allowed:
            continue
        bucket_el = SubElement(buckets_el, "Bucket")
        SubElement(bucket_el, "Name").text = bucket.name
        SubElement(bucket_el, "CreationDate").text = bucket.created_at.isoformat()

    return _xml_response(root)


@s3_api_bp.route("/<bucket_name>", methods=["PUT", "DELETE", "GET", "POST"], strict_slashes=False)
@limiter.limit("120 per minute")
def bucket_handler(bucket_name: str) -> Response:
    storage = _storage()
    subresource_response = _maybe_handle_bucket_subresource(bucket_name)
    if subresource_response is not None:
        return subresource_response

    if request.method == "POST":
        if "delete" not in request.args:
            return _method_not_allowed(["GET", "PUT", "DELETE"])
        return _bulk_delete_handler(bucket_name)

    if request.method == "PUT":
        principal, error = _require_principal()
        if error:
            return error
        try:
            _authorize_action(principal, bucket_name, "write")
        except IamError as exc:
            return _error_response("AccessDenied", str(exc), 403)
        try:
            storage.create_bucket(bucket_name)
        except FileExistsError:
            return _error_response("BucketAlreadyExists", "Bucket exists", 409)
        except StorageError as exc:
            return _error_response("InvalidBucketName", str(exc), 400)
        current_app.logger.info("Bucket created", extra={"bucket": bucket_name})
        return Response(status=200)

    if request.method == "DELETE":
        principal, error = _require_principal()
        if error:
            return error
        try:
            _authorize_action(principal, bucket_name, "delete")
        except IamError as exc:
            return _error_response("AccessDenied", str(exc), 403)
        try:
            storage.delete_bucket(bucket_name)
            _bucket_policies().delete_policy(bucket_name)
            _replication_manager().delete_rule(bucket_name)
        except StorageError as exc:
            code = "BucketNotEmpty" if "not empty" in str(exc) else "NoSuchBucket"
            status = 409 if code == "BucketNotEmpty" else 404
            return _error_response(code, str(exc), status)
        current_app.logger.info("Bucket deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    # GET - list objects
    principal, error = _require_principal()
    try:
        _authorize_action(principal, bucket_name, "list")
    except IamError as exc:
        if error:
            return error
        return _error_response("AccessDenied", str(exc), 403)
    try:
        objects = storage.list_objects(bucket_name)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)

    root = Element("ListBucketResult")
    SubElement(root, "Name").text = bucket_name
    SubElement(root, "MaxKeys").text = str(current_app.config["UI_PAGE_SIZE"])
    SubElement(root, "IsTruncated").text = "false"
    for meta in objects:
        obj_el = SubElement(root, "Contents")
        SubElement(obj_el, "Key").text = meta.key
        SubElement(obj_el, "LastModified").text = meta.last_modified.isoformat()
        SubElement(obj_el, "ETag").text = f'"{meta.etag}"'
        SubElement(obj_el, "Size").text = str(meta.size)

    return _xml_response(root)


@s3_api_bp.route("/<bucket_name>/<path:object_key>", methods=["PUT", "GET", "DELETE", "HEAD", "POST"], strict_slashes=False)
@limiter.limit("240 per minute")
def object_handler(bucket_name: str, object_key: str):
    storage = _storage()

    # Multipart Uploads
    if request.method == "POST":
        if "uploads" in request.args:
            return _initiate_multipart_upload(bucket_name, object_key)
        if "uploadId" in request.args:
            return _complete_multipart_upload(bucket_name, object_key)
        return _method_not_allowed(["GET", "PUT", "DELETE", "HEAD", "POST"])

    if request.method == "PUT":
        if "partNumber" in request.args and "uploadId" in request.args:
            return _upload_part(bucket_name, object_key)

        _, error = _object_principal("write", bucket_name, object_key)
        if error:
            return error
        
        stream = request.stream
        content_encoding = request.headers.get("Content-Encoding", "").lower()
        if "aws-chunked" in content_encoding:
            stream = AwsChunkedDecoder(stream)

        metadata = _extract_request_metadata()
        try:
            meta = storage.put_object(
                bucket_name,
                object_key,
                stream,
                metadata=metadata or None,
            )
        except StorageError as exc:
            message = str(exc)
            if "Bucket" in message:
                return _error_response("NoSuchBucket", message, 404)
            return _error_response("InvalidArgument", message, 400)
        current_app.logger.info(
            "Object uploaded",
            extra={"bucket": bucket_name, "key": object_key, "size": meta.size},
        )
        response = Response(status=200)
        response.headers["ETag"] = f'"{meta.etag}"'
        
        # Trigger replication if not a replication request
        user_agent = request.headers.get("User-Agent", "")
        if "S3ReplicationAgent" not in user_agent:
            _replication_manager().trigger_replication(bucket_name, object_key, action="write")
            
        return response

    if request.method in {"GET", "HEAD"}:
        if request.method == "GET" and "uploadId" in request.args:
            return _list_parts(bucket_name, object_key)

        _, error = _object_principal("read", bucket_name, object_key)
        if error:
            return error
        try:
            path = storage.get_object_path(bucket_name, object_key)
        except StorageError as exc:
            return _error_response("NoSuchKey", str(exc), 404)
        metadata = storage.get_object_metadata(bucket_name, object_key)
        stat = path.stat()
        mimetype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        etag = storage._compute_etag(path)

        if request.method == "GET":
            response = Response(_stream_file(path), mimetype=mimetype, direct_passthrough=True)
            logged_bytes = stat.st_size
        else:
            response = Response(status=200)
            response.headers["Content-Type"] = mimetype
            logged_bytes = 0

        _apply_object_headers(response, file_stat=stat, metadata=metadata, etag=etag)
        action = "Object read" if request.method == "GET" else "Object head"
        current_app.logger.info(action, extra={"bucket": bucket_name, "key": object_key, "bytes": logged_bytes})
        return response

    if "uploadId" in request.args:
        return _abort_multipart_upload(bucket_name, object_key)

    _, error = _object_principal("delete", bucket_name, object_key)
    if error:
        return error
    storage.delete_object(bucket_name, object_key)
    current_app.logger.info("Object deleted", extra={"bucket": bucket_name, "key": object_key})
    
    # Trigger replication if not a replication request
    user_agent = request.headers.get("User-Agent", "")
    if "S3ReplicationAgent" not in user_agent:
        _replication_manager().trigger_replication(bucket_name, object_key, action="delete")
        
    return Response(status=204)


def _list_parts(bucket_name: str, object_key: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "read", object_key=object_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    upload_id = request.args.get("uploadId")
    if not upload_id:
        return _error_response("InvalidArgument", "uploadId is required", 400)

    try:
        parts = _storage().list_multipart_parts(bucket_name, upload_id)
    except StorageError as exc:
        return _error_response("NoSuchUpload", str(exc), 404)

    root = Element("ListPartsResult")
    SubElement(root, "Bucket").text = bucket_name
    SubElement(root, "Key").text = object_key
    SubElement(root, "UploadId").text = upload_id
    
    initiator = SubElement(root, "Initiator")
    SubElement(initiator, "ID").text = principal.access_key
    SubElement(initiator, "DisplayName").text = principal.display_name
    
    owner = SubElement(root, "Owner")
    SubElement(owner, "ID").text = principal.access_key
    SubElement(owner, "DisplayName").text = principal.display_name
    
    SubElement(root, "StorageClass").text = "STANDARD"
    SubElement(root, "PartNumberMarker").text = "0"
    SubElement(root, "NextPartNumberMarker").text = str(parts[-1]["PartNumber"]) if parts else "0"
    SubElement(root, "MaxParts").text = "1000"
    SubElement(root, "IsTruncated").text = "false"

    for part in parts:
        p = SubElement(root, "Part")
        SubElement(p, "PartNumber").text = str(part["PartNumber"])
        SubElement(p, "LastModified").text = part["LastModified"].isoformat()
        SubElement(p, "ETag").text = f'"{part["ETag"]}"'
        SubElement(p, "Size").text = str(part["Size"])

    return _xml_response(root)


@s3_api_bp.route("/bucket-policy/<bucket_name>", methods=["GET", "PUT", "DELETE"])
@limiter.limit("30 per minute")
def bucket_policy_handler(bucket_name: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "policy")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    store = _bucket_policies()
    if request.method == "GET":
        policy = store.get_policy(bucket_name)
        if not policy:
            return _error_response("NoSuchBucketPolicy", "No bucket policy attached", 404)
        return jsonify(policy)
    if request.method == "DELETE":
        store.delete_policy(bucket_name)
        current_app.logger.info("Bucket policy removed", extra={"bucket": bucket_name})
        return Response(status=204)
    payload = request.get_json(silent=True)
    if not payload:
        return _error_response("MalformedPolicy", "Policy document must be JSON", 400)
    try:
        store.set_policy(bucket_name, payload)
        current_app.logger.info("Bucket policy updated", extra={"bucket": bucket_name})
    except ValueError as exc:
        return _error_response("MalformedPolicy", str(exc), 400)
    return Response(status=204)


@s3_api_bp.post("/presign/<bucket_name>/<path:object_key>")
@limiter.limit("45 per minute")
def presign_object(bucket_name: str, object_key: str):
    payload = request.get_json(silent=True) or {}
    method = str(payload.get("method", "GET")).upper()
    allowed_methods = {"GET", "PUT", "DELETE"}
    if method not in allowed_methods:
        return _error_response("InvalidRequest", "Method must be GET, PUT, or DELETE", 400)
    try:
        expires = int(payload.get("expires_in", 900))
    except (TypeError, ValueError):
        return _error_response("InvalidRequest", "expires_in must be an integer", 400)
    expires = max(1, min(expires, 7 * 24 * 3600))
    action = "read" if method == "GET" else ("delete" if method == "DELETE" else "write")
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, action, object_key=object_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    if action != "write":
        try:
            storage.get_object_path(bucket_name, object_key)
        except StorageError:
            return _error_response("NoSuchKey", "Object not found", 404)
    secret = _iam().secret_for_key(principal.access_key)
    url = _generate_presigned_url(
        principal=principal,
        secret_key=secret,
        method=method,
        bucket_name=bucket_name,
        object_key=object_key,
        expires_in=expires,
    )
    current_app.logger.info(
        "Presigned URL generated",
        extra={"bucket": bucket_name, "key": object_key, "method": method},
    )
    return jsonify({"url": url, "method": method, "expires_in": expires})


@s3_api_bp.route("/<bucket_name>", methods=["HEAD"])
@limiter.limit("100 per minute")
def head_bucket(bucket_name: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "list")
        if not _storage().bucket_exists(bucket_name):
            return _error_response("NoSuchBucket", "Bucket not found", 404)
        return Response(status=200)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)


@s3_api_bp.route("/<bucket_name>/<path:object_key>", methods=["HEAD"])
@limiter.limit("100 per minute")
def head_object(bucket_name: str, object_key: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "read", object_key=object_key)
        path = _storage().get_object_path(bucket_name, object_key)
        metadata = _storage().get_object_metadata(bucket_name, object_key)
        stat = path.stat()
        etag = _storage()._compute_etag(path)
        
        response = Response(status=200)
        _apply_object_headers(response, file_stat=stat, metadata=metadata, etag=etag)
        response.headers["Content-Type"] = mimetypes.guess_type(object_key)[0] or "application/octet-stream"
        return response
    except (StorageError, FileNotFoundError):
        return _error_response("NoSuchKey", "Object not found", 404)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)


class AwsChunkedDecoder:
    """Decodes aws-chunked encoded streams."""
    def __init__(self, stream):
        self.stream = stream
        self.buffer = b""
        self.chunk_remaining = 0
        self.finished = False

    def read(self, size=-1):
        if self.finished:
            return b""

        result = b""
        while size == -1 or len(result) < size:
            if self.chunk_remaining > 0:
                to_read = self.chunk_remaining
                if size != -1:
                    to_read = min(to_read, size - len(result))
                
                chunk = self.stream.read(to_read)
                if not chunk:
                    raise IOError("Unexpected EOF in chunk data")
                
                result += chunk
                self.chunk_remaining -= len(chunk)
                
                if self.chunk_remaining == 0:
                    # Read CRLF after chunk data
                    crlf = self.stream.read(2)
                    if crlf != b"\r\n":
                        raise IOError("Malformed chunk: missing CRLF")
            else:
                # Read chunk size line
                line = b""
                while True:
                    char = self.stream.read(1)
                    if not char:
                        if not line: # EOF at start of chunk size
                            self.finished = True
                            return result
                        raise IOError("Unexpected EOF in chunk size")
                    line += char
                    if line.endswith(b"\r\n"):
                        break
                
                # Parse chunk size (hex)
                try:
                    line_str = line.decode("ascii").strip()
                    # Handle chunk-signature extension if present (e.g. "1000;chunk-signature=...")
                    if ";" in line_str:
                        line_str = line_str.split(";")[0]
                    chunk_size = int(line_str, 16)
                except ValueError:
                    raise IOError(f"Invalid chunk size: {line}")

                if chunk_size == 0:
                    self.finished = True
                    # Read trailers if any (until empty line)
                    while True:
                        line = b""
                        while True:
                            char = self.stream.read(1)
                            if not char:
                                break
                            line += char
                            if line.endswith(b"\r\n"):
                                break
                        if line == b"\r\n" or not line:
                            break
                    return result
                
                self.chunk_remaining = chunk_size
        
        return result


def _initiate_multipart_upload(bucket_name: str, object_key: str) -> Response:
    principal, error = _object_principal("write", bucket_name, object_key)
    if error:
        return error
    
    metadata = _extract_request_metadata()
    try:
        upload_id = _storage().initiate_multipart_upload(
            bucket_name, 
            object_key, 
            metadata=metadata or None
        )
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)

    root = Element("InitiateMultipartUploadResult")
    SubElement(root, "Bucket").text = bucket_name
    SubElement(root, "Key").text = object_key
    SubElement(root, "UploadId").text = upload_id
    return _xml_response(root)


def _upload_part(bucket_name: str, object_key: str) -> Response:
    principal, error = _object_principal("write", bucket_name, object_key)
    if error:
        return error

    upload_id = request.args.get("uploadId")
    part_number_str = request.args.get("partNumber")
    if not upload_id or not part_number_str:
        return _error_response("InvalidArgument", "uploadId and partNumber are required", 400)
    
    try:
        part_number = int(part_number_str)
    except ValueError:
        return _error_response("InvalidArgument", "partNumber must be an integer", 400)

    stream = request.stream
    content_encoding = request.headers.get("Content-Encoding", "").lower()
    if "aws-chunked" in content_encoding:
        stream = AwsChunkedDecoder(stream)

    try:
        etag = _storage().upload_multipart_part(bucket_name, upload_id, part_number, stream)
    except StorageError as exc:
        if "NoSuchBucket" in str(exc):
            return _error_response("NoSuchBucket", str(exc), 404)
        if "Multipart upload not found" in str(exc):
            return _error_response("NoSuchUpload", str(exc), 404)
        return _error_response("InvalidArgument", str(exc), 400)

    response = Response(status=200)
    response.headers["ETag"] = f'"{etag}"'
    return response


def _complete_multipart_upload(bucket_name: str, object_key: str) -> Response:
    principal, error = _object_principal("write", bucket_name, object_key)
    if error:
        return error

    upload_id = request.args.get("uploadId")
    if not upload_id:
        return _error_response("InvalidArgument", "uploadId is required", 400)

    payload = request.get_data(cache=False) or b""
    try:
        root = fromstring(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)
    
    if _strip_ns(root.tag) != "CompleteMultipartUpload":
        return _error_response("MalformedXML", "Root element must be CompleteMultipartUpload", 400)

    parts = []
    for part_el in list(root):
        if _strip_ns(part_el.tag) != "Part":
            continue
        part_number_el = part_el.find("{*}PartNumber")
        if part_number_el is None:
            part_number_el = part_el.find("PartNumber")
        
        etag_el = part_el.find("{*}ETag")
        if etag_el is None:
            etag_el = part_el.find("ETag")
            
        if part_number_el is not None and etag_el is not None:
            parts.append({
                "PartNumber": int(part_number_el.text or 0),
                "ETag": (etag_el.text or "").strip('"')
            })

    try:
        meta = _storage().complete_multipart_upload(bucket_name, upload_id, parts)
    except StorageError as exc:
        if "NoSuchBucket" in str(exc):
            return _error_response("NoSuchBucket", str(exc), 404)
        if "Multipart upload not found" in str(exc):
            return _error_response("NoSuchUpload", str(exc), 404)
        return _error_response("InvalidPart", str(exc), 400)

    # Trigger replication
    user_agent = request.headers.get("User-Agent", "")
    if "S3ReplicationAgent" not in user_agent:
        _replication_manager().trigger_replication(bucket_name, object_key, action="write")

    root = Element("CompleteMultipartUploadResult")
    # Use request.host_url to construct full location
    location = f"{request.host_url}{bucket_name}/{object_key}"
    SubElement(root, "Location").text = location
    SubElement(root, "Bucket").text = bucket_name
    SubElement(root, "Key").text = object_key
    SubElement(root, "ETag").text = f'"{meta.etag}"'
    
    return _xml_response(root)


def _abort_multipart_upload(bucket_name: str, object_key: str) -> Response:
    principal, error = _object_principal("delete", bucket_name, object_key)
    if error:
        return error

    upload_id = request.args.get("uploadId")
    if not upload_id:
        return _error_response("InvalidArgument", "uploadId is required", 400)

    try:
        _storage().abort_multipart_upload(bucket_name, upload_id)
    except StorageError as exc:
        # Abort is idempotent, but if bucket missing...
        if "Bucket does not exist" in str(exc):
            return _error_response("NoSuchBucket", str(exc), 404)
            
    return Response(status=204)


@s3_api_bp.before_request
def resolve_principal():
    g.principal = None
    # Try SigV4
    try:
        if ("Authorization" in request.headers and request.headers["Authorization"].startswith("AWS4-HMAC-SHA256")) or \
           (request.args.get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"):
            g.principal = _verify_sigv4(request)
            return
    except Exception:
        pass
    
    # Try simple auth headers (internal/testing)
    access_key = request.headers.get("X-Access-Key")
    secret_key = request.headers.get("X-Secret-Key")
    if access_key and secret_key:
        try:
            g.principal = _iam().authenticate(access_key, secret_key)
        except Exception:
            pass
