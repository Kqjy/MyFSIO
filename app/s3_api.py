from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import mimetypes
import re
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlencode, urlparse, unquote
from xml.etree.ElementTree import Element, SubElement, tostring, ParseError
from defusedxml.ElementTree import fromstring

try:
    import myfsio_core as _rc
    if not all(hasattr(_rc, f) for f in (
        "verify_sigv4_signature", "derive_signing_key", "clear_signing_key_cache",
    )):
        raise ImportError("myfsio_core is outdated, rebuild with: cd myfsio_core && maturin develop --release")
    _HAS_RUST = True
except ImportError:
    _rc = None
    _HAS_RUST = False

from flask import Blueprint, Response, current_app, jsonify, request, g
from werkzeug.http import http_date

from .access_logging import AccessLoggingService, LoggingConfiguration
from .acl import AclService
from .bucket_policies import BucketPolicyStore
from .encryption import SSECEncryption, SSECMetadata, EncryptionError
from .extensions import limiter
from .iam import IamError, Principal
from .notifications import NotificationService, NotificationConfiguration, WebhookDestination
from .object_lock import ObjectLockService, ObjectLockRetention, ObjectLockConfig, ObjectLockError, RetentionMode
from .replication import ReplicationManager
from .storage import ObjectStorage, StorageError, QuotaExceededError, BucketNotFoundError, ObjectNotFoundError

logger = logging.getLogger(__name__)

S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"

_HEADER_CONTROL_CHARS = re.compile(r'[\r\n\x00-\x1f\x7f]')


def _sanitize_header_value(value: str) -> str:
    return _HEADER_CONTROL_CHARS.sub('', value)


MAX_XML_PAYLOAD_SIZE = 1048576  # 1 MB


def _parse_xml_with_limit(payload: bytes) -> Element:
    """Parse XML payload with size limit to prevent DoS attacks."""
    max_size = current_app.config.get("MAX_XML_PAYLOAD_SIZE", MAX_XML_PAYLOAD_SIZE)
    if len(payload) > max_size:
        raise ParseError(f"XML payload exceeds maximum size of {max_size} bytes")
    return fromstring(payload)


s3_api_bp = Blueprint("s3_api", __name__)

def _storage() -> ObjectStorage:
    return current_app.extensions["object_storage"]


def _acl() -> AclService:
    return current_app.extensions["acl"]


def _iam():
    return current_app.extensions["iam"]


def _replication_manager() -> ReplicationManager:
    return current_app.extensions["replication"]


def _bucket_policies() -> BucketPolicyStore:
    store: BucketPolicyStore = current_app.extensions["bucket_policies"]
    store.maybe_reload()
    return store


def _build_policy_context() -> Dict[str, Any]:
    cached = getattr(g, "_policy_context", None)
    if cached is not None:
        return cached
    ctx: Dict[str, Any] = {}
    if request.headers.get("Referer"):
        ctx["aws:Referer"] = request.headers.get("Referer")
    num_proxies = current_app.config.get("NUM_TRUSTED_PROXIES", 0)
    if num_proxies > 0 and request.access_route and len(request.access_route) > num_proxies:
        ctx["aws:SourceIp"] = request.access_route[-num_proxies]
    elif request.remote_addr:
        ctx["aws:SourceIp"] = request.remote_addr
    elif request.access_route:
        ctx["aws:SourceIp"] = request.access_route[0]
    ctx["aws:SecureTransport"] = str(request.is_secure).lower()
    if request.headers.get("User-Agent"):
        ctx["aws:UserAgent"] = request.headers.get("User-Agent")
    g._policy_context = ctx
    return ctx


def _object_lock() -> ObjectLockService:
    return current_app.extensions["object_lock"]


def _notifications() -> NotificationService:
    return current_app.extensions["notifications"]


def _access_logging() -> AccessLoggingService:
    return current_app.extensions["access_logging"]


def _get_list_buckets_limit() -> str:
    return current_app.config.get("RATELIMIT_LIST_BUCKETS", "60 per minute")


def _get_bucket_ops_limit() -> str:
    return current_app.config.get("RATELIMIT_BUCKET_OPS", "120 per minute")


def _get_object_ops_limit() -> str:
    return current_app.config.get("RATELIMIT_OBJECT_OPS", "240 per minute")


def _get_head_ops_limit() -> str:
    return current_app.config.get("RATELIMIT_HEAD_OPS", "100 per minute")


def _xml_response(element: Element, status: int = 200) -> Response:
    xml_bytes = tostring(element, encoding="utf-8")
    return Response(xml_bytes, status=status, mimetype="application/xml")


def _error_response(code: str, message: str, status: int) -> Response:
    g.s3_error_code = code
    error = Element("Error")
    SubElement(error, "Code").text = code
    SubElement(error, "Message").text = message
    SubElement(error, "Resource").text = request.path
    SubElement(error, "RequestId").text = uuid.uuid4().hex
    return _xml_response(error, status)


def _require_xml_content_type() -> Response | None:
    ct = request.headers.get("Content-Type", "")
    if ct and not ct.startswith(("application/xml", "text/xml")):
        return _error_response("InvalidRequest", "Content-Type must be application/xml or text/xml", 400)
    return None


def _parse_range_header(range_header: str, file_size: int) -> list[tuple[int, int]] | None:
    if not range_header.startswith("bytes="):
        return None
    max_range_value = 2**63 - 1
    ranges = []
    range_spec = range_header[6:]
    for part in range_spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if part.startswith("-"):
                suffix_length = int(part[1:])
                if suffix_length <= 0 or suffix_length > max_range_value:
                    return None
                start = max(0, file_size - suffix_length)
                end = file_size - 1
            elif part.endswith("-"):
                start = int(part[:-1])
                if start < 0 or start > max_range_value or start >= file_size:
                    return None
                end = file_size - 1
            else:
                start_str, end_str = part.split("-", 1)
                start = int(start_str)
                end = int(end_str)
                if start < 0 or end < 0 or start > max_range_value or end > max_range_value:
                    return None
                if start > end or start >= file_size:
                    return None
                end = min(end, file_size - 1)
        except (ValueError, OverflowError):
            return None
        ranges.append((start, end))
    return ranges if ranges else None


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


_SIGNING_KEY_CACHE: OrderedDict[Tuple[str, str, str, str], Tuple[bytes, float]] = OrderedDict()
_SIGNING_KEY_CACHE_LOCK = threading.Lock()
_SIGNING_KEY_CACHE_TTL = 60.0
_SIGNING_KEY_CACHE_MAX_SIZE = 256

_SIGV4_HEADER_RE = re.compile(
    r"AWS4-HMAC-SHA256 Credential=([^/]+)/([^/]+)/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([^,]+), Signature=(.+)"
)
_SIGV4_REQUIRED_HEADERS = frozenset({'host', 'x-amz-date'})


def clear_signing_key_cache() -> None:
    if _HAS_RUST:
        _rc.clear_signing_key_cache()
    with _SIGNING_KEY_CACHE_LOCK:
        _SIGNING_KEY_CACHE.clear()


def _get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    if _HAS_RUST:
        return bytes(_rc.derive_signing_key(key, date_stamp, region_name, service_name))

    cache_key = (key, date_stamp, region_name, service_name)
    now = time.time()

    with _SIGNING_KEY_CACHE_LOCK:
        cached = _SIGNING_KEY_CACHE.get(cache_key)
        if cached:
            signing_key, cached_time = cached
            if now - cached_time < _SIGNING_KEY_CACHE_TTL:
                _SIGNING_KEY_CACHE.move_to_end(cache_key)
                return signing_key
            else:
                del _SIGNING_KEY_CACHE[cache_key]

    k_date = _sign(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, "aws4_request")

    with _SIGNING_KEY_CACHE_LOCK:
        if len(_SIGNING_KEY_CACHE) >= _SIGNING_KEY_CACHE_MAX_SIZE:
            _SIGNING_KEY_CACHE.popitem(last=False)
        _SIGNING_KEY_CACHE[cache_key] = (k_signing, now)

    return k_signing


def _get_canonical_uri(req: Any) -> str:
    """Get the canonical URI for SigV4 signature verification.
    
    AWS SigV4 requires the canonical URI to be URL-encoded exactly as the client
    sent it. Flask/Werkzeug automatically URL-decodes request.path, so we need
    to get the raw path from the environ.
    
    The canonical URI should have each path segment URL-encoded (with '/' preserved),
    and the encoding should match what the client used when signing.
    """
    raw_uri = req.environ.get('RAW_URI') or req.environ.get('REQUEST_URI')
    
    if raw_uri:
        path = raw_uri.split('?')[0]
        return path
    
    return quote(req.path, safe="/-_.~")


def _verify_sigv4_header(req: Any, auth_header: str) -> Principal | None:
    match = _SIGV4_HEADER_RE.match(auth_header)
    if not match:
        return None

    access_key, date_stamp, region, service, signed_headers_str, signature = match.groups()
    secret_key = _iam().get_secret_key(access_key)
    if not secret_key:
        raise IamError("SignatureDoesNotMatch")

    amz_date = req.headers.get("X-Amz-Date") or req.headers.get("Date")
    if not amz_date:
        raise IamError("Missing Date header")

    try:
        request_time = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise IamError("Invalid X-Amz-Date format")

    now = datetime.now(timezone.utc)
    time_diff = abs((now - request_time).total_seconds())
    tolerance = current_app.config.get("SIGV4_TIMESTAMP_TOLERANCE_SECONDS", 900)
    if time_diff > tolerance:
        raise IamError("Request timestamp too old or too far in the future")

    signed_headers_set = set(signed_headers_str.split(';'))
    if not _SIGV4_REQUIRED_HEADERS.issubset(signed_headers_set):
        if not ({'host', 'date'}.issubset(signed_headers_set)):
             raise IamError("Required headers not signed")

    canonical_uri = _get_canonical_uri(req)
    payload_hash = req.headers.get("X-Amz-Content-Sha256") or "UNSIGNED-PAYLOAD"

    if _HAS_RUST:
        query_params = list(req.args.items(multi=True))
        header_values = []
        for h in signed_headers_str.split(";"):
            val = req.headers.get(h) or ""
            if h.lower() == "expect" and val == "":
                val = "100-continue"
            header_values.append((h, val))
        if not _rc.verify_sigv4_signature(
            req.method, canonical_uri, query_params, signed_headers_str,
            header_values, payload_hash, amz_date, date_stamp, region,
            service, secret_key, signature,
        ):
            raise IamError("SignatureDoesNotMatch")
    else:
        method = req.method
        query_args = sorted(req.args.items(multi=True), key=lambda x: (x[0], x[1]))
        canonical_query_parts = []
        for k, v in query_args:
            canonical_query_parts.append(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}")
        canonical_query_string = "&".join(canonical_query_parts)

        signed_headers_list = signed_headers_str.split(";")
        canonical_headers_parts = []
        for header in signed_headers_list:
            header_val = req.headers.get(header)
            if header_val is None:
                 header_val = ""
            if header.lower() == 'expect' and header_val == "":
                header_val = "100-continue"
            header_val = " ".join(header_val.split())
            canonical_headers_parts.append(f"{header.lower()}:{header_val}\n")
        canonical_headers = "".join(canonical_headers_parts)

        canonical_request = f"{method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers_str}\n{payload_hash}"

        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        signing_key = _get_signature_key(secret_key, date_stamp, region, service)
        string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        calculated_signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_signature, signature):
            raise IamError("SignatureDoesNotMatch")

    session_token = req.headers.get("X-Amz-Security-Token")
    if session_token:
        if not _iam().validate_session_token(access_key, session_token):
            raise IamError("InvalidToken")

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
    tolerance = timedelta(seconds=current_app.config.get("SIGV4_TIMESTAMP_TOLERANCE_SECONDS", 900))
    if req_time > now + tolerance:
        raise IamError("Request date is too far in the future")
    try:
        expires_seconds = int(expires)
        if expires_seconds <= 0:
            raise IamError("Invalid Expires value: must be positive")
    except ValueError:
        raise IamError("Invalid Expires value: must be an integer")
    min_expiry = current_app.config.get("PRESIGNED_URL_MIN_EXPIRY_SECONDS", 1)
    max_expiry = current_app.config.get("PRESIGNED_URL_MAX_EXPIRY_SECONDS", 604800)
    if expires_seconds < min_expiry or expires_seconds > max_expiry:
        raise IamError(f"Expiration must be between {min_expiry} second(s) and {max_expiry} seconds")
    if now > req_time + timedelta(seconds=expires_seconds):
        raise IamError("Request expired")

    secret_key = _iam().get_secret_key(access_key)
    if not secret_key:
        raise IamError("Invalid access key")

    canonical_uri = _get_canonical_uri(req)

    if _HAS_RUST:
        query_params = [(k, v) for k, v in req.args.items(multi=True) if k != "X-Amz-Signature"]
        header_values = []
        for h in signed_headers_str.split(";"):
            val = req.headers.get(h) or ""
            if h.lower() == "expect" and val == "":
                val = "100-continue"
            header_values.append((h, val))
        if not _rc.verify_sigv4_signature(
            req.method, canonical_uri, query_params, signed_headers_str,
            header_values, "UNSIGNED-PAYLOAD", amz_date, date_stamp, region,
            service, secret_key, signature,
        ):
            raise IamError("SignatureDoesNotMatch")
    else:
        method = req.method
        query_args = []
        for key, value in req.args.items(multi=True):
            if key != "X-Amz-Signature":
                query_args.append((key, value))
        query_args.sort(key=lambda x: (x[0], x[1]))

        canonical_query_parts = []
        for k, v in query_args:
            canonical_query_parts.append(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}")
        canonical_query_string = "&".join(canonical_query_parts)

        signed_headers_list = signed_headers_str.split(";")
        canonical_headers_parts = []
        for header in signed_headers_list:
            val = req.headers.get(header, "").strip()
            if header.lower() == 'expect' and val == "":
                val = "100-continue"
            val = " ".join(val.split())
            canonical_headers_parts.append(f"{header.lower()}:{val}\n")
        canonical_headers = "".join(canonical_headers_parts)

        payload_hash = "UNSIGNED-PAYLOAD"

        canonical_request = "\n".join([
            method,
            canonical_uri,
            canonical_query_string,
            canonical_headers,
            signed_headers_str,
            payload_hash
        ])

        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        signing_key = _get_signature_key(secret_key, date_stamp, region, service)
        hashed_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashed_request}"
        calculated_signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calculated_signature, signature):
            raise IamError("SignatureDoesNotMatch")

    session_token = req.args.get("X-Amz-Security-Token")
    if session_token:
        if not _iam().validate_session_token(access_key, session_token):
            raise IamError("InvalidToken")

    return _iam().get_principal(access_key)


def _verify_sigv4(req: Any) -> Principal | None:
    auth_header = req.headers.get("Authorization")
    if auth_header and auth_header.startswith("AWS4-HMAC-SHA256"):
        return _verify_sigv4_header(req, auth_header)
    
    if req.args.get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256":
        return _verify_sigv4_query(req)
        
    return None


def _require_principal():
    sigv4_attempted = ("Authorization" in request.headers and request.headers["Authorization"].startswith("AWS4-HMAC-SHA256")) or \
                      (request.args.get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256")
    if sigv4_attempted:
        try:
            principal = _verify_sigv4(request)
            if principal:
                return principal, None
            return None, _error_response("AccessDenied", "Signature verification failed", 403)
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
            _iam().authorize(principal, bucket_name, action, object_key=object_key)
            iam_allowed = True
        except IamError as exc:
            iam_error = exc
    else:
        iam_error = IamError("Missing credentials")

    policy_decision = None
    access_key = principal.access_key if principal else None
    if bucket_name:
        policy_context = _build_policy_context()
        policy_decision = _bucket_policies().evaluate(access_key, bucket_name, object_key, action, policy_context)
        if policy_decision == "deny":
            raise IamError("Access denied by bucket policy")

    if iam_allowed:
        return
    if policy_decision == "allow":
        return

    acl_allowed = False
    if bucket_name:
        acl_service = _acl()
        acl_allowed = acl_service.evaluate_bucket_acl(
            bucket_name,
            access_key,
            action,
            is_authenticated=principal is not None,
        )
    if acl_allowed:
        return

    raise iam_error or IamError("Access denied")


def _object_principal(action: str, bucket_name: str, object_key: str):
    principal, error = _require_principal()
    try:
        _authorize_action(principal, bucket_name, action, object_key=object_key)
        return principal, None
    except IamError as exc:
        if not error:
            return None, _error_response("AccessDenied", str(exc), 403)
        return None, error


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
            if key and not (key.startswith("__") and key.endswith("__")):
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
    api_base_url: str | None = None,
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

    api_base = api_base_url or current_app.config.get("API_BASE_URL")
    if api_base:
        parsed = urlparse(api_base)
        host = parsed.netloc
        scheme = parsed.scheme
    else:
        host = request.host
        scheme = request.scheme or "http"

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


def _find_element(parent: Element, name: str) -> Optional[Element]:
    """Find a child element by name, trying S3 namespace then no namespace.

    This handles XML documents that may or may not include namespace prefixes.
    """
    el = parent.find(f"{{{S3_NS}}}{name}")
    if el is None:
        el = parent.find(name)
    return el


def _find_element_text(parent: Element, name: str, default: str = "") -> str:
    """Find a child element and return its text content.

    Returns the default value if element not found or has no text.
    """
    el = _find_element(parent, name)
    if el is None or el.text is None:
        return default
    return el.text.strip()


def _parse_tagging_document(payload: bytes) -> list[dict[str, str]]:
    try:
        root = _parse_xml_with_limit(payload)
    except ParseError as exc:
        raise ValueError("Malformed XML") from exc
    if _strip_ns(root.tag) != "Tagging":
        raise ValueError("Root element must be Tagging")
    tagset = root.find(".//{http://s3.amazonaws.com/doc/2006-03-01/}TagSet")
    if tagset is None:
        tagset = root.find("TagSet")
    if tagset is None:
        return []
    tags: list[dict[str, str]] = []
    for tag_el in list(tagset):
        if _strip_ns(tag_el.tag) != "Tag":
            continue
        key = _find_element_text(tag_el, "Key")
        if not key:
            continue
        value = _find_element_text(tag_el, "Value")
        tags.append({"Key": key, "Value": value})
    return tags


def _render_tagging_document(tags: list[dict[str, str]]) -> Element:
    root = Element("Tagging")
    tagset_el = SubElement(root, "TagSet")
    for tag in tags:
        tag_el = SubElement(tagset_el, "Tag")
        SubElement(tag_el, "Key").text = tag.get("Key", "")
        SubElement(tag_el, "Value").text = tag.get("Value", "")
    return root

DANGEROUS_CONTENT_TYPES = frozenset([
    "text/html",
    "application/xhtml+xml",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "text/ecmascript",
    "application/ecmascript",
    "image/svg+xml", 
])

SAFE_EXTENSION_MAP = {
    ".txt": ["text/plain"],
    ".json": ["application/json"],
    ".xml": ["application/xml", "text/xml"],
    ".csv": ["text/csv"],
    ".pdf": ["application/pdf"],
    ".png": ["image/png"],
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".gif": ["image/gif"],
    ".webp": ["image/webp"],
    ".mp4": ["video/mp4"],
    ".mp3": ["audio/mpeg"],
    ".zip": ["application/zip"],
    ".gz": ["application/gzip"],
    ".tar": ["application/x-tar"],
}


def _validate_content_type(object_key: str, content_type: str | None) -> str | None:
    """Validate Content-Type header for security.
    
    Returns an error message if validation fails, None otherwise.
    
    Rules:
    1. Block dangerous MIME types that can execute scripts (unless explicitly allowed)
    2. Warn if Content-Type doesn't match file extension (but don't block)
    """
    if not content_type:
        return None
    
    base_type = content_type.split(";")[0].strip().lower()
    
    if base_type in DANGEROUS_CONTENT_TYPES:
        ext = "." + object_key.rsplit(".", 1)[-1].lower() if "." in object_key else ""
        
        allowed_dangerous = {
            ".svg": "image/svg+xml",
            ".html": "text/html",
            ".htm": "text/html",
            ".xhtml": "application/xhtml+xml",
            ".js": "application/javascript",
            ".mjs": "application/javascript",
        }
        
        if ext in allowed_dangerous and base_type == allowed_dangerous[ext]:
            return None 
        
        return (
            f"Content-Type '{content_type}' is potentially dangerous and not allowed "
            f"for object key '{object_key}'. Use a safe Content-Type or rename the file "
            f"with an appropriate extension."
        )
    
    return None


def _parse_cors_document(payload: bytes) -> list[dict[str, Any]]:
    try:
        root = _parse_xml_with_limit(payload)
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
        root = _parse_xml_with_limit(payload)
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
        algo_el = default_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}SSEAlgorithm")
        if algo_el is None:
            algo_el = default_el.find("SSEAlgorithm")
        if algo_el is None or not (algo_el.text or "").strip():
            raise ValueError("SSEAlgorithm is required")
        rule: dict[str, Any] = {"SSEAlgorithm": algo_el.text.strip()}
        kms_el = default_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}KMSMasterKeyID")
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


def _stream_file(path, chunk_size: int = 1024 * 1024):
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


def _check_conditional_headers(etag: str, last_modified: float | None) -> Response | None:
    from email.utils import parsedate_to_datetime

    if_match = request.headers.get("If-Match")
    if if_match:
        if if_match.strip() != "*":
            match_etags = [e.strip().strip('"') for e in if_match.split(",")]
            if etag not in match_etags:
                return Response(status=412)

    if_unmodified = request.headers.get("If-Unmodified-Since")
    if not if_match and if_unmodified and last_modified is not None:
        try:
            dt = parsedate_to_datetime(if_unmodified)
            obj_dt = datetime.fromtimestamp(last_modified, timezone.utc)
            if obj_dt > dt:
                return Response(status=412)
        except (TypeError, ValueError):
            pass

    if_none_match = request.headers.get("If-None-Match")
    if if_none_match:
        if if_none_match.strip() == "*":
            resp = Response(status=304)
            resp.headers["ETag"] = f'"{etag}"'
            if last_modified is not None:
                resp.headers["Last-Modified"] = http_date(last_modified)
            return resp
        none_match_etags = [e.strip().strip('"') for e in if_none_match.split(",")]
        if etag in none_match_etags:
            resp = Response(status=304)
            resp.headers["ETag"] = f'"{etag}"'
            if last_modified is not None:
                resp.headers["Last-Modified"] = http_date(last_modified)
            return resp

    if_modified = request.headers.get("If-Modified-Since")
    if not if_none_match and if_modified and last_modified is not None:
        try:
            dt = parsedate_to_datetime(if_modified)
            obj_dt = datetime.fromtimestamp(last_modified, timezone.utc)
            if obj_dt <= dt:
                resp = Response(status=304)
                resp.headers["ETag"] = f'"{etag}"'
                resp.headers["Last-Modified"] = http_date(last_modified)
                return resp
        except (TypeError, ValueError):
            pass

    return None


def _apply_object_headers(
    response: Response,
    *,
    file_stat,
    metadata: Dict[str, str] | None,
    etag: str,
    size_override: int | None = None,
    mtime_override: float | None = None,
) -> None:
    effective_size = size_override if size_override is not None else (file_stat.st_size if file_stat is not None else None)
    effective_mtime = mtime_override if mtime_override is not None else (file_stat.st_mtime if file_stat is not None else None)
    if effective_size is not None and response.status_code != 206:
        response.headers["Content-Length"] = str(effective_size)
    if effective_mtime is not None:
        response.headers["Last-Modified"] = http_date(effective_mtime)
    response.headers["ETag"] = f'"{etag}"'
    response.headers["Accept-Ranges"] = "bytes"
    for key, value in (metadata or {}).items():
        if key.startswith("__") and key.endswith("__"):
            continue
        safe_value = _sanitize_header_value(str(value))
        response.headers[f"X-Amz-Meta-{key}"] = safe_value


def _maybe_handle_bucket_subresource(bucket_name: str) -> Response | None:
    handlers = {
        "versioning": _bucket_versioning_handler,
        "tagging": _bucket_tagging_handler,
        "cors": _bucket_cors_handler,
        "encryption": _bucket_encryption_handler,
        "location": _bucket_location_handler,
        "acl": _bucket_acl_handler,
        "versions": _bucket_list_versions_handler,
        "lifecycle": _bucket_lifecycle_handler,
        "quota": _bucket_quota_handler,
        "object-lock": _bucket_object_lock_handler,
        "notification": _bucket_notification_handler,
        "logging": _bucket_logging_handler,
        "uploads": _bucket_uploads_handler,
        "policy": _bucket_policy_handler,
        "policyStatus": _bucket_policy_status_handler,
        "replication": _bucket_replication_handler,
        "website": _bucket_website_handler,
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
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "versioning")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()

    if request.method == "PUT":
        ct_error = _require_xml_content_type()
        if ct_error:
            return ct_error
        payload = request.get_data(cache=False) or b""
        if not payload.strip():
            return _error_response("MalformedXML", "Request body is required", 400)
        try:
            root = _parse_xml_with_limit(payload)
        except ParseError:
            return _error_response("MalformedXML", "Unable to parse XML document", 400)
        if _strip_ns(root.tag) != "VersioningConfiguration":
            return _error_response("MalformedXML", "Root element must be VersioningConfiguration", 400)
        status_el = root.find("{http://s3.amazonaws.com/doc/2006-03-01/}Status")
        if status_el is None:
            status_el = root.find("Status")
        status = (status_el.text or "").strip() if status_el is not None else ""
        if status not in {"Enabled", "Suspended", ""}:
            return _error_response("MalformedXML", "Status must be Enabled or Suspended", 400)
        try:
            storage.set_bucket_versioning(bucket_name, status == "Enabled")
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket versioning updated", extra={"bucket": bucket_name, "status": status})
        return Response(status=200)
    
    try:
        enabled = storage.is_versioning_enabled(bucket_name)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    root = Element("VersioningConfiguration")
    SubElement(root, "Status").text = "Enabled" if enabled else "Suspended"
    return _xml_response(root)


def _bucket_tagging_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "tagging")
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
    if request.method == "DELETE":
        try:
            storage.set_bucket_tags(bucket_name, None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket tags deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    try:
        tags = _parse_tagging_document(payload)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    tag_limit = current_app.config.get("OBJECT_TAG_LIMIT", 50)
    if len(tags) > tag_limit:
        return _error_response("InvalidTag", f"A maximum of {tag_limit} tags is supported", 400)
    try:
        storage.set_bucket_tags(bucket_name, tags)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    current_app.logger.info("Bucket tags updated", extra={"bucket": bucket_name, "tags": len(tags)})
    return Response(status=204)


def _object_tagging_handler(bucket_name: str, object_key: str) -> Response:
    """Handle object tagging operations (GET/PUT/DELETE /<bucket>/<key>?tagging)."""
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
    
    principal, error = _require_principal()
    if error:
        return error
    
    action = "read" if request.method == "GET" else "write"
    try:
        _authorize_action(principal, bucket_name, action, object_key=object_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    
    storage = _storage()
    
    if request.method == "GET":
        try:
            tags = storage.get_object_tags(bucket_name, object_key)
        except BucketNotFoundError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        except ObjectNotFoundError as exc:
            return _error_response("NoSuchKey", str(exc), 404)
        except StorageError as exc:
            return _error_response("InternalError", str(exc), 500)
        return _xml_response(_render_tagging_document(tags))
    
    if request.method == "DELETE":
        try:
            storage.delete_object_tags(bucket_name, object_key)
        except BucketNotFoundError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        except ObjectNotFoundError as exc:
            return _error_response("NoSuchKey", str(exc), 404)
        except StorageError as exc:
            return _error_response("InternalError", str(exc), 500)
        current_app.logger.info("Object tags deleted", extra={"bucket": bucket_name, "key": object_key})
        return Response(status=204)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    try:
        tags = _parse_tagging_document(payload)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    if len(tags) > 10:
        return _error_response("InvalidTag", "A maximum of 10 tags is supported for objects", 400)
    try:
        storage.set_object_tags(bucket_name, object_key, tags)
    except BucketNotFoundError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    except ObjectNotFoundError as exc:
        return _error_response("NoSuchKey", str(exc), 404)
    except StorageError as exc:
        return _error_response("InternalError", str(exc), 500)
    current_app.logger.info("Object tags updated", extra={"bucket": bucket_name, "key": object_key, "tags": len(tags)})
    return Response(status=204)


def _validate_cors_origin(origin: str) -> bool:
    """Validate a CORS origin pattern."""
    import re
    origin = origin.strip()
    if not origin:
        return False
    if origin == "*":
        return True
    if origin.startswith("*."):
        domain = origin[2:]
        if not domain or ".." in domain:
            return False
        return bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', domain))
    if origin.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            parsed = urlparse(origin)
            if not parsed.netloc:
                return False
            if parsed.path and parsed.path != "/":
                return False
            return True
        except Exception:
            return False
    return False


def _sanitize_cors_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for rule in rules:
        allowed_origins = [origin.strip() for origin in rule.get("AllowedOrigins", []) if origin and origin.strip()]
        allowed_methods = [method.strip().upper() for method in rule.get("AllowedMethods", []) if method and method.strip()]
        allowed_headers = [header.strip() for header in rule.get("AllowedHeaders", []) if header and header.strip()]
        expose_headers = [header.strip() for header in rule.get("ExposeHeaders", []) if header and header.strip()]
        if not allowed_origins or not allowed_methods:
            raise ValueError("Each CORSRule must include AllowedOrigin and AllowedMethod entries")
        for origin in allowed_origins:
            if not _validate_cors_origin(origin):
                raise ValueError(f"Invalid CORS origin: {origin}")
        valid_methods = {"GET", "PUT", "POST", "DELETE", "HEAD"}
        for method in allowed_methods:
            if method not in valid_methods:
                raise ValueError(f"Invalid CORS method: {method}")
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
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "cors")
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
    if request.method == "DELETE":
        try:
            storage.set_bucket_cors(bucket_name, None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket CORS deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
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
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "encryption")
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
    if request.method == "DELETE":
        try:
            storage.set_bucket_encryption(bucket_name, None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket encryption deleted", extra={"bucket": bucket_name})
        return Response(status=204)
    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
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


def _bucket_location_handler(bucket_name: str) -> Response:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "list")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    
    region = current_app.config.get("AWS_REGION", "us-east-1")
    root = Element("LocationConstraint")
    root.text = region if region != "us-east-1" else None
    return _xml_response(root)


def _bucket_acl_handler(bucket_name: str) -> Response:
    from .acl import create_canned_acl, Acl, AclGrant, GRANTEE_ALL_USERS, GRANTEE_AUTHENTICATED_USERS

    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "share")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    acl_service = _acl()
    owner_id = principal.access_key if principal else "anonymous"

    if request.method == "PUT":
        canned_acl = request.headers.get("x-amz-acl", "private")
        acl = acl_service.set_bucket_canned_acl(bucket_name, canned_acl, owner_id)
        current_app.logger.info("Bucket ACL set", extra={"bucket": bucket_name, "acl": canned_acl})
        return Response(status=200)

    acl = acl_service.get_bucket_acl(bucket_name)
    if not acl:
        acl = create_canned_acl("private", owner_id)

    root = Element("AccessControlPolicy")
    owner_el = SubElement(root, "Owner")
    SubElement(owner_el, "ID").text = acl.owner
    SubElement(owner_el, "DisplayName").text = acl.owner

    acl_el = SubElement(root, "AccessControlList")
    for grant in acl.grants:
        grant_el = SubElement(acl_el, "Grant")
        grantee = SubElement(grant_el, "Grantee")
        if grant.grantee == GRANTEE_ALL_USERS:
            grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "Group")
            SubElement(grantee, "URI").text = "http://acs.amazonaws.com/groups/global/AllUsers"
        elif grant.grantee == GRANTEE_AUTHENTICATED_USERS:
            grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "Group")
            SubElement(grantee, "URI").text = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        else:
            grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "CanonicalUser")
            SubElement(grantee, "ID").text = grant.grantee
            SubElement(grantee, "DisplayName").text = grant.grantee
        SubElement(grant_el, "Permission").text = grant.permission

    return _xml_response(root)


def _object_acl_handler(bucket_name: str, object_key: str) -> Response:
    from .acl import create_canned_acl, GRANTEE_ALL_USERS, GRANTEE_AUTHENTICATED_USERS

    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])
    storage = _storage()
    try:
        path = storage.get_object_path(bucket_name, object_key)
    except (StorageError, FileNotFoundError):
        return _error_response("NoSuchKey", "Object not found", 404)

    if request.method == "PUT":
        principal, error = _object_principal("write", bucket_name, object_key)
        if error:
            return error
        owner_id = principal.access_key if principal else "anonymous"
        canned_acl = request.headers.get("x-amz-acl", "private")
        acl = create_canned_acl(canned_acl, owner_id)
        acl_service = _acl()
        metadata = storage.get_object_metadata(bucket_name, object_key)
        metadata.update(acl_service.create_object_acl_metadata(acl))
        safe_key = storage._sanitize_object_key(object_key, storage._object_key_max_length_bytes)
        storage._write_metadata(bucket_name, safe_key, metadata)
        current_app.logger.info("Object ACL set", extra={"bucket": bucket_name, "key": object_key, "acl": canned_acl})
        return Response(status=200)

    principal, error = _object_principal("read", bucket_name, object_key)
    if error:
        return error
    owner_id = principal.access_key if principal else "anonymous"
    acl_service = _acl()
    metadata = storage.get_object_metadata(bucket_name, object_key)
    acl = acl_service.get_object_acl(bucket_name, object_key, metadata)
    if not acl:
        acl = create_canned_acl("private", owner_id)

    root = Element("AccessControlPolicy")
    owner_el = SubElement(root, "Owner")
    SubElement(owner_el, "ID").text = acl.owner
    SubElement(owner_el, "DisplayName").text = acl.owner
    acl_el = SubElement(root, "AccessControlList")
    for grant in acl.grants:
        grant_el = SubElement(acl_el, "Grant")
        grantee = SubElement(grant_el, "Grantee")
        if grant.grantee == GRANTEE_ALL_USERS:
            grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "Group")
            SubElement(grantee, "URI").text = "http://acs.amazonaws.com/groups/global/AllUsers"
        elif grant.grantee == GRANTEE_AUTHENTICATED_USERS:
            grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "Group")
            SubElement(grantee, "URI").text = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
        else:
            grantee.set("{http://www.w3.org/2001/XMLSchema-instance}type", "CanonicalUser")
            SubElement(grantee, "ID").text = grant.grantee
            SubElement(grantee, "DisplayName").text = grant.grantee
        SubElement(grant_el, "Permission").text = grant.permission
    return _xml_response(root)


def _object_attributes_handler(bucket_name: str, object_key: str) -> Response:
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    principal, error = _object_principal("read", bucket_name, object_key)
    if error:
        return error
    storage = _storage()
    try:
        path = storage.get_object_path(bucket_name, object_key)
        file_stat = path.stat()
        metadata = storage.get_object_metadata(bucket_name, object_key)
    except (StorageError, FileNotFoundError):
        return _error_response("NoSuchKey", "Object not found", 404)

    requested = request.headers.get("x-amz-object-attributes", "")
    attrs = {a.strip() for a in requested.split(",") if a.strip()}

    root = Element("GetObjectAttributesResponse")
    if "ETag" in attrs:
        etag = metadata.get("__etag__") or storage._compute_etag(path)
        SubElement(root, "ETag").text = etag
    if "StorageClass" in attrs:
        SubElement(root, "StorageClass").text = "STANDARD"
    if "ObjectSize" in attrs:
        SubElement(root, "ObjectSize").text = str(file_stat.st_size)
    if "Checksum" in attrs:
        SubElement(root, "Checksum")
    if "ObjectParts" in attrs:
        SubElement(root, "ObjectParts")

    response = _xml_response(root)
    response.headers["Last-Modified"] = http_date(file_stat.st_mtime)
    return response


def _bucket_list_versions_handler(bucket_name: str) -> Response:
    """Handle ListObjectVersions (GET /<bucket>?versions)."""
    if request.method != "GET":
        return _method_not_allowed(["GET"])
    
    principal, error = _require_principal()
    try:
        _authorize_action(principal, bucket_name, "list")
    except IamError as exc:
        if error:
            return error
        return _error_response("AccessDenied", str(exc), 403)
    
    storage = _storage()
    
    try:
        objects = storage.list_objects_all(bucket_name)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    
    prefix = request.args.get("prefix", "")
    delimiter = request.args.get("delimiter", "")
    try:
        max_keys = int(request.args.get("max-keys", 1000))
        if max_keys < 1:
            return _error_response("InvalidArgument", "max-keys must be a positive integer", 400)
        max_keys = min(max_keys, 1000)
    except ValueError:
        return _error_response("InvalidArgument", "max-keys must be an integer", 400)
    key_marker = request.args.get("key-marker", "")
    
    if prefix:
        objects = [obj for obj in objects if obj.key.startswith(prefix)]
    
    if key_marker:
        objects = [obj for obj in objects if obj.key > key_marker]
    
    root = Element("ListVersionsResult", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
    SubElement(root, "Name").text = bucket_name
    SubElement(root, "Prefix").text = prefix
    SubElement(root, "KeyMarker").text = key_marker
    SubElement(root, "MaxKeys").text = str(max_keys)
    if delimiter:
        SubElement(root, "Delimiter").text = delimiter
    
    version_count = 0
    is_truncated = False
    next_key_marker = ""
    
    for obj in objects:
        if version_count >= max_keys:
            is_truncated = True
            break
        
        version = SubElement(root, "Version")
        SubElement(version, "Key").text = obj.key
        SubElement(version, "VersionId").text = "null"
        SubElement(version, "IsLatest").text = "true"
        SubElement(version, "LastModified").text = obj.last_modified.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if obj.etag:
            SubElement(version, "ETag").text = f'"{obj.etag}"'
        SubElement(version, "Size").text = str(obj.size)
        SubElement(version, "StorageClass").text = "STANDARD"
        
        owner = SubElement(version, "Owner")
        SubElement(owner, "ID").text = "local-owner"
        SubElement(owner, "DisplayName").text = "Local Owner"
        
        version_count += 1
        next_key_marker = obj.key
        
        try:
            versions = storage.list_object_versions(bucket_name, obj.key)
            for v in versions:
                if version_count >= max_keys:
                    is_truncated = True
                    break
                    
                ver_elem = SubElement(root, "Version")
                SubElement(ver_elem, "Key").text = obj.key
                SubElement(ver_elem, "VersionId").text = v.get("version_id", "unknown")
                SubElement(ver_elem, "IsLatest").text = "false"
                SubElement(ver_elem, "LastModified").text = v.get("archived_at") or "1970-01-01T00:00:00Z"
                SubElement(ver_elem, "ETag").text = f'"{v.get("etag", "")}"'
                SubElement(ver_elem, "Size").text = str(v.get("size", 0))
                SubElement(ver_elem, "StorageClass").text = "STANDARD"
                
                owner = SubElement(ver_elem, "Owner")
                SubElement(owner, "ID").text = "local-owner"
                SubElement(owner, "DisplayName").text = "Local Owner"
                
                version_count += 1
        except StorageError:
            pass
    
    SubElement(root, "IsTruncated").text = "true" if is_truncated else "false"
    if is_truncated and next_key_marker:
        SubElement(root, "NextKeyMarker").text = next_key_marker
    
    return _xml_response(root)


def _bucket_lifecycle_handler(bucket_name: str) -> Response:
    """Handle bucket lifecycle configuration (GET/PUT/DELETE /<bucket>?lifecycle)."""
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "lifecycle")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    
    storage = _storage()
    
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    
    if request.method == "GET":
        config = storage.get_bucket_lifecycle(bucket_name)
        if not config:
            return _error_response("NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist", 404)
        return _xml_response(_render_lifecycle_config(config))
    
    if request.method == "DELETE":
        storage.set_bucket_lifecycle(bucket_name, None)
        current_app.logger.info("Bucket lifecycle deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body is required", 400)
    try:
        config = _parse_lifecycle_config(payload)
        storage.set_bucket_lifecycle(bucket_name, config)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    
    current_app.logger.info("Bucket lifecycle updated", extra={"bucket": bucket_name})
    return Response(status=200)


def _render_lifecycle_config(config: list) -> Element:
    """Render lifecycle configuration to XML."""
    root = Element("LifecycleConfiguration", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
    for rule in config:
        rule_el = SubElement(root, "Rule")
        SubElement(rule_el, "ID").text = rule.get("ID", "")
        
        filter_el = SubElement(rule_el, "Filter")
        if rule.get("Prefix"):
            SubElement(filter_el, "Prefix").text = rule.get("Prefix", "")
        
        SubElement(rule_el, "Status").text = rule.get("Status", "Enabled")
        
        if "Expiration" in rule:
            exp = rule["Expiration"]
            exp_el = SubElement(rule_el, "Expiration")
            if "Days" in exp:
                SubElement(exp_el, "Days").text = str(exp["Days"])
            if "Date" in exp:
                SubElement(exp_el, "Date").text = exp["Date"]
            if exp.get("ExpiredObjectDeleteMarker"):
                SubElement(exp_el, "ExpiredObjectDeleteMarker").text = "true"
        
        if "NoncurrentVersionExpiration" in rule:
            nve = rule["NoncurrentVersionExpiration"]
            nve_el = SubElement(rule_el, "NoncurrentVersionExpiration")
            if "NoncurrentDays" in nve:
                SubElement(nve_el, "NoncurrentDays").text = str(nve["NoncurrentDays"])
        
        if "AbortIncompleteMultipartUpload" in rule:
            aimu = rule["AbortIncompleteMultipartUpload"]
            aimu_el = SubElement(rule_el, "AbortIncompleteMultipartUpload")
            if "DaysAfterInitiation" in aimu:
                SubElement(aimu_el, "DaysAfterInitiation").text = str(aimu["DaysAfterInitiation"])
    
    return root


def _parse_lifecycle_config(payload: bytes) -> list:
    """Parse lifecycle configuration from XML."""
    try:
        root = _parse_xml_with_limit(payload)
    except ParseError as exc:
        raise ValueError(f"Unable to parse XML document: {exc}") from exc
    
    if _strip_ns(root.tag) != "LifecycleConfiguration":
        raise ValueError("Root element must be LifecycleConfiguration")
    
    rules = []
    for rule_el in root.findall("{http://s3.amazonaws.com/doc/2006-03-01/}Rule") or root.findall("Rule"):
        rule: dict = {}
        
        id_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}ID") or rule_el.find("ID")
        if id_el is not None and id_el.text:
            rule["ID"] = id_el.text.strip()
        
        filter_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Filter") or rule_el.find("Filter")
        if filter_el is not None:
            prefix_el = filter_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Prefix") or filter_el.find("Prefix")
            if prefix_el is not None and prefix_el.text:
                rule["Prefix"] = prefix_el.text
        
        if "Prefix" not in rule:
            prefix_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Prefix") or rule_el.find("Prefix")
            if prefix_el is not None:
                rule["Prefix"] = prefix_el.text or ""
        
        status_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Status") or rule_el.find("Status")
        rule["Status"] = (status_el.text or "Enabled").strip() if status_el is not None else "Enabled"
        
        exp_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Expiration") or rule_el.find("Expiration")
        if exp_el is not None:
            expiration: dict = {}
            days_el = exp_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Days") or exp_el.find("Days")
            if days_el is not None and days_el.text:
                days_val = int(days_el.text.strip())
                if days_val <= 0:
                    raise ValueError("Expiration Days must be a positive integer")
                expiration["Days"] = days_val
            date_el = exp_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}Date") or exp_el.find("Date")
            if date_el is not None and date_el.text:
                expiration["Date"] = date_el.text.strip()
            eodm_el = exp_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}ExpiredObjectDeleteMarker") or exp_el.find("ExpiredObjectDeleteMarker")
            if eodm_el is not None and (eodm_el.text or "").strip().lower() in {"true", "1"}:
                expiration["ExpiredObjectDeleteMarker"] = True
            if expiration:
                rule["Expiration"] = expiration
        
        nve_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}NoncurrentVersionExpiration") or rule_el.find("NoncurrentVersionExpiration")
        if nve_el is not None:
            nve: dict = {}
            days_el = nve_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}NoncurrentDays") or nve_el.find("NoncurrentDays")
            if days_el is not None and days_el.text:
                noncurrent_days = int(days_el.text.strip())
                if noncurrent_days <= 0:
                    raise ValueError("NoncurrentDays must be a positive integer")
                nve["NoncurrentDays"] = noncurrent_days
            if nve:
                rule["NoncurrentVersionExpiration"] = nve
        
        aimu_el = rule_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}AbortIncompleteMultipartUpload") or rule_el.find("AbortIncompleteMultipartUpload")
        if aimu_el is not None:
            aimu: dict = {}
            days_el = aimu_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}DaysAfterInitiation") or aimu_el.find("DaysAfterInitiation")
            if days_el is not None and days_el.text:
                days_after = int(days_el.text.strip())
                if days_after <= 0:
                    raise ValueError("DaysAfterInitiation must be a positive integer")
                aimu["DaysAfterInitiation"] = days_after
            if aimu:
                rule["AbortIncompleteMultipartUpload"] = aimu
        
        rules.append(rule)
    
    return rules


def _bucket_quota_handler(bucket_name: str) -> Response:
    """Handle bucket quota configuration (GET/PUT/DELETE /<bucket>?quota)."""
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "quota")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    
    storage = _storage()
    
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    
    if request.method == "GET":
        quota = storage.get_bucket_quota(bucket_name)
        if not quota:
            return _error_response("NoSuchQuotaConfiguration", "No quota configuration found", 404)
        
        stats = storage.bucket_stats(bucket_name)
        return jsonify({
            "quota": quota,
            "usage": {
                "bytes": stats.get("bytes", 0),
                "objects": stats.get("objects", 0),
            }
        })
    
    if request.method == "DELETE":
        try:
            storage.set_bucket_quota(bucket_name, max_bytes=None, max_objects=None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket quota deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    payload = request.get_json(silent=True)
    if not payload:
        return _error_response("MalformedRequest", "Request body must be JSON with quota limits", 400)
    
    max_size_bytes = payload.get("max_size_bytes")
    max_objects = payload.get("max_objects")
    
    if max_size_bytes is None and max_objects is None:
        return _error_response("InvalidArgument", "At least one of max_size_bytes or max_objects is required", 400)
    
    if max_size_bytes is not None:
        try:
            max_size_bytes = int(max_size_bytes)
            if max_size_bytes < 0:
                raise ValueError("must be non-negative")
        except (TypeError, ValueError) as exc:
            return _error_response("InvalidArgument", f"max_size_bytes {exc}", 400)
    
    if max_objects is not None:
        try:
            max_objects = int(max_objects)
            if max_objects < 0:
                raise ValueError("must be non-negative")
        except (TypeError, ValueError) as exc:
            return _error_response("InvalidArgument", f"max_objects {exc}", 400)
    
    try:
        storage.set_bucket_quota(bucket_name, max_bytes=max_size_bytes, max_objects=max_objects)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    
    current_app.logger.info(
        "Bucket quota updated",
        extra={"bucket": bucket_name, "max_size_bytes": max_size_bytes, "max_objects": max_objects}
    )
    return Response(status=204)


def _bucket_object_lock_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "object_lock")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    lock_service = _object_lock()

    if request.method == "GET":
        config = lock_service.get_bucket_lock_config(bucket_name)
        root = Element("ObjectLockConfiguration", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
        SubElement(root, "ObjectLockEnabled").text = "Enabled" if config.enabled else "Disabled"
        return _xml_response(root)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body is required", 400)

    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)

    enabled_el = root.find("{http://s3.amazonaws.com/doc/2006-03-01/}ObjectLockEnabled") or root.find("ObjectLockEnabled")
    enabled = (enabled_el.text or "").strip() == "Enabled" if enabled_el is not None else False

    config = ObjectLockConfig(enabled=enabled)
    lock_service.set_bucket_lock_config(bucket_name, config)

    current_app.logger.info("Bucket object lock updated", extra={"bucket": bucket_name, "enabled": enabled})
    return Response(status=200)


def _bucket_notification_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "notification")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    notification_service = _notifications()

    if request.method == "GET":
        configs = notification_service.get_bucket_notifications(bucket_name)
        root = Element("NotificationConfiguration", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
        for config in configs:
            webhook_el = SubElement(root, "WebhookConfiguration")
            SubElement(webhook_el, "Id").text = config.id
            for event in config.events:
                SubElement(webhook_el, "Event").text = event
            dest_el = SubElement(webhook_el, "Destination")
            SubElement(dest_el, "Url").text = config.destination.url
            if config.prefix_filter or config.suffix_filter:
                filter_el = SubElement(webhook_el, "Filter")
                key_el = SubElement(filter_el, "S3Key")
                if config.prefix_filter:
                    rule_el = SubElement(key_el, "FilterRule")
                    SubElement(rule_el, "Name").text = "prefix"
                    SubElement(rule_el, "Value").text = config.prefix_filter
                if config.suffix_filter:
                    rule_el = SubElement(key_el, "FilterRule")
                    SubElement(rule_el, "Name").text = "suffix"
                    SubElement(rule_el, "Value").text = config.suffix_filter
        return _xml_response(root)

    if request.method == "DELETE":
        notification_service.delete_bucket_notifications(bucket_name)
        current_app.logger.info("Bucket notifications deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        notification_service.delete_bucket_notifications(bucket_name)
        return Response(status=200)

    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)

    configs: list[NotificationConfiguration] = []
    for webhook_el in root.findall("{http://s3.amazonaws.com/doc/2006-03-01/}WebhookConfiguration") or root.findall("WebhookConfiguration"):
        config_id = _find_element_text(webhook_el, "Id") or uuid.uuid4().hex
        events = [el.text for el in webhook_el.findall("{http://s3.amazonaws.com/doc/2006-03-01/}Event") or webhook_el.findall("Event") if el.text]

        dest_el = _find_element(webhook_el, "Destination")
        url = _find_element_text(dest_el, "Url") if dest_el else ""
        if not url:
            return _error_response("InvalidArgument", "Destination URL is required", 400)

        prefix = ""
        suffix = ""
        filter_el = _find_element(webhook_el, "Filter")
        if filter_el:
            key_el = _find_element(filter_el, "S3Key")
            if key_el:
                for rule_el in key_el.findall("{http://s3.amazonaws.com/doc/2006-03-01/}FilterRule") or key_el.findall("FilterRule"):
                    name = _find_element_text(rule_el, "Name")
                    value = _find_element_text(rule_el, "Value")
                    if name == "prefix":
                        prefix = value
                    elif name == "suffix":
                        suffix = value

        configs.append(NotificationConfiguration(
            id=config_id,
            events=events,
            destination=WebhookDestination(url=url),
            prefix_filter=prefix,
            suffix_filter=suffix,
        ))

    notification_service.set_bucket_notifications(bucket_name, configs)
    current_app.logger.info("Bucket notifications updated", extra={"bucket": bucket_name, "configs": len(configs)})
    return Response(status=200)


def _bucket_logging_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "logging")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    logging_service = _access_logging()

    if request.method == "GET":
        config = logging_service.get_bucket_logging(bucket_name)
        root = Element("BucketLoggingStatus", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
        if config and config.enabled:
            logging_enabled = SubElement(root, "LoggingEnabled")
            SubElement(logging_enabled, "TargetBucket").text = config.target_bucket
            SubElement(logging_enabled, "TargetPrefix").text = config.target_prefix
        return _xml_response(root)

    if request.method == "DELETE":
        logging_service.delete_bucket_logging(bucket_name)
        current_app.logger.info("Bucket logging deleted", extra={"bucket": bucket_name})
        return Response(status=204)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        logging_service.delete_bucket_logging(bucket_name)
        return Response(status=200)

    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)

    logging_enabled = _find_element(root, "LoggingEnabled")
    if logging_enabled is None:
        logging_service.delete_bucket_logging(bucket_name)
        return Response(status=200)

    target_bucket = _find_element_text(logging_enabled, "TargetBucket")
    if not target_bucket:
        return _error_response("InvalidArgument", "TargetBucket is required", 400)

    if not storage.bucket_exists(target_bucket):
        return _error_response("InvalidTargetBucketForLogging", "Target bucket does not exist", 400)

    target_prefix = _find_element_text(logging_enabled, "TargetPrefix")

    config = LoggingConfiguration(
        target_bucket=target_bucket,
        target_prefix=target_prefix,
        enabled=True,
    )
    logging_service.set_bucket_logging(bucket_name, config)

    current_app.logger.info(
        "Bucket logging updated",
        extra={"bucket": bucket_name, "target_bucket": target_bucket, "target_prefix": target_prefix}
    )
    return Response(status=200)


def _bucket_uploads_handler(bucket_name: str) -> Response:
    if request.method != "GET":
        return _method_not_allowed(["GET"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "list")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    key_marker = request.args.get("key-marker", "")
    upload_id_marker = request.args.get("upload-id-marker", "")
    prefix = request.args.get("prefix", "")
    delimiter = request.args.get("delimiter", "")
    try:
        max_uploads = int(request.args.get("max-uploads", 1000))
        if max_uploads < 1:
            return _error_response("InvalidArgument", "max-uploads must be a positive integer", 400)
        max_uploads = min(max_uploads, 1000)
    except ValueError:
        return _error_response("InvalidArgument", "max-uploads must be an integer", 400)

    uploads = storage.list_multipart_uploads(bucket_name, include_orphaned=True)

    if prefix:
        uploads = [u for u in uploads if u["object_key"].startswith(prefix)]
    if key_marker:
        uploads = [u for u in uploads if u["object_key"] > key_marker or
                   (u["object_key"] == key_marker and upload_id_marker and u["upload_id"] > upload_id_marker)]

    uploads.sort(key=lambda u: (u["object_key"], u["upload_id"]))

    is_truncated = len(uploads) > max_uploads
    if is_truncated:
        uploads = uploads[:max_uploads]

    root = Element("ListMultipartUploadsResult", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
    SubElement(root, "Bucket").text = bucket_name
    SubElement(root, "KeyMarker").text = key_marker
    SubElement(root, "UploadIdMarker").text = upload_id_marker
    if prefix:
        SubElement(root, "Prefix").text = prefix
    if delimiter:
        SubElement(root, "Delimiter").text = delimiter
    SubElement(root, "MaxUploads").text = str(max_uploads)
    SubElement(root, "IsTruncated").text = "true" if is_truncated else "false"

    if is_truncated and uploads:
        SubElement(root, "NextKeyMarker").text = uploads[-1]["object_key"]
        SubElement(root, "NextUploadIdMarker").text = uploads[-1]["upload_id"]

    for upload in uploads:
        upload_el = SubElement(root, "Upload")
        SubElement(upload_el, "Key").text = upload["object_key"]
        SubElement(upload_el, "UploadId").text = upload["upload_id"]
        if upload.get("created_at"):
            SubElement(upload_el, "Initiated").text = upload["created_at"]
        if upload.get("orphaned"):
            SubElement(upload_el, "StorageClass").text = "ORPHANED"

    return _xml_response(root)


def _object_retention_handler(bucket_name: str, object_key: str) -> Response:
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "object_lock", object_key=object_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    try:
        storage.get_object_path(bucket_name, object_key)
    except StorageError:
        return _error_response("NoSuchKey", "Object does not exist", 404)

    lock_service = _object_lock()

    if request.method == "GET":
        retention = lock_service.get_object_retention(bucket_name, object_key)
        if not retention:
            return _error_response("NoSuchObjectLockConfiguration", "No retention policy", 404)

        root = Element("Retention", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
        SubElement(root, "Mode").text = retention.mode.value
        SubElement(root, "RetainUntilDate").text = retention.retain_until_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return _xml_response(root)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body is required", 400)

    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)

    mode_str = _find_element_text(root, "Mode")
    retain_until_str = _find_element_text(root, "RetainUntilDate")

    if not mode_str or not retain_until_str:
        return _error_response("InvalidArgument", "Mode and RetainUntilDate are required", 400)

    try:
        mode = RetentionMode(mode_str)
    except ValueError:
        return _error_response("InvalidArgument", f"Invalid retention mode: {mode_str}", 400)

    try:
        retain_until = datetime.fromisoformat(retain_until_str.replace("Z", "+00:00"))
    except ValueError:
        return _error_response("InvalidArgument", f"Invalid date format: {retain_until_str}", 400)

    bypass = request.headers.get("x-amz-bypass-governance-retention", "").lower() == "true"

    retention = ObjectLockRetention(mode=mode, retain_until_date=retain_until)
    try:
        lock_service.set_object_retention(bucket_name, object_key, retention, bypass_governance=bypass)
    except ObjectLockError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    current_app.logger.info(
        "Object retention set",
        extra={"bucket": bucket_name, "key": object_key, "mode": mode_str, "until": retain_until_str}
    )
    return Response(status=200)


def _object_legal_hold_handler(bucket_name: str, object_key: str) -> Response:
    if request.method not in {"GET", "PUT"}:
        return _method_not_allowed(["GET", "PUT"])

    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "object_lock", object_key=object_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)

    try:
        storage.get_object_path(bucket_name, object_key)
    except StorageError:
        return _error_response("NoSuchKey", "Object does not exist", 404)

    lock_service = _object_lock()

    if request.method == "GET":
        enabled = lock_service.get_legal_hold(bucket_name, object_key)
        root = Element("LegalHold", xmlns="http://s3.amazonaws.com/doc/2006-03-01/")
        SubElement(root, "Status").text = "ON" if enabled else "OFF"
        return _xml_response(root)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body is required", 400)

    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)

    status = _find_element_text(root, "Status")
    if status not in {"ON", "OFF"}:
        return _error_response("InvalidArgument", "Status must be ON or OFF", 400)

    lock_service.set_legal_hold(bucket_name, object_key, status == "ON")

    current_app.logger.info(
        "Object legal hold set",
        extra={"bucket": bucket_name, "key": object_key, "status": status}
    )
    return Response(status=200)


def _bulk_delete_handler(bucket_name: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "delete")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body must include a Delete specification", 400)
    try:
        root = _parse_xml_with_limit(payload)
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
    deleted: list[dict[str, str | None]] = []
    errors: list[dict[str, str]] = []
    for entry in objects:
        key = entry["Key"] or ""
        version_id = entry.get("VersionId")
        try:
            if version_id:
                storage.delete_object_version(bucket_name, key, version_id)
                deleted.append({"Key": key, "VersionId": version_id})
            else:
                storage.delete_object(bucket_name, key)
                deleted.append({"Key": key, "VersionId": None})
        except StorageError as exc:
            errors.append({"Key": key, "Code": "InvalidRequest", "Message": str(exc)})

    result = Element("DeleteResult")
    if not quiet:
        for item in deleted:
            deleted_el = SubElement(result, "Deleted")
            SubElement(deleted_el, "Key").text = item["Key"]
            if item.get("VersionId"):
                SubElement(deleted_el, "VersionId").text = item["VersionId"]
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


def _post_object(bucket_name: str) -> Response:
    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    object_key = request.form.get("key")
    policy_b64 = request.form.get("policy")
    signature = request.form.get("x-amz-signature")
    credential = request.form.get("x-amz-credential")
    algorithm = request.form.get("x-amz-algorithm")
    amz_date = request.form.get("x-amz-date")
    if not all([object_key, policy_b64, signature, credential, algorithm, amz_date]):
        return _error_response("InvalidArgument", "Missing required form fields", 400)
    if algorithm != "AWS4-HMAC-SHA256":
        return _error_response("InvalidArgument", "Unsupported signing algorithm", 400)
    try:
        policy_json = base64.b64decode(policy_b64).decode("utf-8")
        policy = __import__("json").loads(policy_json)
    except (ValueError, __import__("json").JSONDecodeError) as exc:
        return _error_response("InvalidPolicyDocument", f"Invalid policy: {exc}", 400)
    expiration = policy.get("expiration")
    if expiration:
        try:
            exp_time = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp_time:
                return _error_response("AccessDenied", "Policy expired", 403)
        except ValueError:
            return _error_response("InvalidPolicyDocument", "Invalid expiration format", 400)
    conditions = policy.get("conditions", [])
    validation_error = _validate_post_policy_conditions(bucket_name, object_key, conditions, request.form, request.content_length or 0)
    if validation_error:
        return _error_response("AccessDenied", validation_error, 403)
    try:
        parts = credential.split("/")
        if len(parts) != 5:
            raise ValueError("Invalid credential format")
        access_key, date_stamp, region, service, _ = parts
    except ValueError:
        return _error_response("InvalidArgument", "Invalid credential format", 400)
    secret_key = _iam().get_secret_key(access_key)
    if not secret_key:
        return _error_response("AccessDenied", "Invalid access key", 403)
    signing_key = _derive_signing_key(secret_key, date_stamp, region, service)
    expected_signature = hmac.new(signing_key, policy_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        return _error_response("SignatureDoesNotMatch", "Signature verification failed", 403)
    principal = _iam().get_principal(access_key)
    if not principal:
        return _error_response("AccessDenied", "Invalid access key", 403)
    if "${filename}" in object_key:
        temp_key = object_key.replace("${filename}", request.files.get("file").filename if request.files.get("file") else "upload")
    else:
        temp_key = object_key
    try:
        _authorize_action(principal, bucket_name, "write", object_key=temp_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    file = request.files.get("file")
    if not file:
        return _error_response("InvalidArgument", "Missing file field", 400)
    if "${filename}" in object_key:
        object_key = object_key.replace("${filename}", file.filename or "upload")
    metadata = {}
    for field_name, value in request.form.items():
        if field_name.lower().startswith("x-amz-meta-"):
            key = field_name[11:]
            if key and not (key.startswith("__") and key.endswith("__")):
                metadata[key] = value
    try:
        meta = storage.put_object(bucket_name, object_key, file.stream, metadata=metadata or None)
    except QuotaExceededError as exc:
        return _error_response("QuotaExceeded", str(exc), 403)
    except StorageError as exc:
        return _error_response("InvalidArgument", str(exc), 400)
    current_app.logger.info("Object uploaded via POST", extra={"bucket": bucket_name, "key": object_key, "size": meta.size})
    success_action_status = request.form.get("success_action_status", "204")
    success_action_redirect = request.form.get("success_action_redirect")
    if success_action_redirect:
        allowed_hosts = current_app.config.get("ALLOWED_REDIRECT_HOSTS", [])
        if not allowed_hosts:
            current_app.logger.warning(
                "ALLOWED_REDIRECT_HOSTS not configured, falling back to request Host header. "
                "Set ALLOWED_REDIRECT_HOSTS for production deployments."
            )
            allowed_hosts = [request.host]
        parsed = urlparse(success_action_redirect)
        if parsed.scheme not in ("http", "https"):
            return _error_response("InvalidArgument", "Redirect URL must use http or https", 400)
        if parsed.netloc not in allowed_hosts:
            return _error_response("InvalidArgument", "Redirect URL host not allowed", 400)
        redirect_url = f"{success_action_redirect}?bucket={bucket_name}&key={quote(object_key)}&etag={meta.etag}"
        return Response(status=303, headers={"Location": redirect_url})
    if success_action_status == "200":
        root = Element("PostResponse")
        SubElement(root, "Location").text = f"/{bucket_name}/{object_key}"
        SubElement(root, "Bucket").text = bucket_name
        SubElement(root, "Key").text = object_key
        SubElement(root, "ETag").text = f'"{meta.etag}"'
        return _xml_response(root, status=200)
    if success_action_status == "201":
        root = Element("PostResponse")
        SubElement(root, "Location").text = f"/{bucket_name}/{object_key}"
        SubElement(root, "Bucket").text = bucket_name
        SubElement(root, "Key").text = object_key
        SubElement(root, "ETag").text = f'"{meta.etag}"'
        return _xml_response(root, status=201)
    return Response(status=204)


def _validate_post_policy_conditions(bucket_name: str, object_key: str, conditions: list, form_data, content_length: int) -> Optional[str]:
    for condition in conditions:
        if isinstance(condition, dict):
            for key, expected_value in condition.items():
                if key == "bucket":
                    if bucket_name != expected_value:
                        return f"Bucket must be {expected_value}"
                elif key == "key":
                    if object_key != expected_value:
                        return f"Key must be {expected_value}"
                else:
                    actual_value = form_data.get(key, "")
                    if actual_value != expected_value:
                        return f"Field {key} must be {expected_value}"
        elif isinstance(condition, list) and len(condition) >= 2:
            operator = condition[0].lower() if isinstance(condition[0], str) else ""
            if operator == "starts-with" and len(condition) == 3:
                field = condition[1].lstrip("$")
                prefix = condition[2]
                if field == "key":
                    if not object_key.startswith(prefix):
                        return f"Key must start with {prefix}"
                else:
                    actual_value = form_data.get(field, "")
                    if not actual_value.startswith(prefix):
                        return f"Field {field} must start with {prefix}"
            elif operator == "eq" and len(condition) == 3:
                field = condition[1].lstrip("$")
                expected = condition[2]
                if field == "key":
                    if object_key != expected:
                        return f"Key must equal {expected}"
                else:
                    actual_value = form_data.get(field, "")
                    if actual_value != expected:
                        return f"Field {field} must equal {expected}"
            elif operator == "content-length-range" and len(condition) == 3:
                try:
                    min_size, max_size = int(condition[1]), int(condition[2])
                except (TypeError, ValueError):
                    return "Invalid content-length-range values"
                if content_length < min_size or content_length > max_size:
                    return f"Content length must be between {min_size} and {max_size}"
    return None


@s3_api_bp.get("/")
@limiter.limit(_get_list_buckets_limit)
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
@limiter.limit(_get_bucket_ops_limit)
def bucket_handler(bucket_name: str) -> Response:
    storage = _storage()
    subresource_response = _maybe_handle_bucket_subresource(bucket_name)
    if subresource_response is not None:
        return subresource_response

    if request.method == "POST":
        if "delete" in request.args:
            return _bulk_delete_handler(bucket_name)
        content_type = request.headers.get("Content-Type", "")
        if "multipart/form-data" in content_type:
            return _post_object(bucket_name)
        return _method_not_allowed(["GET", "PUT", "DELETE"])

    if request.method == "PUT":
        principal, error = _require_principal()
        if error:
            return error
        try:
            _authorize_action(principal, bucket_name, "create_bucket")
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
            _authorize_action(principal, bucket_name, "delete_bucket")
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

    principal, error = _require_principal()
    try:
        _authorize_action(principal, bucket_name, "list")
    except IamError as exc:
        if error:
            return error
        return _error_response("AccessDenied", str(exc), 403)

    list_type = request.args.get("list-type")
    prefix = request.args.get("prefix", "")
    delimiter = request.args.get("delimiter", "")
    try:
        max_keys = int(request.args.get("max-keys", current_app.config["UI_PAGE_SIZE"]))
        if max_keys < 1:
            return _error_response("InvalidArgument", "max-keys must be a positive integer", 400)
        max_keys = min(max_keys, 1000)
    except ValueError:
        return _error_response("InvalidArgument", "max-keys must be an integer", 400)

    marker = request.args.get("marker", "")  # ListObjects v1
    continuation_token = request.args.get("continuation-token", "")  # ListObjectsV2
    start_after = request.args.get("start-after", "")  # ListObjectsV2
    
    effective_start = ""
    if list_type == "2":
        if continuation_token:
            try:
                effective_start = base64.urlsafe_b64decode(continuation_token.encode()).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                return _error_response("InvalidArgument", "Invalid continuation token", 400)
        elif start_after:
            effective_start = start_after
    else:
        effective_start = marker
    
    try:
        if delimiter:
            shallow_result = storage.list_objects_shallow(
                bucket_name,
                prefix=prefix,
                delimiter=delimiter,
                max_keys=max_keys,
                continuation_token=effective_start or None,
            )
            objects = shallow_result.objects
            common_prefixes = shallow_result.common_prefixes
            is_truncated = shallow_result.is_truncated

            next_marker = shallow_result.next_continuation_token or ""
            next_continuation_token = ""
            if is_truncated and next_marker and list_type == "2":
                next_continuation_token = base64.urlsafe_b64encode(next_marker.encode()).decode("utf-8")
        else:
            list_result = storage.list_objects(
                bucket_name,
                max_keys=max_keys,
                continuation_token=effective_start or None,
                prefix=prefix or None,
            )
            objects = list_result.objects
            common_prefixes = []
            is_truncated = list_result.is_truncated

            next_marker = ""
            next_continuation_token = ""
            if is_truncated:
                if objects:
                    next_marker = objects[-1].key
                if list_type == "2" and next_marker:
                    next_continuation_token = base64.urlsafe_b64encode(next_marker.encode()).decode("utf-8")
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)

    if list_type == "2":
        root = Element("ListBucketResult")
        SubElement(root, "Name").text = bucket_name
        SubElement(root, "Prefix").text = prefix
        SubElement(root, "MaxKeys").text = str(max_keys)
        SubElement(root, "KeyCount").text = str(len(objects) + len(common_prefixes))
        SubElement(root, "IsTruncated").text = "true" if is_truncated else "false"
        if delimiter:
            SubElement(root, "Delimiter").text = delimiter
        
        continuation_token = request.args.get("continuation-token", "")
        start_after = request.args.get("start-after", "")
        if continuation_token:
            SubElement(root, "ContinuationToken").text = continuation_token
        if start_after:
            SubElement(root, "StartAfter").text = start_after
        
        if is_truncated and next_continuation_token:
            SubElement(root, "NextContinuationToken").text = next_continuation_token
        
        for meta in objects:
            obj_el = SubElement(root, "Contents")
            SubElement(obj_el, "Key").text = meta.key
            SubElement(obj_el, "LastModified").text = meta.last_modified.isoformat()
            if meta.etag:
                SubElement(obj_el, "ETag").text = f'"{meta.etag}"'
            SubElement(obj_el, "Size").text = str(meta.size)
            SubElement(obj_el, "StorageClass").text = "STANDARD"

        for cp in common_prefixes:
            cp_el = SubElement(root, "CommonPrefixes")
            SubElement(cp_el, "Prefix").text = cp
    else:
        root = Element("ListBucketResult")
        SubElement(root, "Name").text = bucket_name
        SubElement(root, "Prefix").text = prefix
        SubElement(root, "Marker").text = marker
        SubElement(root, "MaxKeys").text = str(max_keys)
        SubElement(root, "IsTruncated").text = "true" if is_truncated else "false"
        if delimiter:
            SubElement(root, "Delimiter").text = delimiter

        if is_truncated and delimiter and next_marker:
            SubElement(root, "NextMarker").text = next_marker

        for meta in objects:
            obj_el = SubElement(root, "Contents")
            SubElement(obj_el, "Key").text = meta.key
            SubElement(obj_el, "LastModified").text = meta.last_modified.isoformat()
            if meta.etag:
                SubElement(obj_el, "ETag").text = f'"{meta.etag}"'
            SubElement(obj_el, "Size").text = str(meta.size)
        
        for cp in common_prefixes:
            cp_el = SubElement(root, "CommonPrefixes")
            SubElement(cp_el, "Prefix").text = cp

    return _xml_response(root)


@s3_api_bp.route("/<bucket_name>/<path:object_key>", methods=["PUT", "GET", "DELETE", "HEAD", "POST"], strict_slashes=False)
@limiter.limit(_get_object_ops_limit)
def object_handler(bucket_name: str, object_key: str):
    storage = _storage()

    if "tagging" in request.args:
        return _object_tagging_handler(bucket_name, object_key)

    if "retention" in request.args:
        return _object_retention_handler(bucket_name, object_key)

    if "legal-hold" in request.args:
        return _object_legal_hold_handler(bucket_name, object_key)

    if "acl" in request.args:
        return _object_acl_handler(bucket_name, object_key)

    if "attributes" in request.args:
        return _object_attributes_handler(bucket_name, object_key)

    if request.method == "POST":
        if "uploads" in request.args:
            return _initiate_multipart_upload(bucket_name, object_key)
        if "uploadId" in request.args:
            return _complete_multipart_upload(bucket_name, object_key)
        if "select" in request.args:
            return _select_object_content(bucket_name, object_key)
        return _method_not_allowed(["GET", "PUT", "DELETE", "HEAD", "POST"])

    if request.method == "PUT":
        if "partNumber" in request.args and "uploadId" in request.args:
            return _upload_part(bucket_name, object_key)

        copy_source = request.headers.get("x-amz-copy-source")
        if copy_source:
            return _copy_object(bucket_name, object_key, copy_source)

        principal, error = _object_principal("write", bucket_name, object_key)
        if error:
            return error

        bypass_governance = request.headers.get("x-amz-bypass-governance-retention", "").lower() == "true"
        lock_service = _object_lock()
        can_overwrite, lock_reason = lock_service.can_overwrite_object(bucket_name, object_key, bypass_governance=bypass_governance)
        if not can_overwrite:
            return _error_response("AccessDenied", lock_reason, 403)

        stream = request.stream
        content_encoding = request.headers.get("Content-Encoding", "").lower()
        if "aws-chunked" in content_encoding:
            stream = AwsChunkedDecoder(stream)

        metadata = _extract_request_metadata()

        content_type = request.headers.get("Content-Type")
        validation_error = _validate_content_type(object_key, content_type)
        if validation_error:
            return _error_response("InvalidArgument", validation_error, 400)

        metadata["__content_type__"] = content_type or mimetypes.guess_type(object_key)[0] or "application/octet-stream"

        try:
            meta = storage.put_object(
                bucket_name,
                object_key,
                stream,
                metadata=metadata or None,
            )
        except QuotaExceededError as exc:
            return _error_response("QuotaExceeded", str(exc), 403)
        except StorageError as exc:
            message = str(exc)
            if "Bucket" in message:
                return _error_response("NoSuchBucket", message, 404)
            return _error_response("InvalidArgument", message, 400)

        content_md5 = request.headers.get("Content-MD5")
        if content_md5 and meta.etag:
            try:
                expected_md5 = base64.b64decode(content_md5).hex()
            except Exception:
                storage.delete_object(bucket_name, object_key)
                return _error_response("InvalidDigest", "Content-MD5 header is not valid base64", 400)
            if expected_md5 != meta.etag:
                storage.delete_object(bucket_name, object_key)
                return _error_response("BadDigest", "The Content-MD5 you specified did not match what we received", 400)

        if current_app.logger.isEnabledFor(logging.INFO):
            current_app.logger.info(
                "Object uploaded",
                extra={"bucket": bucket_name, "key": object_key, "size": meta.size},
            )
        response = Response(status=200)
        if meta.etag:
            response.headers["ETag"] = f'"{meta.etag}"'

        _notifications().emit_object_created(
            bucket_name,
            object_key,
            size=meta.size,
            etag=meta.etag,
            request_id=getattr(g, "request_id", ""),
            source_ip=request.remote_addr or "",
            user_identity=principal.access_key if principal else "",
            operation="Put",
        )

        user_agent = request.headers.get("User-Agent", "")
        if "S3ReplicationAgent" not in user_agent and "SiteSyncAgent" not in user_agent:
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
        mimetype = metadata.get("__content_type__") or mimetypes.guess_type(object_key)[0] or "application/octet-stream"
        
        is_encrypted = "x-amz-server-side-encryption" in metadata

        cond_etag = metadata.get("__etag__")
        if not cond_etag and not is_encrypted:
            try:
                cond_etag = storage._compute_etag(path)
            except OSError:
                cond_etag = None
        if cond_etag:
            cond_mtime = float(metadata["__last_modified__"]) if "__last_modified__" in metadata else None
            if cond_mtime is None:
                try:
                    cond_mtime = path.stat().st_mtime
                except OSError:
                    pass
            cond_resp = _check_conditional_headers(cond_etag, cond_mtime)
            if cond_resp:
                return cond_resp

        if request.method == "GET":
            range_header = request.headers.get("Range")

            if is_encrypted and hasattr(storage, 'get_object_data'):
                try:
                    data, clean_metadata = storage.get_object_data(bucket_name, object_key)
                    file_size = len(data)
                    etag = hashlib.md5(data).hexdigest()

                    if range_header:
                        try:
                            ranges = _parse_range_header(range_header, file_size)
                        except (ValueError, TypeError):
                            ranges = None
                        if ranges is None:
                            return _error_response("InvalidRange", "Range Not Satisfiable", 416)
                        start, end = ranges[0]
                        partial_data = data[start:end + 1]
                        response = Response(partial_data, status=206, mimetype=mimetype)
                        response.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
                        response.headers["Content-Length"] = len(partial_data)
                        logged_bytes = len(partial_data)
                    else:
                        response = Response(data, mimetype=mimetype)
                        response.headers["Content-Length"] = file_size
                        logged_bytes = file_size
                except StorageError as exc:
                    return _error_response("InternalError", str(exc), 500)
            else:
                try:
                    stat = path.stat()
                    file_size = stat.st_size
                    etag = metadata.get("__etag__") or storage._compute_etag(path)
                except PermissionError:
                    return _error_response("AccessDenied", "Permission denied accessing object", 403)
                except OSError as exc:
                    return _error_response("InternalError", f"Failed to access object: {exc}", 500)

                if range_header:
                    try:
                        ranges = _parse_range_header(range_header, file_size)
                    except (ValueError, TypeError):
                        ranges = None
                    if ranges is None:
                        return _error_response("InvalidRange", "Range Not Satisfiable", 416)
                    start, end = ranges[0]
                    length = end - start + 1

                    def stream_range(file_path, start_pos, length_to_read):
                        with open(file_path, "rb") as f:
                            f.seek(start_pos)
                            remaining = length_to_read
                            while remaining > 0:
                                chunk_size = min(262144, remaining)
                                chunk = f.read(chunk_size)
                                if not chunk:
                                    break
                                remaining -= len(chunk)
                                yield chunk

                    response = Response(stream_range(path, start, length), status=206, mimetype=mimetype, direct_passthrough=True)
                    response.headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
                    response.headers["Content-Length"] = length
                    logged_bytes = length
                else:
                    response = Response(_stream_file(path), mimetype=mimetype, direct_passthrough=True)
                    logged_bytes = file_size
        else:
            if is_encrypted and hasattr(storage, 'get_object_data'):
                try:
                    data, _ = storage.get_object_data(bucket_name, object_key)
                    response = Response(status=200)
                    response.headers["Content-Length"] = len(data)
                    etag = hashlib.md5(data).hexdigest()
                except StorageError as exc:
                    return _error_response("InternalError", str(exc), 500)
            else:
                try:
                    stat = path.stat()
                    response = Response(status=200)
                    etag = metadata.get("__etag__") or storage._compute_etag(path)
                except PermissionError:
                    return _error_response("AccessDenied", "Permission denied accessing object", 403)
                except OSError as exc:
                    return _error_response("InternalError", f"Failed to access object: {exc}", 500)
            response.headers["Content-Type"] = mimetype
            logged_bytes = 0

        file_stat = stat if not is_encrypted else None
        _apply_object_headers(response, file_stat=file_stat, metadata=metadata, etag=etag)

        if request.method == "GET":
            response_overrides = {
                "response-content-type": "Content-Type",
                "response-content-language": "Content-Language",
                "response-expires": "Expires",
                "response-cache-control": "Cache-Control",
                "response-content-disposition": "Content-Disposition",
                "response-content-encoding": "Content-Encoding",
            }
            for param, header in response_overrides.items():
                value = request.args.get(param)
                if value:
                    response.headers[header] = _sanitize_header_value(value)

        if current_app.logger.isEnabledFor(logging.INFO):
            action = "Object read" if request.method == "GET" else "Object head"
            current_app.logger.info(action, extra={"bucket": bucket_name, "key": object_key, "bytes": logged_bytes})
        return response

    if "uploadId" in request.args:
        return _abort_multipart_upload(bucket_name, object_key)

    _, error = _object_principal("delete", bucket_name, object_key)
    if error:
        return error

    bypass_governance = request.headers.get("x-amz-bypass-governance-retention", "").lower() == "true"
    lock_service = _object_lock()
    can_delete, lock_reason = lock_service.can_delete_object(bucket_name, object_key, bypass_governance=bypass_governance)
    if not can_delete:
        return _error_response("AccessDenied", lock_reason, 403)

    storage.delete_object(bucket_name, object_key)
    lock_service.delete_object_lock_metadata(bucket_name, object_key)
    if current_app.logger.isEnabledFor(logging.INFO):
        current_app.logger.info("Object deleted", extra={"bucket": bucket_name, "key": object_key})

    principal, _ = _require_principal()
    _notifications().emit_object_removed(
        bucket_name,
        object_key,
        request_id=getattr(g, "request_id", ""),
        source_ip=request.remote_addr or "",
        user_identity=principal.access_key if principal else "",
    )

    user_agent = request.headers.get("User-Agent", "")
    if "S3ReplicationAgent" not in user_agent and "SiteSyncAgent" not in user_agent:
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


def _bucket_policy_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
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
    raw_body = request.get_data(cache=False) or b""
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, ValueError):
        return _error_response("MalformedPolicy", "Policy document must be JSON", 400)
    if not payload:
        return _error_response("MalformedPolicy", "Policy document must be JSON", 400)
    try:
        store.set_policy(bucket_name, payload)
        current_app.logger.info("Bucket policy updated", extra={"bucket": bucket_name})
    except ValueError as exc:
        return _error_response("MalformedPolicy", str(exc), 400)
    return Response(status=204)


def _bucket_policy_status_handler(bucket_name: str) -> Response:
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
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    store = _bucket_policies()
    policy = store.get_policy(bucket_name)
    is_public = False
    if policy:
        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Allow" and statement.get("Principal") == "*":
                is_public = True
                break
    root = Element("PolicyStatus")
    SubElement(root, "IsPublic").text = "TRUE" if is_public else "FALSE"
    return _xml_response(root)


def _bucket_replication_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "replication")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if not storage.bucket_exists(bucket_name):
        return _error_response("NoSuchBucket", "Bucket does not exist", 404)
    replication = _replication_manager()
    if request.method == "GET":
        rule = replication.get_rule(bucket_name)
        if not rule:
            return _error_response("ReplicationConfigurationNotFoundError", "Replication configuration not found", 404)
        return _xml_response(_render_replication_config(rule))
    if request.method == "DELETE":
        replication.delete_rule(bucket_name)
        current_app.logger.info("Bucket replication removed", extra={"bucket": bucket_name})
        return Response(status=204)
    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    try:
        rule = _parse_replication_config(bucket_name, payload)
    except ValueError as exc:
        return _error_response("MalformedXML", str(exc), 400)
    replication.set_rule(rule)
    current_app.logger.info("Bucket replication updated", extra={"bucket": bucket_name})
    return Response(status=200)


def _parse_replication_config(bucket_name: str, payload: bytes):
    from .replication import ReplicationRule, REPLICATION_MODE_ALL
    root = _parse_xml_with_limit(payload)
    if _strip_ns(root.tag) != "ReplicationConfiguration":
        raise ValueError("Root element must be ReplicationConfiguration")
    rule_el = None
    for child in list(root):
        if _strip_ns(child.tag) == "Rule":
            rule_el = child
            break
    if rule_el is None:
        raise ValueError("At least one Rule is required")
    status_el = _find_element(rule_el, "Status")
    status = status_el.text if status_el is not None and status_el.text else "Enabled"
    enabled = status.lower() == "enabled"
    filter_prefix = None
    filter_el = _find_element(rule_el, "Filter")
    if filter_el is not None:
        prefix_el = _find_element(filter_el, "Prefix")
        if prefix_el is not None and prefix_el.text:
            filter_prefix = prefix_el.text
    dest_el = _find_element(rule_el, "Destination")
    if dest_el is None:
        raise ValueError("Destination element is required")
    bucket_el = _find_element(dest_el, "Bucket")
    if bucket_el is None or not bucket_el.text:
        raise ValueError("Destination Bucket is required")
    target_bucket, target_connection_id = _parse_destination_arn(bucket_el.text)
    sync_deletions = True
    dm_el = _find_element(rule_el, "DeleteMarkerReplication")
    if dm_el is not None:
        dm_status_el = _find_element(dm_el, "Status")
        if dm_status_el is not None and dm_status_el.text:
            sync_deletions = dm_status_el.text.lower() == "enabled"
    return ReplicationRule(
        bucket_name=bucket_name,
        target_connection_id=target_connection_id,
        target_bucket=target_bucket,
        enabled=enabled,
        mode=REPLICATION_MODE_ALL,
        sync_deletions=sync_deletions,
        filter_prefix=filter_prefix,
    )


def _bucket_website_handler(bucket_name: str) -> Response:
    if request.method not in {"GET", "PUT", "DELETE"}:
        return _method_not_allowed(["GET", "PUT", "DELETE"])
    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        return _error_response("InvalidRequest", "Website hosting is not enabled", 400)
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "website")
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    storage = _storage()
    if request.method == "GET":
        try:
            config = storage.get_bucket_website(bucket_name)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        if not config:
            return _error_response("NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration", 404)
        root = Element("WebsiteConfiguration")
        root.set("xmlns", S3_NS)
        index_doc = config.get("index_document")
        if index_doc:
            idx_el = SubElement(root, "IndexDocument")
            SubElement(idx_el, "Suffix").text = index_doc
        error_doc = config.get("error_document")
        if error_doc:
            err_el = SubElement(root, "ErrorDocument")
            SubElement(err_el, "Key").text = error_doc
        return _xml_response(root)
    if request.method == "DELETE":
        try:
            storage.set_bucket_website(bucket_name, None)
        except StorageError as exc:
            return _error_response("NoSuchBucket", str(exc), 404)
        current_app.logger.info("Bucket website config deleted", extra={"bucket": bucket_name})
        return Response(status=204)
    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    if not payload.strip():
        return _error_response("MalformedXML", "Request body is required", 400)
    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)
    if _strip_ns(root.tag) != "WebsiteConfiguration":
        return _error_response("MalformedXML", "Root element must be WebsiteConfiguration", 400)
    index_el = _find_element(root, "IndexDocument")
    if index_el is None:
        return _error_response("InvalidArgument", "IndexDocument is required", 400)
    suffix_el = _find_element(index_el, "Suffix")
    if suffix_el is None or not (suffix_el.text or "").strip():
        return _error_response("InvalidArgument", "IndexDocument Suffix is required", 400)
    index_suffix = suffix_el.text.strip()
    if "/" in index_suffix:
        return _error_response("InvalidArgument", "IndexDocument Suffix must not contain '/'", 400)
    website_config: Dict[str, Any] = {"index_document": index_suffix}
    error_el = _find_element(root, "ErrorDocument")
    if error_el is not None:
        key_el = _find_element(error_el, "Key")
        if key_el is not None and (key_el.text or "").strip():
            website_config["error_document"] = key_el.text.strip()
    try:
        storage.set_bucket_website(bucket_name, website_config)
    except StorageError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    current_app.logger.info("Bucket website config updated", extra={"bucket": bucket_name, "index": index_suffix})
    return Response(status=200)


def _parse_destination_arn(arn: str) -> tuple:
    if not arn.startswith("arn:aws:s3:::"):
        raise ValueError(f"Invalid ARN format: {arn}")
    bucket_part = arn[13:]
    if "/" in bucket_part:
        connection_id, bucket_name = bucket_part.split("/", 1)
    else:
        connection_id = "local"
        bucket_name = bucket_part
    return bucket_name, connection_id


def _render_replication_config(rule) -> Element:
    root = Element("ReplicationConfiguration")
    SubElement(root, "Role").text = "arn:aws:iam::000000000000:role/replication"
    rule_el = SubElement(root, "Rule")
    SubElement(rule_el, "ID").text = f"{rule.bucket_name}-replication"
    SubElement(rule_el, "Status").text = "Enabled" if rule.enabled else "Disabled"
    SubElement(rule_el, "Priority").text = "1"
    filter_el = SubElement(rule_el, "Filter")
    if rule.filter_prefix:
        SubElement(filter_el, "Prefix").text = rule.filter_prefix
    dest_el = SubElement(rule_el, "Destination")
    if rule.target_connection_id == "local":
        arn = f"arn:aws:s3:::{rule.target_bucket}"
    else:
        arn = f"arn:aws:s3:::{rule.target_connection_id}/{rule.target_bucket}"
    SubElement(dest_el, "Bucket").text = arn
    dm_el = SubElement(rule_el, "DeleteMarkerReplication")
    SubElement(dm_el, "Status").text = "Enabled" if rule.sync_deletions else "Disabled"
    return root


@s3_api_bp.route("/<bucket_name>", methods=["HEAD"])
@limiter.limit(_get_head_ops_limit)
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
@limiter.limit(_get_head_ops_limit)
def head_object(bucket_name: str, object_key: str) -> Response:
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, bucket_name, "read", object_key=object_key)
        path = _storage().get_object_path(bucket_name, object_key)
        metadata = _storage().get_object_metadata(bucket_name, object_key)
        etag = metadata.get("__etag__") or _storage()._compute_etag(path)

        head_mtime = float(metadata["__last_modified__"]) if "__last_modified__" in metadata else None
        if head_mtime is None:
            try:
                head_mtime = path.stat().st_mtime
            except OSError:
                pass
        cond_resp = _check_conditional_headers(etag, head_mtime)
        if cond_resp:
            return cond_resp

        cached_size = metadata.get("__size__")
        cached_mtime = metadata.get("__last_modified__")
        if cached_size is not None and cached_mtime is not None:
            size_val = int(cached_size)
            mtime_val = float(cached_mtime)
            response = Response(status=200)
            _apply_object_headers(response, file_stat=None, metadata=metadata, etag=etag, size_override=size_val, mtime_override=mtime_val)
        else:
            stat = path.stat()
            response = Response(status=200)
            _apply_object_headers(response, file_stat=stat, metadata=metadata, etag=etag)
        response.headers["Content-Type"] = metadata.get("__content_type__") or mimetypes.guess_type(object_key)[0] or "application/octet-stream"
        return response
    except (StorageError, FileNotFoundError):
        return _error_response("NoSuchKey", "Object not found", 404)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)


def _copy_object(dest_bucket: str, dest_key: str, copy_source: str) -> Response:
    """Handle S3 CopyObject operation."""
    from urllib.parse import unquote
    copy_source = unquote(copy_source)
    if copy_source.startswith("/"):
        copy_source = copy_source[1:]
    
    parts = copy_source.split("/", 1)
    if len(parts) != 2:
        return _error_response("InvalidArgument", "Invalid x-amz-copy-source format", 400)
    
    source_bucket, source_key = parts
    if not source_bucket or not source_key:
        return _error_response("InvalidArgument", "Invalid x-amz-copy-source format", 400)
    
    principal, error = _require_principal()
    if error:
        return error
    try:
        _authorize_action(principal, source_bucket, "read", object_key=source_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    
    try:
        _authorize_action(principal, dest_bucket, "write", object_key=dest_key)
    except IamError as exc:
        return _error_response("AccessDenied", str(exc), 403)
    
    storage = _storage()
    
    try:
        source_path = storage.get_object_path(source_bucket, source_key)
    except StorageError:
        return _error_response("NoSuchKey", "Source object not found", 404)

    source_stat = source_path.stat()
    source_etag = storage._compute_etag(source_path)
    source_mtime = datetime.fromtimestamp(source_stat.st_mtime, timezone.utc)

    copy_source_if_match = request.headers.get("x-amz-copy-source-if-match")
    if copy_source_if_match:
        expected_etag = copy_source_if_match.strip('"')
        if source_etag != expected_etag:
            return _error_response("PreconditionFailed", "Source ETag does not match", 412)

    copy_source_if_none_match = request.headers.get("x-amz-copy-source-if-none-match")
    if copy_source_if_none_match:
        not_expected_etag = copy_source_if_none_match.strip('"')
        if source_etag == not_expected_etag:
            return _error_response("PreconditionFailed", "Source ETag matches", 412)

    copy_source_if_modified_since = request.headers.get("x-amz-copy-source-if-modified-since")
    if copy_source_if_modified_since:
        from email.utils import parsedate_to_datetime
        try:
            if_modified = parsedate_to_datetime(copy_source_if_modified_since)
            if source_mtime <= if_modified:
                return _error_response("PreconditionFailed", "Source not modified since specified date", 412)
        except (TypeError, ValueError):
            pass

    copy_source_if_unmodified_since = request.headers.get("x-amz-copy-source-if-unmodified-since")
    if copy_source_if_unmodified_since:
        from email.utils import parsedate_to_datetime
        try:
            if_unmodified = parsedate_to_datetime(copy_source_if_unmodified_since)
            if source_mtime > if_unmodified:
                return _error_response("PreconditionFailed", "Source modified since specified date", 412)
        except (TypeError, ValueError):
            pass

    source_metadata = storage.get_object_metadata(source_bucket, source_key)

    metadata_directive = request.headers.get("x-amz-metadata-directive", "COPY").upper()
    if metadata_directive == "REPLACE":
        metadata = _extract_request_metadata()
        content_type = request.headers.get("Content-Type")
        validation_error = _validate_content_type(dest_key, content_type)
        if validation_error:
            return _error_response("InvalidArgument", validation_error, 400)
    else:
        metadata = {k: v for k, v in source_metadata.items() if not (k.startswith("__") and k.endswith("__"))}

    try:
        with source_path.open("rb") as stream:
            meta = storage.put_object(
                dest_bucket,
                dest_key,
                stream,
                metadata=metadata or None,
            )
    except StorageError as exc:
        message = str(exc)
        if "Bucket" in message:
            return _error_response("NoSuchBucket", message, 404)
        return _error_response("InvalidArgument", message, 400)
    
    current_app.logger.info(
        "Object copied",
        extra={
            "source_bucket": source_bucket,
            "source_key": source_key,
            "dest_bucket": dest_bucket,
            "dest_key": dest_key,
            "size": meta.size,
        },
    )
    
    user_agent = request.headers.get("User-Agent", "")
    if "S3ReplicationAgent" not in user_agent and "SiteSyncAgent" not in user_agent:
        _replication_manager().trigger_replication(dest_bucket, dest_key, action="write")

    root = Element("CopyObjectResult")
    SubElement(root, "LastModified").text = meta.last_modified.isoformat()
    if meta.etag:
        SubElement(root, "ETag").text = f'"{meta.etag}"'
    return _xml_response(root)


class AwsChunkedDecoder:
    """Decodes aws-chunked encoded streams.

    Performance optimized with buffered line reading instead of byte-by-byte.
    """

    def __init__(self, stream):
        self.stream = stream
        self._read_buffer = bytearray()
        self.chunk_remaining = 0
        self.finished = False

    def _read_line(self) -> bytes:
        """Read until CRLF using buffered reads instead of byte-by-byte.

        Performance: Reads in batches of 64-256 bytes instead of 1 byte at a time.
        """
        line = bytearray()
        while True:
            if self._read_buffer:
                idx = self._read_buffer.find(b"\r\n")
                if idx != -1:
                    line.extend(self._read_buffer[: idx + 2])
                    del self._read_buffer[: idx + 2]
                    return bytes(line)
                line.extend(self._read_buffer)
                self._read_buffer.clear()

            chunk = self.stream.read(64)
            if not chunk:
                return bytes(line) if line else b""
            self._read_buffer.extend(chunk)

    def _read_exact(self, n: int) -> bytes:
        """Read exactly n bytes, using buffer first."""
        result = bytearray()
        if self._read_buffer:
            take = min(len(self._read_buffer), n)
            result.extend(self._read_buffer[:take])
            del self._read_buffer[:take]
            n -= take
        if n > 0:
            data = self.stream.read(n)
            if data:
                result.extend(data)

        return bytes(result)

    def read(self, size=-1):
        if self.finished:
            return b""

        result = bytearray()
        while size == -1 or len(result) < size:
            if self.chunk_remaining > 0:
                to_read = self.chunk_remaining
                if size != -1:
                    to_read = min(to_read, size - len(result))

                chunk = self._read_exact(to_read)
                if not chunk:
                    raise IOError("Unexpected EOF in chunk data")

                result.extend(chunk)
                self.chunk_remaining -= len(chunk)

                if self.chunk_remaining == 0:
                    crlf = self._read_exact(2)
                    if crlf != b"\r\n":
                        raise IOError("Malformed chunk: missing CRLF")
            else:
                line = self._read_line()
                if not line:
                    self.finished = True
                    return bytes(result)

                try:
                    line_str = line.decode("ascii").strip()
                    if ";" in line_str:
                        line_str = line_str.split(";")[0]
                    chunk_size = int(line_str, 16)
                except ValueError:
                    raise IOError(f"Invalid chunk size: {line}")

                if chunk_size == 0:
                    self.finished = True
                    while True:
                        trailer = self._read_line()
                        if trailer == b"\r\n" or not trailer:
                            break
                    return bytes(result)

                self.chunk_remaining = chunk_size

        return bytes(result)


def _initiate_multipart_upload(bucket_name: str, object_key: str) -> Response:
    principal, error = _object_principal("write", bucket_name, object_key)
    if error:
        return error
    
    metadata = _extract_request_metadata()
    content_type = request.headers.get("Content-Type")
    metadata["__content_type__"] = content_type or mimetypes.guess_type(object_key)[0] or "application/octet-stream"
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
    copy_source = request.headers.get("x-amz-copy-source")
    if copy_source:
        return _upload_part_copy(bucket_name, object_key, copy_source)

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

    if part_number < 1 or part_number > 10000:
        return _error_response("InvalidArgument", "partNumber must be between 1 and 10000", 400)

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

    content_md5 = request.headers.get("Content-MD5")
    if content_md5 and etag:
        try:
            expected_md5 = base64.b64decode(content_md5).hex()
        except Exception:
            return _error_response("InvalidDigest", "Content-MD5 header is not valid base64", 400)
        if expected_md5 != etag:
            return _error_response("BadDigest", "The Content-MD5 you specified did not match what we received", 400)

    response = Response(status=200)
    response.headers["ETag"] = f'"{etag}"'
    return response


def _upload_part_copy(bucket_name: str, object_key: str, copy_source: str) -> Response:
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

    if part_number < 1 or part_number > 10000:
        return _error_response("InvalidArgument", "partNumber must be between 1 and 10000", 400)

    copy_source = unquote(copy_source)
    if copy_source.startswith("/"):
        copy_source = copy_source[1:]
    parts = copy_source.split("/", 1)
    if len(parts) != 2:
        return _error_response("InvalidArgument", "Invalid x-amz-copy-source format", 400)
    source_bucket, source_key = parts
    if not source_bucket or not source_key:
        return _error_response("InvalidArgument", "Invalid x-amz-copy-source format", 400)

    _, read_error = _object_principal("read", source_bucket, source_key)
    if read_error:
        return read_error

    copy_source_range = request.headers.get("x-amz-copy-source-range")
    start_byte, end_byte = None, None
    if copy_source_range:
        match = re.match(r"bytes=(\d+)-(\d+)", copy_source_range)
        if not match:
            return _error_response("InvalidArgument", "Invalid x-amz-copy-source-range format", 400)
        start_byte, end_byte = int(match.group(1)), int(match.group(2))

    try:
        result = _storage().upload_part_copy(
            bucket_name, upload_id, part_number,
            source_bucket, source_key,
            start_byte, end_byte
        )
    except ObjectNotFoundError:
        return _error_response("NoSuchKey", "Source object not found", 404)
    except StorageError as exc:
        if "Multipart upload not found" in str(exc):
            return _error_response("NoSuchUpload", str(exc), 404)
        if "Invalid byte range" in str(exc):
            return _error_response("InvalidRange", str(exc), 416)
        return _error_response("InvalidArgument", str(exc), 400)

    root = Element("CopyPartResult")
    SubElement(root, "LastModified").text = result["last_modified"].strftime("%Y-%m-%dT%H:%M:%S.000Z")
    SubElement(root, "ETag").text = f'"{result["etag"]}"'
    return _xml_response(root)


def _complete_multipart_upload(bucket_name: str, object_key: str) -> Response:
    principal, error = _object_principal("write", bucket_name, object_key)
    if error:
        return error

    upload_id = request.args.get("uploadId")
    if not upload_id:
        return _error_response("InvalidArgument", "uploadId is required", 400)

    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)
    
    if _strip_ns(root.tag) != "CompleteMultipartUpload":
        return _error_response("MalformedXML", "Root element must be CompleteMultipartUpload", 400)

    parts = []
    for part_el in list(root):
        if _strip_ns(part_el.tag) != "Part":
            continue
        part_number_el = part_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}PartNumber")
        if part_number_el is None:
            part_number_el = part_el.find("PartNumber")
        
        etag_el = part_el.find("{http://s3.amazonaws.com/doc/2006-03-01/}ETag")
        if etag_el is None:
            etag_el = part_el.find("ETag")
            
        if part_number_el is not None and etag_el is not None:
            try:
                part_num = int(part_number_el.text or 0)
            except ValueError:
                return _error_response("InvalidArgument", "PartNumber must be an integer", 400)
            if part_num < 1 or part_num > 10000:
                return _error_response("InvalidArgument", f"PartNumber {part_num} must be between 1 and 10000", 400)
            parts.append({
                "PartNumber": part_num,
                "ETag": (etag_el.text or "").strip('"')
            })

    try:
        meta = _storage().complete_multipart_upload(bucket_name, upload_id, parts)
    except QuotaExceededError as exc:
        return _error_response("QuotaExceeded", str(exc), 403)
    except StorageError as exc:
        if "NoSuchBucket" in str(exc):
            return _error_response("NoSuchBucket", str(exc), 404)
        if "Multipart upload not found" in str(exc):
            return _error_response("NoSuchUpload", str(exc), 404)
        return _error_response("InvalidPart", str(exc), 400)

    user_agent = request.headers.get("User-Agent", "")
    if "S3ReplicationAgent" not in user_agent and "SiteSyncAgent" not in user_agent:
        _replication_manager().trigger_replication(bucket_name, object_key, action="write")

    root = Element("CompleteMultipartUploadResult")
    location = f"{request.host_url}{bucket_name}/{object_key}"
    SubElement(root, "Location").text = location
    SubElement(root, "Bucket").text = bucket_name
    SubElement(root, "Key").text = object_key
    if meta.etag:
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
    except BucketNotFoundError as exc:
        return _error_response("NoSuchBucket", str(exc), 404)
    except StorageError as exc:
        current_app.logger.warning(f"Error aborting multipart upload: {exc}")

    return Response(status=204)


def _select_object_content(bucket_name: str, object_key: str) -> Response:
    _, error = _object_principal("read", bucket_name, object_key)
    if error:
        return error
    ct_error = _require_xml_content_type()
    if ct_error:
        return ct_error
    payload = request.get_data(cache=False) or b""
    try:
        root = _parse_xml_with_limit(payload)
    except ParseError:
        return _error_response("MalformedXML", "Unable to parse XML document", 400)
    if _strip_ns(root.tag) != "SelectObjectContentRequest":
        return _error_response("MalformedXML", "Root element must be SelectObjectContentRequest", 400)
    expression_el = _find_element(root, "Expression")
    if expression_el is None or not expression_el.text:
        return _error_response("InvalidRequest", "Expression is required", 400)
    expression = expression_el.text
    expression_type_el = _find_element(root, "ExpressionType")
    expression_type = expression_type_el.text if expression_type_el is not None and expression_type_el.text else "SQL"
    if expression_type.upper() != "SQL":
        return _error_response("InvalidRequest", "Only SQL expression type is supported", 400)
    input_el = _find_element(root, "InputSerialization")
    if input_el is None:
        return _error_response("InvalidRequest", "InputSerialization is required", 400)
    try:
        input_format, input_config = _parse_select_input_serialization(input_el)
    except ValueError as exc:
        return _error_response("InvalidRequest", str(exc), 400)
    output_el = _find_element(root, "OutputSerialization")
    if output_el is None:
        return _error_response("InvalidRequest", "OutputSerialization is required", 400)
    try:
        output_format, output_config = _parse_select_output_serialization(output_el)
    except ValueError as exc:
        return _error_response("InvalidRequest", str(exc), 400)
    storage = _storage()
    try:
        path = storage.get_object_path(bucket_name, object_key)
    except ObjectNotFoundError:
        return _error_response("NoSuchKey", "Object not found", 404)
    except StorageError:
        return _error_response("NoSuchKey", "Object not found", 404)
    from .select_content import execute_select_query, SelectError
    try:
        result_stream = execute_select_query(
            file_path=path,
            expression=expression,
            input_format=input_format,
            input_config=input_config,
            output_format=output_format,
            output_config=output_config,
        )
    except SelectError as exc:
        return _error_response("InvalidRequest", str(exc), 400)

    def generate_events():
        bytes_scanned = 0
        bytes_returned = 0
        for chunk in result_stream:
            bytes_returned += len(chunk)
            yield _encode_select_event("Records", chunk)
        stats_payload = _build_stats_xml(bytes_scanned, bytes_returned)
        yield _encode_select_event("Stats", stats_payload)
        yield _encode_select_event("End", b"")

    return Response(generate_events(), mimetype="application/octet-stream", headers={"x-amz-request-charged": "requester"})


def _parse_select_input_serialization(el: Element) -> tuple:
    csv_el = _find_element(el, "CSV")
    if csv_el is not None:
        file_header_el = _find_element(csv_el, "FileHeaderInfo")
        config = {
            "file_header_info": file_header_el.text.upper() if file_header_el is not None and file_header_el.text else "NONE",
            "comments": _find_element_text(csv_el, "Comments", "#"),
            "field_delimiter": _find_element_text(csv_el, "FieldDelimiter", ","),
            "record_delimiter": _find_element_text(csv_el, "RecordDelimiter", "\n"),
            "quote_character": _find_element_text(csv_el, "QuoteCharacter", '"'),
            "quote_escape_character": _find_element_text(csv_el, "QuoteEscapeCharacter", '"'),
        }
        return "CSV", config
    json_el = _find_element(el, "JSON")
    if json_el is not None:
        type_el = _find_element(json_el, "Type")
        config = {
            "type": type_el.text.upper() if type_el is not None and type_el.text else "DOCUMENT",
        }
        return "JSON", config
    parquet_el = _find_element(el, "Parquet")
    if parquet_el is not None:
        return "Parquet", {}
    raise ValueError("InputSerialization must specify CSV, JSON, or Parquet")


def _parse_select_output_serialization(el: Element) -> tuple:
    csv_el = _find_element(el, "CSV")
    if csv_el is not None:
        config = {
            "field_delimiter": _find_element_text(csv_el, "FieldDelimiter", ","),
            "record_delimiter": _find_element_text(csv_el, "RecordDelimiter", "\n"),
            "quote_character": _find_element_text(csv_el, "QuoteCharacter", '"'),
            "quote_fields": _find_element_text(csv_el, "QuoteFields", "ASNEEDED").upper(),
        }
        return "CSV", config
    json_el = _find_element(el, "JSON")
    if json_el is not None:
        config = {
            "record_delimiter": _find_element_text(json_el, "RecordDelimiter", "\n"),
        }
        return "JSON", config
    raise ValueError("OutputSerialization must specify CSV or JSON")


def _encode_select_event(event_type: str, payload: bytes) -> bytes:
    import struct
    import binascii
    headers = _build_event_headers(event_type)
    headers_length = len(headers)
    total_length = 4 + 4 + 4 + headers_length + len(payload) + 4
    prelude = struct.pack(">I", total_length) + struct.pack(">I", headers_length)
    prelude_crc = binascii.crc32(prelude) & 0xffffffff
    prelude += struct.pack(">I", prelude_crc)
    message = prelude + headers + payload
    message_crc = binascii.crc32(message) & 0xffffffff
    message += struct.pack(">I", message_crc)
    return message


def _build_event_headers(event_type: str) -> bytes:
    headers = b""
    headers += _encode_select_header(":event-type", event_type)
    if event_type == "Records":
        headers += _encode_select_header(":content-type", "application/octet-stream")
    elif event_type == "Stats":
        headers += _encode_select_header(":content-type", "text/xml")
    headers += _encode_select_header(":message-type", "event")
    return headers


def _encode_select_header(name: str, value: str) -> bytes:
    import struct
    name_bytes = name.encode("utf-8")
    value_bytes = value.encode("utf-8")
    header = struct.pack("B", len(name_bytes)) + name_bytes
    header += struct.pack("B", 7)
    header += struct.pack(">H", len(value_bytes)) + value_bytes
    return header


def _build_stats_xml(bytes_scanned: int, bytes_returned: int) -> bytes:
    stats = Element("Stats")
    SubElement(stats, "BytesScanned").text = str(bytes_scanned)
    SubElement(stats, "BytesProcessed").text = str(bytes_scanned)
    SubElement(stats, "BytesReturned").text = str(bytes_returned)
    return tostring(stats, encoding="utf-8")


@s3_api_bp.before_request
def resolve_principal():
    g.principal = None
    try:
        if ("Authorization" in request.headers and request.headers["Authorization"].startswith("AWS4-HMAC-SHA256")) or \
           (request.args.get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"):
            g.principal = _verify_sigv4(request)
            return
    except IamError as exc:
        logger.debug(f"SigV4 authentication failed: {exc}")
    except (ValueError, KeyError) as exc:
        logger.debug(f"SigV4 parsing error: {exc}")

    access_key = request.headers.get("X-Access-Key")
    secret_key = request.headers.get("X-Secret-Key")
    if access_key and secret_key:
        try:
            g.principal = _iam().authenticate(access_key, secret_key)
        except IamError as exc:
            logger.debug(f"Header authentication failed: {exc}")
