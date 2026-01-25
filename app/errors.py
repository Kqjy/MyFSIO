from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from xml.etree.ElementTree import Element, SubElement, tostring

from flask import Response, jsonify, request, flash, redirect, url_for, g
from flask_limiter import RateLimitExceeded

logger = logging.getLogger(__name__)


@dataclass
class AppError(Exception):
    """Base application error with multi-format response support."""
    code: str
    message: str
    status_code: int = 500
    details: Optional[Dict[str, Any]] = field(default=None)
    
    def __post_init__(self):
        super().__init__(self.message)
    
    def to_xml_response(self) -> Response:
        """Convert to S3 API XML error response."""
        error = Element("Error")
        SubElement(error, "Code").text = self.code
        SubElement(error, "Message").text = self.message
        request_id = getattr(g, 'request_id', None) if g else None
        SubElement(error, "RequestId").text = request_id or "unknown"
        xml_bytes = tostring(error, encoding="utf-8")
        return Response(xml_bytes, status=self.status_code, mimetype="application/xml")
    
    def to_json_response(self) -> tuple[Response, int]:
        """Convert to JSON error response for UI AJAX calls."""
        payload: Dict[str, Any] = {
            "success": False,
            "error": {
                "code": self.code,
                "message": self.message
            }
        }
        if self.details:
            payload["error"]["details"] = self.details
        return jsonify(payload), self.status_code
    
    def to_flash_message(self) -> str:
        """Convert to user-friendly flash message."""
        return self.message


@dataclass
class BucketNotFoundError(AppError):
    """Bucket does not exist."""
    code: str = "NoSuchBucket"
    message: str = "The specified bucket does not exist"
    status_code: int = 404


@dataclass
class BucketAlreadyExistsError(AppError):
    """Bucket already exists."""
    code: str = "BucketAlreadyExists"
    message: str = "The requested bucket name is not available"
    status_code: int = 409


@dataclass
class BucketNotEmptyError(AppError):
    """Bucket is not empty."""
    code: str = "BucketNotEmpty"
    message: str = "The bucket you tried to delete is not empty"
    status_code: int = 409


@dataclass
class ObjectNotFoundError(AppError):
    """Object does not exist."""
    code: str = "NoSuchKey"
    message: str = "The specified key does not exist"
    status_code: int = 404


@dataclass
class InvalidObjectKeyError(AppError):
    """Invalid object key."""
    code: str = "InvalidKey"
    message: str = "The specified key is not valid"
    status_code: int = 400


@dataclass
class AccessDeniedError(AppError):
    """Access denied."""
    code: str = "AccessDenied"
    message: str = "Access Denied"
    status_code: int = 403


@dataclass
class InvalidCredentialsError(AppError):
    """Invalid credentials."""
    code: str = "InvalidAccessKeyId"
    message: str = "The access key ID you provided does not exist"
    status_code: int = 403

@dataclass
class MalformedRequestError(AppError):
    """Malformed request."""
    code: str = "MalformedXML"
    message: str = "The XML you provided was not well-formed"
    status_code: int = 400


@dataclass
class InvalidArgumentError(AppError):
    """Invalid argument."""
    code: str = "InvalidArgument"
    message: str = "Invalid argument"
    status_code: int = 400


@dataclass
class EntityTooLargeError(AppError):
    """Entity too large."""
    code: str = "EntityTooLarge"
    message: str = "Your proposed upload exceeds the maximum allowed size"
    status_code: int = 413


@dataclass
class QuotaExceededAppError(AppError):
    """Bucket quota exceeded."""
    code: str = "QuotaExceeded"
    message: str = "The bucket quota has been exceeded"
    status_code: int = 403
    quota: Optional[Dict[str, Any]] = None
    usage: Optional[Dict[str, int]] = None
    
    def __post_init__(self):
        if self.quota or self.usage:
            self.details = {}
            if self.quota:
                self.details["quota"] = self.quota
            if self.usage:
                self.details["usage"] = self.usage
        super().__post_init__()


def handle_app_error(error: AppError) -> Response:
    """Handle application errors with appropriate response format."""
    log_extra = {"error_code": error.code}
    if error.details:
        log_extra["details"] = error.details
    
    logger.error(f"{error.code}: {error.message}", extra=log_extra)
    
    if request.path.startswith('/ui'):
        wants_json = (
            request.is_json or 
            request.headers.get('X-Requested-With') == 'XMLHttpRequest' or
            'application/json' in request.accept_mimetypes.values()
        )
        if wants_json:
            return error.to_json_response()
        flash(error.to_flash_message(), 'danger')
        referrer = request.referrer
        if referrer and request.host in referrer:
            return redirect(referrer)
        return redirect(url_for('ui.buckets_overview'))
    else:
        return error.to_xml_response()


def handle_rate_limit_exceeded(e: RateLimitExceeded) -> Response:
    g.s3_error_code = "SlowDown"
    error = Element("Error")
    SubElement(error, "Code").text = "SlowDown"
    SubElement(error, "Message").text = "Please reduce your request rate."
    SubElement(error, "Resource").text = request.path
    SubElement(error, "RequestId").text = getattr(g, "request_id", "")
    xml_bytes = tostring(error, encoding="utf-8")
    return Response(xml_bytes, status=429, mimetype="application/xml")


def register_error_handlers(app):
    """Register error handlers with a Flask app."""
    app.register_error_handler(AppError, handle_app_error)
    app.register_error_handler(RateLimitExceeded, handle_rate_limit_exceeded)

    for error_class in [
        BucketNotFoundError, BucketAlreadyExistsError, BucketNotEmptyError,
        ObjectNotFoundError, InvalidObjectKeyError,
        AccessDeniedError, InvalidCredentialsError,
        MalformedRequestError, InvalidArgumentError, EntityTooLargeError,
        QuotaExceededAppError,
    ]:
        app.register_error_handler(error_class, handle_app_error)
