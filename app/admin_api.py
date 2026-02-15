from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
from flask import Blueprint, Response, current_app, jsonify, request

from .connections import ConnectionStore
from .extensions import limiter
from .iam import IamError, Principal
from .replication import ReplicationManager
from .site_registry import PeerSite, SiteInfo, SiteRegistry
from .website_domains import WebsiteDomainStore, normalize_domain, is_valid_domain


def _is_safe_url(url: str, allow_internal: bool = False) -> bool:
    """Check if a URL is safe to make requests to (not internal/private).

    Args:
        url: The URL to check.
        allow_internal: If True, allows internal/private IP addresses.
                       Use for self-hosted deployments on internal networks.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        cloud_metadata_hosts = {
            "metadata.google.internal",
            "169.254.169.254",
        }
        if hostname.lower() in cloud_metadata_hosts:
            return False
        if allow_internal:
            return True
        blocked_hosts = {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
        }
        if hostname.lower() in blocked_hosts:
            return False
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(resolved_ip)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except (socket.gaierror, ValueError):
            return False
        return True
    except Exception:
        return False


def _validate_endpoint(endpoint: str) -> Optional[str]:
    """Validate endpoint URL format. Returns error message or None."""
    try:
        parsed = urlparse(endpoint)
        if not parsed.scheme or parsed.scheme not in ("http", "https"):
            return "Endpoint must be http or https URL"
        if not parsed.netloc:
            return "Endpoint must have a host"
        return None
    except Exception:
        return "Invalid endpoint URL"


def _validate_priority(priority: Any) -> Optional[str]:
    """Validate priority value. Returns error message or None."""
    try:
        p = int(priority)
        if p < 0 or p > 1000:
            return "Priority must be between 0 and 1000"
        return None
    except (TypeError, ValueError):
        return "Priority must be an integer"


def _validate_region(region: str) -> Optional[str]:
    """Validate region format. Returns error message or None."""
    if not re.match(r"^[a-z]{2,}-[a-z]+-\d+$", region):
        return "Region must match format like us-east-1"
    return None


def _validate_site_id(site_id: str) -> Optional[str]:
    """Validate site_id format. Returns error message or None."""
    if not site_id or len(site_id) > 63:
        return "site_id must be 1-63 characters"
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$', site_id):
        return "site_id must start with alphanumeric and contain only alphanumeric, hyphens, underscores"
    return None


logger = logging.getLogger(__name__)

admin_api_bp = Blueprint("admin_api", __name__, url_prefix="/admin")


def _require_principal() -> Tuple[Optional[Principal], Optional[Tuple[Dict[str, Any], int]]]:
    from .s3_api import _require_principal as s3_require_principal
    return s3_require_principal()


def _require_admin() -> Tuple[Optional[Principal], Optional[Tuple[Dict[str, Any], int]]]:
    principal, error = _require_principal()
    if error:
        return None, error

    try:
        _iam().authorize(principal, None, "iam:*")
        return principal, None
    except IamError:
        return None, _json_error("AccessDenied", "Admin access required", 403)


def _site_registry() -> SiteRegistry:
    return current_app.extensions["site_registry"]


def _connections() -> ConnectionStore:
    return current_app.extensions["connections"]


def _replication() -> ReplicationManager:
    return current_app.extensions["replication"]


def _iam():
    return current_app.extensions["iam"]


def _json_error(code: str, message: str, status: int) -> Tuple[Dict[str, Any], int]:
    return {"error": {"code": code, "message": message}}, status


def _get_admin_rate_limit() -> str:
    return current_app.config.get("RATE_LIMIT_ADMIN", "60 per minute")


@admin_api_bp.route("/site", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def get_local_site():
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    local_site = registry.get_local_site()

    if local_site:
        return jsonify(local_site.to_dict())

    config_site_id = current_app.config.get("SITE_ID")
    config_endpoint = current_app.config.get("SITE_ENDPOINT")

    if config_site_id:
        return jsonify({
            "site_id": config_site_id,
            "endpoint": config_endpoint or "",
            "region": current_app.config.get("SITE_REGION", "us-east-1"),
            "priority": current_app.config.get("SITE_PRIORITY", 100),
            "display_name": config_site_id,
            "source": "environment",
        })

    return _json_error("NotFound", "Local site not configured", 404)


@admin_api_bp.route("/site", methods=["PUT"])
@limiter.limit(lambda: _get_admin_rate_limit())
def update_local_site():
    principal, error = _require_admin()
    if error:
        return error

    payload = request.get_json(silent=True) or {}

    site_id = payload.get("site_id")
    endpoint = payload.get("endpoint")

    if not site_id:
        return _json_error("ValidationError", "site_id is required", 400)

    site_id_error = _validate_site_id(site_id)
    if site_id_error:
        return _json_error("ValidationError", site_id_error, 400)

    if endpoint:
        endpoint_error = _validate_endpoint(endpoint)
        if endpoint_error:
            return _json_error("ValidationError", endpoint_error, 400)

    if "priority" in payload:
        priority_error = _validate_priority(payload["priority"])
        if priority_error:
            return _json_error("ValidationError", priority_error, 400)

    if "region" in payload:
        region_error = _validate_region(payload["region"])
        if region_error:
            return _json_error("ValidationError", region_error, 400)

    registry = _site_registry()
    existing = registry.get_local_site()

    site = SiteInfo(
        site_id=site_id,
        endpoint=endpoint or "",
        region=payload.get("region", "us-east-1"),
        priority=payload.get("priority", 100),
        display_name=payload.get("display_name", site_id),
        created_at=existing.created_at if existing else None,
    )

    registry.set_local_site(site)

    logger.info("Local site updated", extra={"site_id": site_id, "principal": principal.access_key})
    return jsonify(site.to_dict())


@admin_api_bp.route("/sites", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def list_all_sites():
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    local = registry.get_local_site()
    peers = registry.list_peers()

    result = {
        "local": local.to_dict() if local else None,
        "peers": [peer.to_dict() for peer in peers],
        "total_peers": len(peers),
    }

    return jsonify(result)


@admin_api_bp.route("/sites", methods=["POST"])
@limiter.limit(lambda: _get_admin_rate_limit())
def register_peer_site():
    principal, error = _require_admin()
    if error:
        return error

    payload = request.get_json(silent=True) or {}

    site_id = payload.get("site_id")
    endpoint = payload.get("endpoint")

    if not site_id:
        return _json_error("ValidationError", "site_id is required", 400)

    site_id_error = _validate_site_id(site_id)
    if site_id_error:
        return _json_error("ValidationError", site_id_error, 400)

    if not endpoint:
        return _json_error("ValidationError", "endpoint is required", 400)

    endpoint_error = _validate_endpoint(endpoint)
    if endpoint_error:
        return _json_error("ValidationError", endpoint_error, 400)

    region = payload.get("region", "us-east-1")
    region_error = _validate_region(region)
    if region_error:
        return _json_error("ValidationError", region_error, 400)

    priority = payload.get("priority", 100)
    priority_error = _validate_priority(priority)
    if priority_error:
        return _json_error("ValidationError", priority_error, 400)

    registry = _site_registry()

    if registry.get_peer(site_id):
        return _json_error("AlreadyExists", f"Peer site '{site_id}' already exists", 409)

    connection_id = payload.get("connection_id")
    if connection_id:
        if not _connections().get(connection_id):
            return _json_error("ValidationError", f"Connection '{connection_id}' not found", 400)

    peer = PeerSite(
        site_id=site_id,
        endpoint=endpoint,
        region=region,
        priority=int(priority),
        display_name=payload.get("display_name", site_id),
        connection_id=connection_id,
    )

    registry.add_peer(peer)

    logger.info("Peer site registered", extra={"site_id": site_id, "principal": principal.access_key})
    return jsonify(peer.to_dict()), 201


@admin_api_bp.route("/sites/<site_id>", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def get_peer_site(site_id: str):
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    peer = registry.get_peer(site_id)

    if not peer:
        return _json_error("NotFound", f"Peer site '{site_id}' not found", 404)

    return jsonify(peer.to_dict())


@admin_api_bp.route("/sites/<site_id>", methods=["PUT"])
@limiter.limit(lambda: _get_admin_rate_limit())
def update_peer_site(site_id: str):
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    existing = registry.get_peer(site_id)

    if not existing:
        return _json_error("NotFound", f"Peer site '{site_id}' not found", 404)

    payload = request.get_json(silent=True) or {}

    if "endpoint" in payload:
        endpoint_error = _validate_endpoint(payload["endpoint"])
        if endpoint_error:
            return _json_error("ValidationError", endpoint_error, 400)

    if "priority" in payload:
        priority_error = _validate_priority(payload["priority"])
        if priority_error:
            return _json_error("ValidationError", priority_error, 400)

    if "region" in payload:
        region_error = _validate_region(payload["region"])
        if region_error:
            return _json_error("ValidationError", region_error, 400)

    if "connection_id" in payload:
        if payload["connection_id"] and not _connections().get(payload["connection_id"]):
            return _json_error("ValidationError", f"Connection '{payload['connection_id']}' not found", 400)

    peer = PeerSite(
        site_id=site_id,
        endpoint=payload.get("endpoint", existing.endpoint),
        region=payload.get("region", existing.region),
        priority=payload.get("priority", existing.priority),
        display_name=payload.get("display_name", existing.display_name),
        connection_id=payload.get("connection_id", existing.connection_id),
        created_at=existing.created_at,
        is_healthy=existing.is_healthy,
        last_health_check=existing.last_health_check,
    )

    registry.update_peer(peer)

    logger.info("Peer site updated", extra={"site_id": site_id, "principal": principal.access_key})
    return jsonify(peer.to_dict())


@admin_api_bp.route("/sites/<site_id>", methods=["DELETE"])
@limiter.limit(lambda: _get_admin_rate_limit())
def delete_peer_site(site_id: str):
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()

    if not registry.delete_peer(site_id):
        return _json_error("NotFound", f"Peer site '{site_id}' not found", 404)

    logger.info("Peer site deleted", extra={"site_id": site_id, "principal": principal.access_key})
    return Response(status=204)


@admin_api_bp.route("/sites/<site_id>/health", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def check_peer_health(site_id: str):
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    peer = registry.get_peer(site_id)

    if not peer:
        return _json_error("NotFound", f"Peer site '{site_id}' not found", 404)

    is_healthy = False
    error_message = None

    if peer.connection_id:
        connection = _connections().get(peer.connection_id)
        if connection:
            is_healthy = _replication().check_endpoint_health(connection)
        else:
            error_message = f"Connection '{peer.connection_id}' not found"
    else:
        error_message = "No connection configured for this peer"

    registry.update_health(site_id, is_healthy)

    result = {
        "site_id": site_id,
        "is_healthy": is_healthy,
        "checked_at": time.time(),
    }
    if error_message:
        result["error"] = error_message

    return jsonify(result)


@admin_api_bp.route("/topology", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def get_topology():
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    local = registry.get_local_site()
    peers = registry.list_peers()

    sites = []

    if local:
        sites.append({
            **local.to_dict(),
            "is_local": True,
            "is_healthy": True,
        })

    for peer in peers:
        sites.append({
            **peer.to_dict(),
            "is_local": False,
        })

    sites.sort(key=lambda s: s.get("priority", 100))

    return jsonify({
        "sites": sites,
        "total": len(sites),
        "healthy_count": sum(1 for s in sites if s.get("is_healthy")),
    })


@admin_api_bp.route("/sites/<site_id>/bidirectional-status", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def check_bidirectional_status(site_id: str):
    principal, error = _require_admin()
    if error:
        return error

    registry = _site_registry()
    peer = registry.get_peer(site_id)

    if not peer:
        return _json_error("NotFound", f"Peer site '{site_id}' not found", 404)

    local_site = registry.get_local_site()
    replication = _replication()
    local_rules = replication.list_rules()

    local_bidir_rules = []
    for rule in local_rules:
        if rule.target_connection_id == peer.connection_id and rule.mode == "bidirectional":
            local_bidir_rules.append({
                "bucket_name": rule.bucket_name,
                "target_bucket": rule.target_bucket,
                "enabled": rule.enabled,
            })

    result = {
        "site_id": site_id,
        "local_site_id": local_site.site_id if local_site else None,
        "local_endpoint": local_site.endpoint if local_site else None,
        "local_bidirectional_rules": local_bidir_rules,
        "local_site_sync_enabled": current_app.config.get("SITE_SYNC_ENABLED", False),
        "remote_status": None,
        "issues": [],
        "is_fully_configured": False,
    }

    if not local_site or not local_site.site_id:
        result["issues"].append({
            "code": "NO_LOCAL_SITE_ID",
            "message": "Local site identity not configured",
            "severity": "error",
        })

    if not local_site or not local_site.endpoint:
        result["issues"].append({
            "code": "NO_LOCAL_ENDPOINT",
            "message": "Local site endpoint not configured (remote site cannot reach back)",
            "severity": "error",
        })

    if not peer.connection_id:
        result["issues"].append({
            "code": "NO_CONNECTION",
            "message": "No connection configured for this peer",
            "severity": "error",
        })
        return jsonify(result)

    connection = _connections().get(peer.connection_id)
    if not connection:
        result["issues"].append({
            "code": "CONNECTION_NOT_FOUND",
            "message": f"Connection '{peer.connection_id}' not found",
            "severity": "error",
        })
        return jsonify(result)

    if not local_bidir_rules:
        result["issues"].append({
            "code": "NO_LOCAL_BIDIRECTIONAL_RULES",
            "message": "No bidirectional replication rules configured on this site",
            "severity": "warning",
        })

    if not result["local_site_sync_enabled"]:
        result["issues"].append({
            "code": "SITE_SYNC_DISABLED",
            "message": "Site sync worker is disabled (SITE_SYNC_ENABLED=false). Pull operations will not work.",
            "severity": "warning",
        })

    if not replication.check_endpoint_health(connection):
        result["issues"].append({
            "code": "REMOTE_UNREACHABLE",
            "message": "Remote endpoint is not reachable",
            "severity": "error",
        })
        return jsonify(result)

    allow_internal = current_app.config.get("ALLOW_INTERNAL_ENDPOINTS", False)
    if not _is_safe_url(peer.endpoint, allow_internal=allow_internal):
        result["issues"].append({
            "code": "ENDPOINT_NOT_ALLOWED",
            "message": "Peer endpoint points to cloud metadata service (SSRF protection)",
            "severity": "error",
        })
        return jsonify(result)

    try:
        admin_url = peer.endpoint.rstrip("/") + "/admin/sites"
        resp = requests.get(
            admin_url,
            timeout=10,
            headers={
                "Accept": "application/json",
                "X-Access-Key": connection.access_key,
                "X-Secret-Key": connection.secret_key,
            },
        )

        if resp.status_code == 200:
            try:
                remote_data = resp.json()
                if not isinstance(remote_data, dict):
                    raise ValueError("Expected JSON object")
                remote_local = remote_data.get("local")
                if remote_local is not None and not isinstance(remote_local, dict):
                    raise ValueError("Expected 'local' to be an object")
                remote_peers = remote_data.get("peers", [])
                if not isinstance(remote_peers, list):
                    raise ValueError("Expected 'peers' to be a list")
            except (ValueError, json.JSONDecodeError) as e:
                logger.warning("Invalid JSON from remote admin API: %s", e)
                result["remote_status"] = {"reachable": True, "invalid_response": True}
                result["issues"].append({
                    "code": "REMOTE_INVALID_RESPONSE",
                    "message": "Remote admin API returned invalid JSON",
                    "severity": "warning",
                })
                return jsonify(result)

            result["remote_status"] = {
                "reachable": True,
                "local_site": remote_local,
                "site_sync_enabled": None,
                "has_peer_for_us": False,
                "peer_connection_configured": False,
                "has_bidirectional_rules_for_us": False,
            }

            for rp in remote_peers:
                if not isinstance(rp, dict):
                    continue
                if local_site and (
                    rp.get("site_id") == local_site.site_id or
                    rp.get("endpoint") == local_site.endpoint
                ):
                    result["remote_status"]["has_peer_for_us"] = True
                    result["remote_status"]["peer_connection_configured"] = bool(rp.get("connection_id"))
                    break

            if not result["remote_status"]["has_peer_for_us"]:
                result["issues"].append({
                    "code": "REMOTE_NO_PEER_FOR_US",
                    "message": "Remote site does not have this site registered as a peer",
                    "severity": "error",
                })
            elif not result["remote_status"]["peer_connection_configured"]:
                result["issues"].append({
                    "code": "REMOTE_NO_CONNECTION_FOR_US",
                    "message": "Remote site has us as peer but no connection configured (cannot push back)",
                    "severity": "error",
                })
        elif resp.status_code == 401 or resp.status_code == 403:
            result["remote_status"] = {
                "reachable": True,
                "admin_access_denied": True,
            }
            result["issues"].append({
                "code": "REMOTE_ADMIN_ACCESS_DENIED",
                "message": "Cannot verify remote configuration (admin access denied)",
                "severity": "warning",
            })
        else:
            result["remote_status"] = {
                "reachable": True,
                "admin_api_error": resp.status_code,
            }
            result["issues"].append({
                "code": "REMOTE_ADMIN_API_ERROR",
                "message": f"Remote admin API returned status {resp.status_code}",
                "severity": "warning",
            })
    except requests.RequestException as e:
        logger.warning("Remote admin API unreachable: %s", e)
        result["remote_status"] = {
            "reachable": False,
            "error": "Connection failed",
        }
        result["issues"].append({
            "code": "REMOTE_ADMIN_UNREACHABLE",
            "message": "Could not reach remote admin API",
            "severity": "warning",
        })
    except Exception as e:
        logger.warning("Error checking remote bidirectional status: %s", e, exc_info=True)
        result["issues"].append({
            "code": "VERIFICATION_ERROR",
            "message": "Internal error during verification",
            "severity": "warning",
        })

    error_issues = [i for i in result["issues"] if i["severity"] == "error"]
    result["is_fully_configured"] = len(error_issues) == 0 and len(local_bidir_rules) > 0

    return jsonify(result)


def _website_domains() -> WebsiteDomainStore:
    return current_app.extensions["website_domains"]


def _storage():
    return current_app.extensions["object_storage"]


@admin_api_bp.route("/website-domains", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def list_website_domains():
    principal, error = _require_admin()
    if error:
        return error
    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        return _json_error("InvalidRequest", "Website hosting is not enabled", 400)
    return jsonify(_website_domains().list_all())


@admin_api_bp.route("/website-domains", methods=["POST"])
@limiter.limit(lambda: _get_admin_rate_limit())
def create_website_domain():
    principal, error = _require_admin()
    if error:
        return error
    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        return _json_error("InvalidRequest", "Website hosting is not enabled", 400)
    payload = request.get_json(silent=True) or {}
    domain = normalize_domain(payload.get("domain") or "")
    bucket = (payload.get("bucket") or "").strip()
    if not domain:
        return _json_error("ValidationError", "domain is required", 400)
    if not is_valid_domain(domain):
        return _json_error("ValidationError", f"Invalid domain: '{domain}'", 400)
    if not bucket:
        return _json_error("ValidationError", "bucket is required", 400)
    storage = _storage()
    if not storage.bucket_exists(bucket):
        return _json_error("NoSuchBucket", f"Bucket '{bucket}' does not exist", 404)
    store = _website_domains()
    existing = store.get_bucket(domain)
    if existing:
        return _json_error("Conflict", f"Domain '{domain}' is already mapped to bucket '{existing}'", 409)
    store.set_mapping(domain, bucket)
    logger.info("Website domain mapping created: %s -> %s", domain, bucket)
    return jsonify({"domain": domain, "bucket": bucket}), 201


@admin_api_bp.route("/website-domains/<domain>", methods=["GET"])
@limiter.limit(lambda: _get_admin_rate_limit())
def get_website_domain(domain: str):
    principal, error = _require_admin()
    if error:
        return error
    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        return _json_error("InvalidRequest", "Website hosting is not enabled", 400)
    domain = normalize_domain(domain)
    bucket = _website_domains().get_bucket(domain)
    if not bucket:
        return _json_error("NotFound", f"No mapping found for domain '{domain}'", 404)
    return jsonify({"domain": domain, "bucket": bucket})


@admin_api_bp.route("/website-domains/<domain>", methods=["PUT"])
@limiter.limit(lambda: _get_admin_rate_limit())
def update_website_domain(domain: str):
    principal, error = _require_admin()
    if error:
        return error
    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        return _json_error("InvalidRequest", "Website hosting is not enabled", 400)
    domain = normalize_domain(domain)
    payload = request.get_json(silent=True) or {}
    bucket = (payload.get("bucket") or "").strip()
    if not bucket:
        return _json_error("ValidationError", "bucket is required", 400)
    storage = _storage()
    if not storage.bucket_exists(bucket):
        return _json_error("NoSuchBucket", f"Bucket '{bucket}' does not exist", 404)
    store = _website_domains()
    if not store.get_bucket(domain):
        return _json_error("NotFound", f"No mapping found for domain '{domain}'", 404)
    store.set_mapping(domain, bucket)
    logger.info("Website domain mapping updated: %s -> %s", domain, bucket)
    return jsonify({"domain": domain, "bucket": bucket})


@admin_api_bp.route("/website-domains/<domain>", methods=["DELETE"])
@limiter.limit(lambda: _get_admin_rate_limit())
def delete_website_domain(domain: str):
    principal, error = _require_admin()
    if error:
        return error
    if not current_app.config.get("WEBSITE_HOSTING_ENABLED", False):
        return _json_error("InvalidRequest", "Website hosting is not enabled", 400)
    domain = normalize_domain(domain)
    if not _website_domains().delete_mapping(domain):
        return _json_error("NotFound", f"No mapping found for domain '{domain}'", 404)
    logger.info("Website domain mapping deleted: %s", domain)
    return Response(status=204)
