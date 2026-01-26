from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, Response, current_app, jsonify, request

from .connections import ConnectionStore
from .extensions import limiter
from .iam import IamError, Principal
from .replication import ReplicationManager
from .site_registry import PeerSite, SiteInfo, SiteRegistry

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
    if not endpoint:
        return _json_error("ValidationError", "endpoint is required", 400)

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
        region=payload.get("region", "us-east-1"),
        priority=payload.get("priority", 100),
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
