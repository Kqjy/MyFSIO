from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SiteInfo:
    site_id: str
    endpoint: str
    region: str = "us-east-1"
    priority: int = 100
    display_name: str = ""
    created_at: Optional[float] = None
    updated_at: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.display_name:
            self.display_name = self.site_id
        if self.created_at is None:
            self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_id": self.site_id,
            "endpoint": self.endpoint,
            "region": self.region,
            "priority": self.priority,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SiteInfo:
        return cls(
            site_id=data["site_id"],
            endpoint=data.get("endpoint", ""),
            region=data.get("region", "us-east-1"),
            priority=data.get("priority", 100),
            display_name=data.get("display_name", ""),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


@dataclass
class PeerSite:
    site_id: str
    endpoint: str
    region: str = "us-east-1"
    priority: int = 100
    display_name: str = ""
    created_at: Optional[float] = None
    updated_at: Optional[float] = None
    connection_id: Optional[str] = None
    is_healthy: Optional[bool] = None
    last_health_check: Optional[float] = None

    def __post_init__(self) -> None:
        if not self.display_name:
            self.display_name = self.site_id
        if self.created_at is None:
            self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "site_id": self.site_id,
            "endpoint": self.endpoint,
            "region": self.region,
            "priority": self.priority,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "connection_id": self.connection_id,
            "is_healthy": self.is_healthy,
            "last_health_check": self.last_health_check,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PeerSite:
        return cls(
            site_id=data["site_id"],
            endpoint=data.get("endpoint", ""),
            region=data.get("region", "us-east-1"),
            priority=data.get("priority", 100),
            display_name=data.get("display_name", ""),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            connection_id=data.get("connection_id"),
            is_healthy=data.get("is_healthy"),
            last_health_check=data.get("last_health_check"),
        )


class SiteRegistry:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self._local_site: Optional[SiteInfo] = None
        self._peers: Dict[str, PeerSite] = {}
        self.reload()

    def reload(self) -> None:
        if not self.config_path.exists():
            self._local_site = None
            self._peers = {}
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if data.get("local"):
                self._local_site = SiteInfo.from_dict(data["local"])
            else:
                self._local_site = None

            self._peers = {}
            for peer_data in data.get("peers", []):
                peer = PeerSite.from_dict(peer_data)
                self._peers[peer.site_id] = peer

        except (OSError, json.JSONDecodeError, KeyError):
            self._local_site = None
            self._peers = {}

    def save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "local": self._local_site.to_dict() if self._local_site else None,
            "peers": [peer.to_dict() for peer in self._peers.values()],
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def get_local_site(self) -> Optional[SiteInfo]:
        return self._local_site

    def set_local_site(self, site: SiteInfo) -> None:
        site.updated_at = time.time()
        self._local_site = site
        self.save()

    def list_peers(self) -> List[PeerSite]:
        return list(self._peers.values())

    def get_peer(self, site_id: str) -> Optional[PeerSite]:
        return self._peers.get(site_id)

    def add_peer(self, peer: PeerSite) -> None:
        peer.created_at = peer.created_at or time.time()
        self._peers[peer.site_id] = peer
        self.save()

    def update_peer(self, peer: PeerSite) -> None:
        if peer.site_id not in self._peers:
            raise ValueError(f"Peer {peer.site_id} not found")
        peer.updated_at = time.time()
        self._peers[peer.site_id] = peer
        self.save()

    def delete_peer(self, site_id: str) -> bool:
        if site_id in self._peers:
            del self._peers[site_id]
            self.save()
            return True
        return False

    def update_health(self, site_id: str, is_healthy: bool) -> None:
        peer = self._peers.get(site_id)
        if peer:
            peer.is_healthy = is_healthy
            peer.last_health_check = time.time()
            self.save()
