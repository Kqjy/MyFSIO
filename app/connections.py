"""Manage remote S3 connections."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .config import AppConfig


@dataclass
class RemoteConnection:
    id: str
    name: str
    endpoint_url: str
    access_key: str
    secret_key: str
    region: str = "us-east-1"


class ConnectionStore:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self._connections: Dict[str, RemoteConnection] = {}
        self.reload()

    def reload(self) -> None:
        if not self.config_path.exists():
            self._connections = {}
            return

        try:
            with open(self.config_path, "r") as f:
                data = json.load(f)
                for item in data:
                    conn = RemoteConnection(**item)
                    self._connections[conn.id] = conn
        except (OSError, json.JSONDecodeError):
            self._connections = {}

    def save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        data = [asdict(conn) for conn in self._connections.values()]
        with open(self.config_path, "w") as f:
            json.dump(data, f, indent=2)

    def list(self) -> List[RemoteConnection]:
        return list(self._connections.values())

    def get(self, connection_id: str) -> Optional[RemoteConnection]:
        return self._connections.get(connection_id)

    def add(self, connection: RemoteConnection) -> None:
        self._connections[connection.id] = connection
        self.save()

    def delete(self, connection_id: str) -> None:
        if connection_id in self._connections:
            del self._connections[connection_id]
            self.save()
