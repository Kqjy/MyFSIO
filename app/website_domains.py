from __future__ import annotations

import json
import re
import threading
from pathlib import Path
from typing import Dict, List, Optional

_DOMAIN_RE = re.compile(
    r"^(?!-)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$"
)


def normalize_domain(raw: str) -> str:
    raw = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/", 1)[0]
    raw = raw.split("?", 1)[0]
    raw = raw.split("#", 1)[0]
    if ":" in raw:
        raw = raw.rsplit(":", 1)[0]
    return raw


def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain))


class WebsiteDomainStore:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self._lock = threading.Lock()
        self._domains: Dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        if not self.config_path.exists():
            self._domains = {}
            return
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._domains = {k.lower(): v for k, v in data.items()}
                else:
                    self._domains = {}
        except (OSError, json.JSONDecodeError):
            self._domains = {}

    def _save(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self._domains, f, indent=2)

    def list_all(self) -> List[Dict[str, str]]:
        with self._lock:
            return [{"domain": d, "bucket": b} for d, b in self._domains.items()]

    def get_bucket(self, domain: str) -> Optional[str]:
        with self._lock:
            return self._domains.get(domain.lower())

    def set_mapping(self, domain: str, bucket: str) -> None:
        with self._lock:
            self._domains[domain.lower()] = bucket
            self._save()

    def delete_mapping(self, domain: str) -> bool:
        with self._lock:
            key = domain.lower()
            if key not in self._domains:
                return False
            del self._domains[key]
            self._save()
            return True
