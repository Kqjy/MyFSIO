from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional


class EphemeralSecretStore:
    """Keeps values in-memory for a short period and returns them once."""

    def __init__(self, default_ttl: int = 300) -> None:
        self._default_ttl = max(default_ttl, 1)
        self._store: Dict[str, tuple[Any, float]] = {}

    def remember(self, payload: Any, *, ttl: Optional[int] = None) -> str:
        token = secrets.token_urlsafe(16)
        expires_at = time.time() + (ttl or self._default_ttl)
        self._store[token] = (payload, expires_at)
        return token

    def peek(self, token: str | None) -> Any | None:
        if not token:
            return None
        entry = self._store.get(token)
        if not entry:
            return None
        payload, expires_at = entry
        if expires_at < time.time():
            self._store.pop(token, None)
            return None
        return payload

    def pop(self, token: str | None) -> Any | None:
        if not token:
            return None
        entry = self._store.pop(token, None)
        if not entry:
            return None
        payload, expires_at = entry
        if expires_at < time.time():
            return None
        return payload

    def purge_expired(self) -> None:
        now = time.time()
        stale = [token for token, (_, expires_at) in self._store.items() if expires_at < now]
        for token in stale:
            self._store.pop(token, None)
