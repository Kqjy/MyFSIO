"""Central location for the application version string."""
from __future__ import annotations

APP_VERSION = "0.1.0b2"


def get_version() -> str:
    """Return the current application version."""
    return APP_VERSION
