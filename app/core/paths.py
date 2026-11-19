"""Paths: where Handshake stores its data on each platform."""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "handshake"


def config_dir() -> Path:
    """Platform app-data directory for Handshake.

    Override with the ``HANDSHAKE_HOME`` environment variable (used by
    tests and for portable installs).
    """
    override = os.environ.get("HANDSHAKE_HOME")
    if override:
        return Path(override).expanduser()

    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / APP_NAME


def vault_path() -> Path:
    return config_dir() / "vault.json"


def archive_dir() -> Path:
    return config_dir() / "archive"
