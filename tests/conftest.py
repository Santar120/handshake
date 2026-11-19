"""Shared pytest fixtures for the Handshake test suite."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

# Make the workspace root importable (so `import app` works under pytest).
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def qapp():
    """A single QApplication for the whole session (Qt signals need one)."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def hs_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point HANDSHAKE_HOME at a fresh temp dir (isolates vault/archive)."""
    home = tmp_path / "hs"
    home.mkdir()
    monkeypatch.setenv("HANDSHAKE_HOME", str(home))
    return home


def spin_until(qapp, cond, timeout: float = 10.0) -> bool:
    """Pump the Qt event loop until ``cond()`` is true or ``timeout`` elapses.

    AppCore emits Qt signals from its background loop thread; they are
    delivered to the main thread only while the event loop is running.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qapp.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def make_core(qapp, alias: str, port: int, pin: str | None = None):
    """Create, start, and onboard an AppCore listening on ``port``."""
    from app.core.appcore import AppCore

    core = AppCore()
    core.start()
    core.onboard(alias, pin)
    core.update_settings(listen_port=port)
    return core


def add_peer(core, card_text: str, host: str, port: int, psk: str | None = None):
    """Parse a peer's Identity Card and store it on ``core``."""
    return core.add_peer(card_text, host, port, psk)
