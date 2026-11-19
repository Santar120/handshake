"""Unit tests for app.core.archive (encrypted per-peer history)."""

from __future__ import annotations

from pathlib import Path

from app.core.archive import Archive


def test_append_and_load_no_key(tmp_path: Path):
    arch = Archive(None, tmp_path)
    arch.append("PEER", {"type": "text", "payload": {"text": "hi"}})
    arch.append("PEER", {"type": "text", "payload": {"text": "yo"}})
    msgs = arch.load("PEER")
    assert len(msgs) == 2
    assert msgs[0]["payload"]["text"] == "hi"


def test_append_and_load_with_key(tmp_path: Path):
    key = b"\x00" * 32
    arch = Archive(key, tmp_path)
    arch.append("PEER", {"type": "text", "payload": {"text": "secret"}})
    # Stored encrypted on disk (not plaintext JSON).
    raw = (tmp_path / "PEER.json").read_bytes()
    assert b"secret" not in raw
    # Correct key reads it back.
    assert Archive(key, tmp_path).load("PEER")[0]["payload"]["text"] == "secret"


def test_wrong_key_returns_empty(tmp_path: Path):
    arch = Archive(b"\x00" * 32, tmp_path)
    arch.append("PEER", {"type": "text", "payload": {"text": "secret"}})
    assert Archive(b"\x01" * 32, tmp_path).load("PEER") == []


def test_clear(tmp_path: Path):
    arch = Archive(None, tmp_path)
    arch.append("PEER", {"type": "text", "payload": {"text": "x"}})
    arch.clear("PEER")
    assert arch.load("PEER") == []


def test_missing_peer_returns_empty(tmp_path: Path):
    assert Archive(None, tmp_path).load("NOPE") == []
