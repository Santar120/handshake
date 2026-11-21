"""Unit tests for app.core.archive (SQLite, per-message encrypted)."""

from __future__ import annotations

import json
from pathlib import Path

from app.core.archive import Archive
from app.core.crypto import aes_gcm_encrypt, b64_encode


def test_append_and_load_no_key(tmp_path: Path):
    arch = Archive(None, tmp_path)
    arch.append("PEER", {"type": "text", "ts": 1.0, "payload": {"text": "hi"}})
    arch.append("PEER", {"type": "text", "ts": 2.0, "payload": {"text": "yo"}})
    msgs = arch.load("PEER")
    assert len(msgs) == 2
    assert msgs[0]["payload"]["text"] == "hi"
    assert msgs[1]["payload"]["text"] == "yo"


def test_append_and_load_with_key(tmp_path: Path):
    key = b"\x00" * 32
    arch = Archive(key, tmp_path)
    arch.append("PEER", {"type": "text", "ts": 1.0, "payload": {"text": "secret"}})
    # Stored encrypted in the database (not plaintext).
    raw = (tmp_path / "archive.db").read_bytes()
    assert b"secret" not in raw
    # Correct key reads it back.
    assert Archive(key, tmp_path).load("PEER")[0]["payload"]["text"] == "secret"


def test_wrong_key_returns_empty(tmp_path: Path):
    arch = Archive(b"\x00" * 32, tmp_path)
    arch.append("PEER", {"type": "text", "ts": 1.0, "payload": {"text": "secret"}})
    assert Archive(b"\x01" * 32, tmp_path).load("PEER") == []


def test_clear(tmp_path: Path):
    arch = Archive(None, tmp_path)
    arch.append("PEER", {"type": "text", "ts": 1.0, "payload": {"text": "x"}})
    arch.clear("PEER")
    assert arch.load("PEER") == []


def test_missing_peer_returns_empty(tmp_path: Path):
    assert Archive(None, tmp_path).load("NOPE") == []


def test_dedup_by_message_id(tmp_path: Path):
    arch = Archive(None, tmp_path)
    env = {"type": "text", "ts": 1.0, "payload": {"text": "once"}, "id": "same-id"}
    arch.append("PEER", env)
    arch.append("PEER", env)  # duplicate id is ignored
    assert len(arch.load("PEER")) == 1


def test_list_files_groups_by_peer(tmp_path: Path):
    arch = Archive(None, tmp_path)
    arch.append("PEER A", {"type": "text", "ts": 1.0, "payload": {"text": "a"}})
    arch.append("PEER B", {"type": "text", "ts": 2.0, "payload": {"text": "b"}})
    arch.append("PEER A", {"type": "text", "ts": 3.0, "payload": {"text": "a2"}})
    files = arch.list_files()
    assert set(files) == {"PEER A", "PEER B"}
    assert [m["payload"]["text"] for m in files["PEER A"]] == ["a", "a2"]


def test_legacy_json_migration(tmp_path: Path):
    """Old per-peer JSON archive files are imported, then removed."""
    key = b"\x00" * 32
    messages = [
        {"type": "text", "sender": "X", "seq": 1, "ts": 1.0,
         "payload": {"text": "old one"}},
        {"type": "text", "sender": "X", "seq": 2, "ts": 2.0,
         "payload": {"text": "old two"}},
    ]
    doc = {"version": 1, "peer_fingerprint": "PEER", "messages": messages}
    payload = json.dumps(doc, sort_keys=True).encode("utf-8")
    blob = b64_encode(aes_gcm_encrypt(key, payload)).encode("ascii")
    (tmp_path / "PEER.json").write_bytes(blob)

    arch = Archive(key, tmp_path)
    msgs = arch.load("PEER")
    assert [m["payload"]["text"] for m in msgs] == ["old one", "old two"]
    # Legacy file removed after migration.
    assert not (tmp_path / "PEER.json").exists()
    # New appends go to the database.
    arch.append("PEER", {"type": "text", "ts": 3.0, "payload": {"text": "new"}})
    assert len(arch.load("PEER")) == 3
