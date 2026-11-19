"""Tests for identity bundle export/import (moving to another computer)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.archive import Archive
from app.core.crypto import VaultError
from app.core.identity import new_identity
from app.core.vault import Peer, Vault


def _peer(alias: str = "Peer") -> Peer:
    idn = new_identity(alias)
    return Peer(
        alias=idn.alias,
        x25519_pub=idn.x25519_pub,
        ed25519_pub=idn.ed25519_pub,
        host="127.0.0.1",
        port=41337,
    )


def _make_vault(tmp_path: Path, pin: str | None) -> Vault:
    path = tmp_path / "vault.json"
    vault = Vault.create(path, new_identity("Alice"), pin)
    vault.add_peer(_peer("Bob"))
    return vault


def _archive_with_messages(tmp_path: Path, key: bytes | None) -> Archive:
    arch = Archive(key, tmp_path / "archive")
    arch.append("AAAA BBBB CCCC DDDD EEEE", {"type": "text", "text": "hello"})
    arch.append("AAAA BBBB CCCC DDDD EEEE", {"type": "text", "text": "world"})
    return arch


def test_bundle_roundtrip_with_pin(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()

    vault = _make_vault(src, "123456")
    arch = _archive_with_messages(src, vault._key)

    text = vault.export_bundle(arch.list_files())
    (dst / "bundle.json").write_text(text, encoding="utf-8")

    # The encrypted bundle must not leak the raw private key.
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    raw_priv = vault.identity.x25519.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    assert b64_of(raw_priv) not in text.encode()

    restored = Vault.import_bundle(
        text, dst / "vault.json", "123456", dst / "archive"
    )
    assert restored.identity.alias == "Alice"
    assert restored.identity.fingerprint == vault.identity.fingerprint
    assert restored.has_pin is True
    assert len(restored.peers) == 1
    assert restored.peers[0].alias == "Bob"

    # Archive survived the roundtrip.
    restored_arch = Archive(restored._key, dst / "archive")
    msgs = restored_arch.load("AAAA BBBB CCCC DDDD EEEE")
    assert [m["text"] for m in msgs] == ["hello", "world"]


def test_bundle_roundtrip_pinless(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()

    vault = _make_vault(src, None)
    arch = _archive_with_messages(src, None)

    text = vault.export_bundle(arch.list_files())
    restored = Vault.import_bundle(text, dst / "vault.json", None, dst / "archive")
    assert restored.identity.fingerprint == vault.identity.fingerprint
    assert restored.has_pin is False
    assert len(restored.peers) == 1

    restored_arch = Archive(None, dst / "archive")
    msgs = restored_arch.load("AAAA BBBB CCCC DDDD EEEE")
    assert len(msgs) == 2


def test_bundle_wrong_pin_fails(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()

    vault = _make_vault(src, "123456")
    text = vault.export_bundle({})
    with pytest.raises(VaultError):
        Vault.import_bundle(text, dst / "vault.json", "654321", dst / "archive")
    with pytest.raises(VaultError):
        Vault.import_bundle(text, dst / "vault.json", None, dst / "archive")
    assert not (dst / "vault.json").exists()


def test_bundle_refuses_overwrite(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()

    vault = _make_vault(src, None)
    text = vault.export_bundle({})
    existing = Vault.create(dst / "vault.json", new_identity("Existing"), None)
    with pytest.raises(VaultError):
        Vault.import_bundle(text, dst / "vault.json", None, dst / "archive")
    # The existing vault is untouched.
    assert Vault.open(dst / "vault.json", None).identity.alias == "Existing"


def test_bundle_rejects_non_bundle_file(tmp_path: Path):
    dst = tmp_path / "dst"
    dst.mkdir()
    with pytest.raises(VaultError):
        Vault.import_bundle(
            json.dumps({"magic": "SOMETHING-ELSE"}),
            dst / "vault.json",
            None,
            dst / "archive",
        )
    with pytest.raises(VaultError):
        Vault.import_bundle("not json at all", dst / "vault.json", None, dst / "archive")


def test_bundle_empty_archive(tmp_path: Path):
    src = tmp_path / "src"
    dst = tmp_path / "dst"
    src.mkdir()
    dst.mkdir()

    vault = _make_vault(src, None)
    text = vault.export_bundle({})
    restored = Vault.import_bundle(text, dst / "vault.json", None, dst / "archive")
    assert restored.identity.fingerprint == vault.identity.fingerprint
    assert not (dst / "archive").exists()


def b64_of(data: bytes) -> bytes:
    import base64

    return base64.b64encode(data)


def test_appcore_export_import_roundtrip(qapp, monkeypatch, tmp_path: Path):
    """Full AppCore path: onboard -> export -> import into a fresh home."""
    import os

    from app.core.appcore import AppCore

    home_a = tmp_path / "home_a"
    home_b = tmp_path / "home_b"
    home_a.mkdir()
    home_b.mkdir()

    # -- machine A: onboard, add a peer, store a message -------------------
    monkeypatch.setenv("HANDSHAKE_HOME", str(home_a))
    core_a = AppCore()
    core_a.start()
    core_a.onboard("Alice", "123456")
    core_a.update_settings(listen_port=41401)

    peer = _peer("Bob")
    core_a.add_peer(
        _card_for(peer), "127.0.0.1", 41402, None
    )
    fp = peer.fingerprint_display
    core_a.archive.append(fp, {"type": "text", "text": "hi from A"})

    bundle_path = tmp_path / "bundle.json"
    core_a.export_bundle(str(bundle_path))
    assert bundle_path.exists()
    core_a.stop()

    # -- machine B: fresh home, import the bundle --------------------------
    monkeypatch.setenv("HANDSHAKE_HOME", str(home_b))
    core_b = AppCore()
    core_b.start()
    core_b.import_bundle(str(bundle_path), "123456")

    assert core_b.identity is not None
    assert core_b.identity.alias == "Alice"
    assert core_b.identity.fingerprint == core_a.identity.fingerprint
    assert len(core_b.peers()) == 1
    assert core_b.peers()[0].alias == "Bob"
    assert [m["text"] for m in core_b.load_history(fp)] == ["hi from A"]

    core_b.stop()


def _card_for(peer: Peer) -> str:
    from app.core.identity import render_card

    return render_card(peer.alias, peer.x25519_pub, peer.ed25519_pub)
