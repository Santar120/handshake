"""Unit tests for app.core.vault (create/open, PIN, peers, settings)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.crypto import VaultError
from app.core.identity import new_identity
from app.core.vault import Peer, Settings, Vault


def _peer(alias: str = "Peer") -> Peer:
    idn = new_identity(alias)
    return Peer(
        alias=idn.alias,
        x25519_pub=idn.x25519_pub,
        ed25519_pub=idn.ed25519_pub,
        host="127.0.0.1",
        port=41337,
    )


def test_create_and_open_with_pin(tmp_path: Path):
    path = tmp_path / "vault.json"
    idn = new_identity("Alice")
    Vault.create(path, idn, "123456")
    assert path.exists()

    opened = Vault.open(path, "123456")
    assert opened.identity.alias == "Alice"
    assert opened.has_pin is True
    assert opened._key is not None


def test_open_wrong_pin_fails(tmp_path: Path):
    path = tmp_path / "vault.json"
    Vault.create(path, new_identity("Alice"), "123456")
    with pytest.raises(VaultError):
        Vault.open(path, "654321")


def test_open_pinless(tmp_path: Path):
    path = tmp_path / "vault.json"
    Vault.create(path, new_identity("Alice"), None)
    opened = Vault.open(path, None)
    assert opened.has_pin is False
    assert opened._key is None


def test_create_twice_fails(tmp_path: Path):
    path = tmp_path / "vault.json"
    Vault.create(path, new_identity("Alice"), None)
    with pytest.raises(VaultError):
        Vault.create(path, new_identity("Bob"), None)


def test_add_and_find_peer(tmp_path: Path):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, new_identity("Alice"), None)
    p = _peer("Bob")
    vault.add_peer(p)
    found = vault.find_peer_by_fingerprint(p.fingerprint)
    assert found is not None
    assert found.alias == "Bob"
    # Persisted across reopen.
    reopened = Vault.open(path, None)
    assert reopened.find_peer_by_fingerprint(p.fingerprint) is not None


def test_add_peer_updates_existing(tmp_path: Path):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, new_identity("Alice"), None)
    p = _peer("Bob")
    vault.add_peer(p)
    p2 = Peer(
        alias=p.alias,
        x25519_pub=p.x25519_pub,
        ed25519_pub=p.ed25519_pub,
        host="10.0.0.1",
        port=5555,
    )
    vault.add_peer(p2)
    assert len(vault.peers) == 1
    assert vault.peers[0].host == "10.0.0.1"
    assert vault.peers[0].port == 5555


def test_remove_peer(tmp_path: Path):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, new_identity("Alice"), None)
    p = _peer("Bob")
    vault.add_peer(p)
    vault.remove_peer(p.fingerprint)
    assert vault.find_peer_by_fingerprint(p.fingerprint) is None


def test_update_settings(tmp_path: Path):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, new_identity("Alice"), None)
    vault.update_settings(listen_port=50000, archive_enabled=False)
    assert vault.settings.listen_port == 50000
    assert vault.settings.archive_enabled is False
    with pytest.raises(ValueError):
        vault.update_settings(nope=1)


def test_rotate_identity(tmp_path: Path):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, new_identity("Alice"), None)
    old_fp = vault.identity.fingerprint
    new_id = new_identity("Alice")
    vault.rotate_identity(new_id)
    assert vault.identity.fingerprint != old_fp
