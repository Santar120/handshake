"""Tests for LAN discovery (app/net/discovery.py).

Covers the beacon handling logic (parse, tamper-check, dedupe, own-echo
filter), the beacon→Identity-Card round trip that the UI relies on, and the
real socket receive path (send a crafted beacon to a running Discovery and
watch it surface the peer). Pure asyncio — no Qt involved.
"""

from __future__ import annotations

import asyncio
import json
import socket

from app.core.crypto import b64_encode
from app.core.identity import Identity, new_identity, parse_card
from app.net.discovery import DISCOVERY_MAGIC, Discovery


def _beacon_for(identity: Identity, port: int, address: str = "") -> bytes:
    """Build a beacon exactly as Discovery._build_beacon does."""
    doc = {
        "magic": DISCOVERY_MAGIC,
        "alias": identity.alias,
        "x25519": b64_encode(identity.x25519_pub),
        "ed25519": b64_encode(identity.ed25519_pub),
        "fingerprint": identity.fingerprint_display,
        "port": port,
    }
    if address:
        doc["address"] = address
    return json.dumps(doc, separators=(",", ":")).encode("utf-8")


def _make_discovery(identity: Identity, found: list, **kwargs) -> Discovery:
    return Discovery(
        identity,
        on_discovered=lambda peer, src, beacon: found.append((peer, src, beacon)),
        advertised_port=12345,
        **kwargs,
    )


def test_handle_beacon_reports_new_peer():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    found: list = []
    disc = _make_discovery(alice, found)

    disc._handle_beacon(_beacon_for(bob, 41337, "10.0.0.5"), "10.0.0.5")

    assert len(found) == 1
    peer, src, beacon = found[0]
    assert peer.alias == "Bob"
    assert peer.fingerprint_display == bob.fingerprint_display
    assert peer.port == 41337
    assert peer.address == "10.0.0.5"
    assert src == "10.0.0.5"
    assert beacon == _beacon_for(bob, 41337, "10.0.0.5")


def test_handle_beacon_ignores_bad_magic():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    found: list = []
    disc = _make_discovery(alice, found)

    doc = json.loads(_beacon_for(bob, 41337))
    doc["magic"] = "SOMETHING-ELSE"
    disc._handle_beacon(json.dumps(doc).encode(), "10.0.0.5")

    assert found == []


def test_handle_beacon_ignores_tampered_fingerprint():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    found: list = []
    disc = _make_discovery(alice, found)

    doc = json.loads(_beacon_for(bob, 41337))
    doc["fingerprint"] = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH"
    disc._handle_beacon(json.dumps(doc).encode(), "10.0.0.5")

    assert found == []


def test_handle_beacon_ignores_own_echo():
    alice = new_identity("Alice")
    found: list = []
    disc = _make_discovery(alice, found)

    # A beacon carrying Alice's own identity (our own broadcast echoed back).
    disc._handle_beacon(_beacon_for(alice, 41337), "127.0.0.1")

    assert found == []


def test_handle_beacon_dedupes_per_session():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    found: list = []
    disc = _make_discovery(alice, found)

    beacon = _beacon_for(bob, 41337)
    disc._handle_beacon(beacon, "10.0.0.5")
    disc._handle_beacon(beacon, "10.0.0.5")  # repeat of the same peer

    assert len(found) == 1


def test_beacon_is_parseable_identity_card():
    """The UI hands the beacon straight to add_peer → parse_card must accept it."""
    bob = new_identity("Bob")
    beacon = _beacon_for(bob, 41337, "10.0.0.5").decode("utf-8")

    parsed = parse_card(beacon)

    assert parsed.alias == "Bob"
    assert parsed.fingerprint_display == bob.fingerprint_display
    assert parsed.port == 41337
    assert parsed.address == "10.0.0.5"


async def _receive_path() -> list:
    """Start a Discovery, send a crafted beacon to its port, collect the hit."""
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    found: list = []
    done = asyncio.Event()
    disc = Discovery(
        alice,
        on_discovered=lambda peer, src, beacon: (found.append((peer, src, beacon)), done.set()),
        advertised_port=41337,
        channel_port=0,  # ephemeral port
    )
    await disc.start()
    try:
        port = disc.port
        assert port > 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(_beacon_for(bob, 41337, "10.0.0.5"), ("127.0.0.1", port))
        await asyncio.wait_for(done.wait(), timeout=5.0)
    finally:
        await disc.stop()
    return found


def test_receive_path_end_to_end():
    found = asyncio.run(_receive_path())
    assert len(found) == 1
    peer, src, _ = found[0]
    assert peer.alias == "Bob"
    assert src == "127.0.0.1"


async def _lifecycle() -> None:
    alice = new_identity("Alice")
    disc = _make_discovery(alice, [], channel_port=0)
    await disc.start()
    try:
        assert disc.port > 0
    finally:
        await disc.stop()
    # Stopping twice must be safe.
    await disc.stop()


def test_start_stop_lifecycle():
    asyncio.run(_lifecycle())
