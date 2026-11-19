"""Unit tests for app.core.identity (keypairs, cards, fingerprints)."""

from __future__ import annotations

import pytest

from app.core.crypto import IdentityCardError
from app.core.identity import (
    Identity,
    PeerIdentity,
    new_identity,
    parse_card,
    render_card,
)


def test_new_identity_shapes():
    idn = new_identity("Alice")
    assert idn.alias == "Alice"
    assert len(idn.x25519_pub) == 32
    assert len(idn.ed25519_pub) == 32
    assert len(idn.fingerprint) == 20


def test_fingerprint_display_matches_peer_identity():
    idn = new_identity("Alice")
    peer = PeerIdentity(
        alias=idn.alias,
        x25519_pub=idn.x25519_pub,
        ed25519_pub=idn.ed25519_pub,
    )
    assert idn.fingerprint == peer.fingerprint
    assert idn.fingerprint_display == peer.fingerprint_display


def test_card_roundtrip():
    idn = new_identity("Bob")
    card = idn.to_card()
    parsed = parse_card(card)
    assert parsed.alias == "Bob"
    assert parsed.x25519_pub == idn.x25519_pub
    assert parsed.ed25519_pub == idn.ed25519_pub
    assert parsed.fingerprint == idn.fingerprint


def test_card_tamper_detected():
    idn = new_identity("Eve")
    card = idn.to_card()
    # Flip one character in the x25519 line -> fingerprint mismatch.
    lines = card.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("x25519:"):
            val = line.split(":", 1)[1].strip()
            # Corrupt the last base64 char.
            val = val[:-1] + ("A" if val[-1] != "A" else "B")
            lines[i] = f"x25519: {val}"
            break
    tampered = "\n".join(lines)
    with pytest.raises(IdentityCardError):
        parse_card(tampered)


def test_json_card_roundtrip():
    idn = new_identity("Carol")
    card = idn.to_card_json()
    parsed = parse_card(card)
    assert parsed.alias == "Carol"
    assert parsed.x25519_pub == idn.x25519_pub
    assert parsed.ed25519_pub == idn.ed25519_pub
    assert parsed.fingerprint == idn.fingerprint


def test_json_card_matches_text_card():
    idn = new_identity("Dan")
    from_text = parse_card(idn.to_card())
    from_json = parse_card(idn.to_card_json())
    assert from_text.x25519_pub == from_json.x25519_pub
    assert from_text.ed25519_pub == from_json.ed25519_pub
    assert from_text.fingerprint == from_json.fingerprint


def test_json_card_tamper_detected():
    import json

    idn = new_identity("Eve")
    doc = json.loads(idn.to_card_json())
    # Corrupt the x25519 key -> fingerprint mismatch.
    val = doc["x25519"]
    doc["x25519"] = val[:-1] + ("A" if val[-1] != "A" else "B")
    with pytest.raises(IdentityCardError):
        parse_card(json.dumps(doc))


def test_json_card_missing_field():
    import json

    idn = new_identity("Eve")
    doc = json.loads(idn.to_card_json())
    del doc["ed25519"]
    with pytest.raises(IdentityCardError):
        parse_card(json.dumps(doc))


def test_json_card_invalid_json():
    with pytest.raises(IdentityCardError):
        parse_card("{not valid json")


def test_card_missing_field():
    with pytest.raises(IdentityCardError):
        parse_card("HANDSHAKE-IDENTITY v1\nalias: X\n")


def test_sign_verify():
    idn = new_identity("Carol")
    msg = b"hello"
    sig = idn.sign(msg)
    peer = PeerIdentity(
        alias=idn.alias,
        x25519_pub=idn.x25519_pub,
        ed25519_pub=idn.ed25519_pub,
    )
    assert peer.verify_signature(msg, sig) is True
    assert peer.verify_signature(b"tampered", sig) is False


def test_qr_png_bytes():
    idn = new_identity("Dave")
    png = idn.to_qr_png()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
