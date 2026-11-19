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


def test_card_with_port_roundtrip():
    idn = new_identity("Porty")
    card = idn.to_card(port=50000)
    assert "port: 50000" in card
    parsed = parse_card(card)
    assert parsed.port == 50000
    assert parsed.alias == "Porty"


def test_card_without_port_is_none():
    idn = new_identity("NoPort")
    card = idn.to_card()
    assert "port:" not in card
    parsed = parse_card(card)
    assert parsed.port is None


def test_json_card_with_port_roundtrip():
    import json

    idn = new_identity("JsonPort")
    card = idn.to_card_json(port=41337)
    doc = json.loads(card)
    assert doc["port"] == 41337
    parsed = parse_card(card)
    assert parsed.port == 41337


def test_json_card_without_port_omits_key():
    import json

    idn = new_identity("JsonNoPort")
    doc = json.loads(idn.to_card_json())
    assert "port" not in doc
    assert parse_card(idn.to_card_json()).port is None


def test_card_port_backward_compatible():
    # A card written by an older version (no port line) still parses.
    idn = new_identity("Old")
    card = render_card(idn.alias, idn.x25519_pub, idn.ed25519_pub)
    assert "port:" not in card
    parsed = parse_card(card)
    assert parsed.port is None


def test_card_port_forward_compatible():
    # A card with a port line is still parsed by the text parser.
    idn = new_identity("New")
    card = render_card(idn.alias, idn.x25519_pub, idn.ed25519_pub, port=1234)
    parsed = parse_card(card)
    assert parsed.port == 1234


def test_card_bad_port_rejected():
    idn = new_identity("BadPort")
    card = idn.to_card()
    # Append an out-of-range port line.
    card += "port: 99999\n"
    with pytest.raises(IdentityCardError):
        parse_card(card)
    # Non-numeric port.
    card2 = idn.to_card() + "port: abc\n"
    with pytest.raises(IdentityCardError):
        parse_card(card2)


def test_qr_png_with_port():
    idn = new_identity("QrPort")
    png = idn.to_qr_png(port=41337)
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


# -- address ----------------------------------------------------------------


def test_card_with_address_roundtrip():
    idn = new_identity("Addr")
    card = idn.to_card(port=41337, address="203.0.113.5")
    assert "address: 203.0.113.5" in card
    parsed = parse_card(card)
    assert parsed.address == "203.0.113.5"
    assert parsed.port == 41337


def test_card_without_address_is_none():
    idn = new_identity("NoAddr")
    card = idn.to_card(port=41337)
    assert "address:" not in card
    assert parse_card(card).address is None


def test_json_card_with_address_roundtrip():
    import json

    idn = new_identity("JsonAddr")
    card = idn.to_card_json(port=41337, address="chat.example.com")
    doc = json.loads(card)
    assert doc["address"] == "chat.example.com"
    assert parse_card(card).address == "chat.example.com"


def test_json_card_without_address_omits_key():
    import json

    idn = new_identity("JsonNoAddr")
    doc = json.loads(idn.to_card_json(port=41337))
    assert "address" not in doc
    assert parse_card(idn.to_card_json(port=41337)).address is None


def test_card_address_backward_compatible():
    # A card written by an older version (no address line) still parses.
    idn = new_identity("OldAddr")
    card = render_card(idn.alias, idn.x25519_pub, idn.ed25519_pub, port=1234)
    assert "address:" not in card
    assert parse_card(card).address is None


def test_qr_png_with_address():
    idn = new_identity("QrAddr")
    png = idn.to_qr_png(port=41337, address="192.168.1.20")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"


def test_best_address_priority():
    from app.core.addresses import best_address
    from app.core.vault import Settings

    # Custom URL wins over everything.
    s = Settings(public_ip="1.1.1.1", lan_ip="2.2.2.2", custom_url="chat.example.com")
    assert best_address(s) == "chat.example.com"
    # Public IP wins over LAN.
    s = Settings(public_ip="1.1.1.1", lan_ip="2.2.2.2")
    assert best_address(s) == "1.1.1.1"
    # LAN is the fallback.
    s = Settings(lan_ip="2.2.2.2")
    assert best_address(s) == "2.2.2.2"
    # Empty when nothing is set.
    assert best_address(Settings()) == ""
    # Whitespace-only values are treated as empty.
    s = Settings(public_ip="   ", lan_ip="2.2.2.2")
    assert best_address(s) == "2.2.2.2"
