"""Unit tests for app.protocol.handshake (HELLO/ACK, verify, key derivation)."""

from __future__ import annotations

import pytest

from app.core.crypto import generate_ephemeral_x25519
from app.core.identity import new_identity
from app.core.vault import Peer
from app.protocol.handshake import (
    REJ_BAD_SIGNATURE,
    REJ_PSK_MISMATCH,
    REJ_UNKNOWN_PEER,
    HandshakeFailed,
    build_hello,
    build_hello_ack,
    derive_session,
    verify_hello,
)


def _peer_of(idn) -> Peer:
    return Peer(
        alias=idn.alias,
        x25519_pub=idn.x25519_pub,
        ed25519_pub=idn.ed25519_pub,
        host="127.0.0.1",
        port=41337,
    )


def test_verify_hello_ok():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    eph = generate_ephemeral_x25519()
    hello = build_hello(alice, eph, None)
    verify_hello(hello, _peer_of(alice).to_identity(), None)  # no raise


def test_verify_hello_ack_ok():
    alice = new_identity("Alice")
    eph = generate_ephemeral_x25519()
    ack = build_hello_ack(alice, eph, None)
    verify_hello(ack, _peer_of(alice).to_identity(), None, is_ack=True)


def test_verify_hello_unknown_peer():
    alice = new_identity("Alice")
    mallory = new_identity("Mallory")
    eph = generate_ephemeral_x25519()
    hello = build_hello(mallory, eph, None)
    with pytest.raises(HandshakeFailed) as exc:
        verify_hello(hello, _peer_of(alice).to_identity(), None)
    assert exc.value.reason == REJ_UNKNOWN_PEER


def test_verify_hello_bad_signature():
    alice = new_identity("Alice")
    eph = generate_ephemeral_x25519()
    hello = build_hello(alice, eph, None)
    hello.sig = b"\x00" * 64  # corrupt signature
    with pytest.raises(HandshakeFailed) as exc:
        verify_hello(hello, _peer_of(alice).to_identity(), None)
    assert exc.value.reason == REJ_BAD_SIGNATURE


def test_verify_hello_psk_flag_mismatch():
    alice = new_identity("Alice")
    eph = generate_ephemeral_x25519()
    hello = build_hello(alice, eph, "secret")  # sender has a PSK
    with pytest.raises(HandshakeFailed) as exc:
        verify_hello(hello, _peer_of(alice).to_identity(), None)  # peer has none
    assert exc.value.reason == REJ_PSK_MISMATCH


def test_derive_session_symmetric():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    eph_a = generate_ephemeral_x25519()
    eph_b = generate_ephemeral_x25519()

    key_a, kc_a, pa_a, pb_a = derive_session(
        eph_a,
        eph_b.public_key().public_bytes_raw(),
        alice.fingerprint,
        bob.fingerprint,
        None,
    )
    key_b, kc_b, pa_b, pb_b = derive_session(
        eph_b,
        eph_a.public_key().public_bytes_raw(),
        bob.fingerprint,
        alice.fingerprint,
        None,
    )
    assert key_a == key_b
    assert kc_a == kc_b
    assert (pa_a, pb_a) == (pa_b, pb_b)  # same derived prefix pair
    assert pa_a != pb_a  # directions use distinct prefixes
    assert len(key_a) == 32
    assert len(kc_a) == 16
    assert len(pa_a) == 8


def test_derive_session_psk_must_match():
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    eph_a = generate_ephemeral_x25519()
    eph_b = generate_ephemeral_x25519()
    key_a, _, _, _ = derive_session(
        eph_a,
        eph_b.public_key().public_bytes_raw(),
        alice.fingerprint,
        bob.fingerprint,
        "psk-1",
    )
    key_b, _, _, _ = derive_session(
        eph_b,
        eph_a.public_key().public_bytes_raw(),
        bob.fingerprint,
        alice.fingerprint,
        "psk-2",
    )
    assert key_a != key_b
