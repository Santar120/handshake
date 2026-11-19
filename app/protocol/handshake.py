"""Handshake: HELLO / HELLO_ACK exchange, verification, key derivation.

Implements PROTOCOL.md §4. Symmetric — works whether A dials B or B
dials A. Ephemeral X25519 keys give forward secrecy; the long-term
Ed25519 signature proves key ownership.
"""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from ..core.crypto import (
    ED25519_PUB_LEN,
    X25519_PUB_LEN,
    HandshakeError,
    b64_decode,
    b64_encode,
    derive_nonce_prefixes,
    derive_session_key,
    fingerprint_bytes,
    fingerprint_display,
    fingerprint_parse,
    generate_ephemeral_x25519,
    key_check,
)
from ..core.identity import Identity, PeerIdentity
from ..core.vault import Peer
from .frames import HelloMessage

PROTOCOL_VERSION = 1

# Rejection reasons
REJ_UNKNOWN_PEER = "unknown-peer"
REJ_PSK_MISMATCH = "psk-mismatch"
REJ_BAD_SIGNATURE = "bad-signature"
REJ_BAD_FINGERPRINT = "bad-fingerprint"
REJ_UNSUPPORTED_VERSION = "unsupported-version"


class HandshakeFailed(HandshakeError):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------------------
# Canonical serialization for signatures (PROTOCOL.md §5)
# ---------------------------------------------------------------------------


def _canonical_hello(kind: bytes, msg: HelloMessage) -> bytes:
    alias = msg.alias.encode("utf-8")
    return (
        kind
        + struct.pack(">B", msg.v)
        + struct.pack(">H", len(alias))
        + alias
        + msg.x25519
        + msg.ed25519
        + msg.eph_pub
        + struct.pack(">B", 1 if msg.psk_flag else 0)
    )


def canonical_hello(msg: HelloMessage) -> bytes:
    return _canonical_hello(b"HELLO-v1", msg)


def canonical_hello_ack(msg: HelloMessage) -> bytes:
    return _canonical_hello(b"HELLO_ACK-v1", msg)


# ---------------------------------------------------------------------------
# Building outgoing messages
# ---------------------------------------------------------------------------


def build_hello(identity: Identity, eph: X25519PrivateKey, psk: str | None) -> HelloMessage:
    msg = HelloMessage(
        v=PROTOCOL_VERSION,
        alias=identity.alias,
        x25519=identity.x25519_pub,
        ed25519=identity.ed25519_pub,
        fingerprint=identity.fingerprint_display,
        eph_pub=eph.public_key().public_bytes_raw(),
        psk_flag=psk is not None,
        sig=b"",
    )
    msg.sig = identity.sign(canonical_hello(msg))
    return msg


def build_hello_ack(identity: Identity, eph: X25519PrivateKey, psk: str | None) -> HelloMessage:
    msg = HelloMessage(
        v=PROTOCOL_VERSION,
        alias=identity.alias,
        x25519=identity.x25519_pub,
        ed25519=identity.ed25519_pub,
        fingerprint=identity.fingerprint_display,
        eph_pub=eph.public_key().public_bytes_raw(),
        psk_flag=psk is not None,
        sig=b"",
    )
    msg.sig = identity.sign(canonical_hello_ack(msg))
    return msg


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_hello(
    msg: HelloMessage,
    expected: PeerIdentity,
    expected_psk: str | None,
    is_ack: bool = False,
) -> None:
    """Verify a HELLO/HELLO_ACK against a configured peer.

    Raises HandshakeFailed with a machine-readable reason on failure.
    """
    if msg.v != PROTOCOL_VERSION:
        raise HandshakeFailed(REJ_UNSUPPORTED_VERSION, f"got v{msg.v}")

    if msg.x25519 != expected.x25519_pub or msg.ed25519 != expected.ed25519_pub:
        raise HandshakeFailed(REJ_UNKNOWN_PEER, "identity does not match any configured peer")

    if len(msg.x25519) != X25519_PUB_LEN or len(msg.ed25519) != ED25519_PUB_LEN:
        raise HandshakeFailed(REJ_BAD_FINGERPRINT, "bad key length")

    try:
        fp = fingerprint_parse(msg.fingerprint)
    except ValueError:
        raise HandshakeFailed(REJ_BAD_FINGERPRINT, "unparseable fingerprint")
    if fp != fingerprint_bytes(msg.x25519, msg.ed25519):
        raise HandshakeFailed(REJ_BAD_FINGERPRINT, "fingerprint does not match keys")

    canonical = canonical_hello_ack(msg) if is_ack else canonical_hello(msg)
    if not expected.verify_signature(canonical, msg.sig):
        raise HandshakeFailed(REJ_BAD_SIGNATURE, "signature verification failed")

    if msg.psk_flag != (expected_psk is not None):
        raise HandshakeFailed(REJ_PSK_MISMATCH, "shared-secret flag mismatch")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_session(
    local_eph: X25519PrivateKey,
    peer_eph_pub: bytes,
    fp_local: bytes,
    fp_peer: bytes,
    psk: str | None,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Derive (session_key, key_check, prefix_a, prefix_b) from the ECDH.

    ``prefix_a`` / ``prefix_b`` are the two direction-specific nonce prefixes
    (see ``derive_nonce_prefixes``). Both sides derive the identical tuple;
    each side then picks its send/receive prefixes by fingerprint order
    (see ``channel_prefixes_for``).
    """
    peer_eph = X25519PublicKey.from_public_bytes(peer_eph_pub)
    eph_shared = local_eph.exchange(peer_eph)
    session_key = derive_session_key(eph_shared, fp_local, fp_peer, psk)
    prefix_a, prefix_b = derive_nonce_prefixes(session_key)
    return session_key, key_check(session_key), prefix_a, prefix_b


def channel_prefixes_for(
    fp_local: bytes, fp_peer: bytes, prefix_a: bytes, prefix_b: bytes
) -> tuple[bytes, bytes]:
    """Return (send_prefix, recv_prefix) for this side of the session.

    The side whose fingerprint sorts first sends with ``prefix_a`` and
    receives with ``prefix_b``; the other side does the reverse. This is
    deterministic, so both sides agree without exchanging anything.
    """
    if fp_local < fp_peer:
        return prefix_a, prefix_b
    return prefix_b, prefix_a
