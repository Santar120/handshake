"""Cryptographic primitives used across Handshake.

Only the `cryptography` library and `argon2-cffi` are used. No
home-rolled crypto. See docs/PROTOCOL.md and docs/SECURITY.md.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import string

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

X25519_PUB_LEN = 32
ED25519_PUB_LEN = 32
FINGERPRINT_BYTES = 20  # first 160 bits of SHA-256
SESSION_KEY_LEN = 32
NONCE_LEN = 12  # ChaCha20-Poly1305
NONCE_PREFIX_LEN = 8
COUNTER_LEN = 4
MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB

# argon2id parameters for the vault key (64 MiB, 3 iterations, 4 lanes)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # KiB
ARGON2_PARALLELISM = 4

VAULT_INFO = b"handshake-vault-v1"
SESSION_INFO_PREFIX = b"handshake-v1"

_B32_ALPHABET = string.ascii_uppercase + "234567"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HandshakeError(Exception):
    """Base class for all protocol/crypto errors."""


class IdentityCardError(HandshakeError):
    """An Identity Card could not be parsed or failed verification."""


class VaultError(HandshakeError):
    """Vault could not be opened (wrong PIN, corrupt file, ...)."""


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: str) -> bytes:
    return base64.b64decode(text.strip(), validate=True)


def fingerprint_bytes(x25519_pub: bytes, ed25519_pub: bytes) -> bytes:
    """First 160 bits of SHA-256(x25519_pub || ed25519_pub)."""
    if len(x25519_pub) != X25519_PUB_LEN or len(ed25519_pub) != ED25519_PUB_LEN:
        raise ValueError("public keys must be 32 bytes each")
    return hashlib.sha256(x25519_pub + ed25519_pub).digest()[:FINGERPRINT_BYTES]


def fingerprint_display(fp: bytes) -> str:
    """Render 20 raw fingerprint bytes as 8 groups of 4 base32 chars."""
    if len(fp) != FINGERPRINT_BYTES:
        raise ValueError("fingerprint must be 20 bytes")
    raw = base64.b32encode(fp).decode("ascii")  # exactly 32 chars, no padding
    return " ".join(raw[i : i + 4] for i in range(0, 32, 4))


def fingerprint_parse(text: str) -> bytes:
    """Parse 'ABCD EFGH ...' (8 groups of 4 base32) back to 20 bytes."""
    cleaned = re.sub(r"[\s-]", "", text).upper()
    if len(cleaned) != 32 or any(c not in _B32_ALPHABET for c in cleaned):
        raise ValueError("invalid fingerprint format")
    fp = base64.b32decode(cleaned)
    if len(fp) != FINGERPRINT_BYTES:
        raise ValueError("invalid fingerprint length")
    return fp


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def generate_x25519() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def generate_ed25519() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def generate_ephemeral_x25519() -> X25519PrivateKey:
    """Fresh per-connection ephemeral key (forward secrecy)."""
    return X25519PrivateKey.generate()


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_vault_key(pin: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """argon2id(PIN, salt) -> HKDF -> (32-byte vault key, salt).

    A fresh random salt is generated when ``salt`` is None; the salt must
    be stored alongside the vault so the key can be re-derived on unlock.
    """
    if salt is None:
        salt = os.urandom(16)
    secret = pin.encode("utf-8")
    raw = hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=SESSION_KEY_LEN,
        type=Type.ID,
    )
    # HKDF binds the argon2 output to a domain tag so vault keys can't be
    # reused for other purposes.
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_LEN,
        salt=salt,
        info=VAULT_INFO,
    ).derive(raw)
    return key, salt


def derive_session_key(
    eph_shared: bytes,
    fp_local: bytes,
    fp_peer: bytes,
    psk: str | None,
) -> bytes:
    """HKDF over the ephemeral ECDH shared secret (PROTOCOL.md §4.5).

    The two fingerprints are ordered canonically (sorted) so that both
    sides derive the identical key regardless of which one is "local".
    """
    fp_a, fp_b = sorted((fp_local, fp_peer))
    info = SESSION_INFO_PREFIX + fp_a + fp_b
    if psk:
        info += psk.encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_LEN,
        salt=b"",
        info=info,
    ).derive(eph_shared)


def key_check(session_key: bytes) -> bytes:
    """16-byte confirmation value sent as the first encrypted frame."""
    return hashlib.sha256(session_key).digest()[:16]


def derive_nonce_prefixes(session_key: bytes) -> tuple[bytes, bytes]:
    """Derive two direction-specific 8-byte nonce prefixes from the session key.

    Both sides derive the identical pair from the shared session key. One
    direction sends with ``prefix_a`` / receives with ``prefix_b``; the other
    direction does the reverse. Using distinct prefixes per direction
    guarantees the two directions never share a nonce (no nonce reuse), which
    is required for ChaCha20-Poly1305.
    """
    prefix_a = HKDF(
        algorithm=hashes.SHA256(),
        length=NONCE_PREFIX_LEN,
        salt=b"",
        info=SESSION_INFO_PREFIX + b"-nonce-a",
    ).derive(session_key)
    prefix_b = HKDF(
        algorithm=hashes.SHA256(),
        length=NONCE_PREFIX_LEN,
        salt=b"",
        info=SESSION_INFO_PREFIX + b"-nonce-b",
    ).derive(session_key)
    return prefix_a, prefix_b


# ---------------------------------------------------------------------------
# Symmetric encryption
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Returns nonce(12) || ciphertext+tag."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def aes_gcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Inverse of aes_gcm_encrypt."""
    if len(blob) < 13:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
