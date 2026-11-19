"""Unit tests for app.core.crypto."""

from __future__ import annotations

import pytest

from app.core import crypto
from app.core.crypto import (
    FINGERPRINT_BYTES,
    NONCE_LEN,
    VaultError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64_decode,
    b64_encode,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
    derive_session_key,
    derive_vault_key,
    fingerprint_bytes,
    fingerprint_display,
    fingerprint_parse,
    generate_ed25519,
    generate_x25519,
    key_check,
)


# -- encoding ---------------------------------------------------------------


def test_b64_roundtrip():
    data = b"\x00\x01\x02\xff" * 10
    assert b64_decode(b64_encode(data)) == data


def test_fingerprint_bytes_length_and_determinism():
    x = generate_x25519().public_key().public_bytes_raw()
    e = generate_ed25519().public_key().public_bytes_raw()
    fp = fingerprint_bytes(x, e)
    assert len(fp) == FINGERPRINT_BYTES
    assert fp == fingerprint_bytes(x, e)


def test_fingerprint_bytes_rejects_bad_length():
    with pytest.raises(ValueError):
        fingerprint_bytes(b"short", b"short")


def test_fingerprint_display_format():
    fp = b"\x00" * FINGERPRINT_BYTES
    disp = fingerprint_display(fp)
    groups = disp.split(" ")
    assert len(groups) == 8
    assert all(len(g) == 4 for g in groups)
    # Round-trips back to the same bytes.
    assert fingerprint_parse(disp) == fp


def test_fingerprint_parse_rejects_garbage():
    with pytest.raises(ValueError):
        fingerprint_parse("not a fingerprint")
    with pytest.raises(ValueError):
        fingerprint_parse("ABCD")  # too short


# -- key derivation ---------------------------------------------------------


def test_derive_vault_key_deterministic_with_salt():
    salt = b"0123456789abcdef"
    k1, s1 = derive_vault_key("123456", salt)
    k2, s2 = derive_vault_key("123456", salt)
    assert k1 == k2
    assert s1 == s2 == salt
    assert len(k1) == 32


def test_derive_vault_key_differs_by_pin():
    salt = b"0123456789abcdef"
    k1, _ = derive_vault_key("123456", salt)
    k2, _ = derive_vault_key("654321", salt)
    assert k1 != k2


def test_derive_session_key_deterministic():
    eph = b"\x11" * 32
    fp_l = b"\x01" * FINGERPRINT_BYTES
    fp_p = b"\x02" * FINGERPRINT_BYTES
    k1 = derive_session_key(eph, fp_l, fp_p, None)
    k2 = derive_session_key(eph, fp_l, fp_p, None)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_session_key_psk_changes_key():
    eph = b"\x11" * 32
    fp_l = b"\x01" * FINGERPRINT_BYTES
    fp_p = b"\x02" * FINGERPRINT_BYTES
    k_none = derive_session_key(eph, fp_l, fp_p, None)
    k_psk = derive_session_key(eph, fp_l, fp_p, "hunter2")
    assert k_none != k_psk


def test_key_check_is_16_bytes():
    assert len(key_check(b"\x00" * 32)) == 16


# -- symmetric AEAD ---------------------------------------------------------


def test_aes_gcm_roundtrip():
    key = b"\x00" * 32
    pt = b"hello handshake"
    blob = aes_gcm_encrypt(key, pt)
    assert aes_gcm_decrypt(key, blob) == pt


def test_aes_gcm_tamper_detected():
    key = b"\x00" * 32
    blob = bytearray(aes_gcm_encrypt(key, b"secret"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        aes_gcm_decrypt(key, bytes(blob))


def test_chacha20_poly1305_roundtrip():
    key = b"\x00" * 32
    nonce = b"\x00" * NONCE_LEN
    pt = b"frame payload"
    ct = chacha20_poly1305_encrypt(key, nonce, pt)
    assert chacha20_poly1305_decrypt(key, nonce, ct) == pt


def test_chacha20_poly1305_rejects_bad_nonce_len():
    key = b"\x00" * 32
    with pytest.raises(ValueError):
        chacha20_poly1305_encrypt(key, b"short", b"x")
    with pytest.raises(ValueError):
        chacha20_poly1305_decrypt(key, b"short", b"x")
