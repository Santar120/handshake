"""Unit tests for app.protocol.channel (AEAD framing + nonce ordering)."""

from __future__ import annotations

import pytest

from app.protocol.channel import ChannelError, EncryptedChannel


def _pair():
    key = b"\x00" * 32
    pa, pb = b"\x01" * 8, b"\x02" * 8
    return (
        EncryptedChannel(key, pa, pb),
        EncryptedChannel(key, pb, pa),
    )


def test_encrypt_decrypt_roundtrip():
    a, b = _pair()
    frame = a.encrypt(b"hello")
    assert b.decrypt(frame) == b"hello"


def test_bidirectional_multiple_frames():
    a, b = _pair()
    for i in range(50):
        msg = f"message {i}".encode()
        assert b.decrypt(a.encrypt(msg)) == msg
        assert a.decrypt(b.encrypt(msg)) == msg


def test_out_of_order_frame_rejected():
    a, b = _pair()
    f0 = a.encrypt(b"first")   # counter 0
    f1 = a.encrypt(b"second")  # counter 1
    # Delivering f1 before f0 is out of order (recv expects counter 0).
    with pytest.raises(ChannelError):
        b.decrypt(f1)


def test_replay_rejected():
    a, b = _pair()
    f0 = a.encrypt(b"first")
    b.decrypt(f0)
    with pytest.raises(ChannelError):
        b.decrypt(f0)  # replay of counter 0


def test_wrong_key_fails():
    a = EncryptedChannel(b"\x00" * 32, b"\x01" * 8, b"\x02" * 8)
    b = EncryptedChannel(b"\x02" * 32, b"\x01" * 8, b"\x02" * 8)
    with pytest.raises(ChannelError):
        b.decrypt(a.encrypt(b"secret"))


def test_wrong_prefix_fails():
    a = EncryptedChannel(b"\x00" * 32, b"\x01" * 8, b"\x02" * 8)
    b = EncryptedChannel(b"\x00" * 32, b"\x03" * 8, b"\x04" * 8)
    with pytest.raises(ChannelError):
        b.decrypt(a.encrypt(b"secret"))


def test_tampered_ciphertext_fails():
    a, b = _pair()
    frame = bytearray(a.encrypt(b"secret"))
    frame[-1] ^= 0x01
    with pytest.raises(ChannelError):
        b.decrypt(bytes(frame))


def test_frame_too_short():
    _, b = _pair()
    with pytest.raises(ChannelError):
        b.decrypt(b"tiny")
