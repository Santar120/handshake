"""Unit tests for app.protocol.frames (length-prefixed framing + hello codec)."""

from __future__ import annotations

import pytest

from app.protocol.frames import (
    FrameError,
    FrameReader,
    HelloMessage,
    decode_hello,
    encode_hello,
    encode_hello_reject,
)
from app.protocol.handshake import build_hello
from app.core.identity import new_identity
from app.core.crypto import generate_ephemeral_x25519


def _hello() -> HelloMessage:
    idn = new_identity("Alice")
    eph = generate_ephemeral_x25519()
    return build_hello(idn, eph, None)


def test_frame_reader_single_frame():
    reader = FrameReader()
    payload = b"hello"
    frames = reader.feed(encode_hello(_hello())[:0] + _pack(payload))
    assert frames == [payload]


def _pack(payload: bytes) -> bytes:
    import struct

    return struct.pack(">I", len(payload)) + payload


def test_frame_reader_splits_across_feeds():
    reader = FrameReader()
    payload = b"0123456789"
    wire = _pack(payload)
    # Feed one byte at a time; nothing until the full frame arrives.
    for i in range(len(wire) - 1):
        assert reader.feed(wire[i : i + 1]) == []
    assert reader.feed(wire[len(wire) - 1 :]) == [payload]


def test_frame_reader_multiple_frames_one_feed():
    reader = FrameReader()
    a, b = b"aaa", b"bbbb"
    frames = reader.feed(_pack(a) + _pack(b))
    assert frames == [a, b]


def test_frame_reader_rejects_oversized():
    reader = FrameReader()
    import struct

    wire = struct.pack(">I", 17 * 1024 * 1024) + b"\x00"
    with pytest.raises(FrameError):
        reader.feed(wire)


def _parse(wire: bytes) -> bytes:
    """Feed wire bytes through FrameReader; return the single payload."""
    frames = FrameReader().feed(wire)
    assert len(frames) == 1
    return frames[0]


def test_hello_roundtrip():
    msg = _hello()
    decoded = decode_hello(_parse(encode_hello(msg)))
    assert isinstance(decoded, HelloMessage)
    assert decoded.alias == msg.alias
    assert decoded.x25519 == msg.x25519
    assert decoded.ed25519 == msg.ed25519
    assert decoded.eph_pub == msg.eph_pub
    assert decoded.sig == msg.sig
    assert decoded.psk_flag == msg.psk_flag


def test_hello_reject_roundtrip():
    decoded = decode_hello(_parse(encode_hello_reject("unknown-peer")))
    assert type(decoded).__name__ == "HelloReject"
    assert decoded.reason == "unknown-peer"


def test_decode_hello_rejects_non_handshake():
    with pytest.raises(FrameError):
        decode_hello(b"\x00\x00\x00\x01x")
