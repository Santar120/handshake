"""Frame codec: length-prefixed framing over a byte stream.

Wire format (PROTOCOL.md §1):

    frame       = u32be(length) | frame_bytes
    hello_frame = u32be(length) | b"HSK1" | json_bytes   (unencrypted)
    data_frame  = u32be(length) | nonce(12) | ciphertext+tag  (encrypted)

The codec is stream-oriented: feed it bytes as they arrive, and it yields
complete frames.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any, Iterator

from ..core.crypto import MAX_FRAME_BYTES, HandshakeError

MAGIC_HELLO = b"HSK1"
_HEADER = struct.Struct(">I")


class FrameError(HandshakeError):
    pass


@dataclass
class HelloMessage:
    """HELLO / HELLO_ACK payload (PROTOCOL.md §4)."""

    v: int
    alias: str
    x25519: bytes
    ed25519: bytes
    fingerprint: str
    eph_pub: bytes
    psk_flag: bool
    sig: bytes

    def to_json_bytes(self) -> bytes:
        from ..core.crypto import b64_encode

        doc = {
            "v": self.v,
            "alias": self.alias,
            "x25519": b64_encode(self.x25519),
            "ed25519": b64_encode(self.ed25519),
            "fingerprint": self.fingerprint,
            "eph_pub": b64_encode(self.eph_pub),
            "psk_flag": self.psk_flag,
            "sig": b64_encode(self.sig),
        }
        return json.dumps(doc, sort_keys=True).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "HelloMessage":
        from ..core.crypto import b64_decode

        doc = json.loads(data)
        return cls(
            v=int(doc["v"]),
            alias=doc["alias"],
            x25519=b64_decode(doc["x25519"]),
            ed25519=b64_decode(doc["ed25519"]),
            fingerprint=doc["fingerprint"],
            eph_pub=b64_decode(doc["eph_pub"]),
            psk_flag=bool(doc["psk_flag"]),
            sig=b64_decode(doc["sig"]),
        )


@dataclass
class HelloReject:
    v: int
    reason: str

    def to_json_bytes(self) -> bytes:
        return json.dumps({"v": self.v, "reason": self.reason}).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data: bytes) -> "HelloReject":
        doc = json.loads(data)
        return cls(v=int(doc["v"]), reason=doc["reason"])


class FrameReader:
    """Incremental frame parser. Feed bytes, get complete frames."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        """Return all complete frame payloads (without length headers).

        Incomplete trailing data is buffered for the next call.
        """
        self._buf.extend(data)
        frames: list[bytes] = []
        while True:
            if len(self._buf) < _HEADER.size:
                break
            (length,) = _HEADER.unpack_from(self._buf, 0)
            if length > MAX_FRAME_BYTES:
                raise FrameError(f"frame too large: {length} bytes")
            end = _HEADER.size + length
            if len(self._buf) < end:
                break
            frames.append(bytes(self._buf[_HEADER.size : end]))
            del self._buf[:end]
        return frames


def encode_hello(msg: HelloMessage) -> bytes:
    """HELLO / HELLO_ACK frame (unencrypted, magic-prefixed)."""
    body = MAGIC_HELLO + msg.to_json_bytes()
    return _HEADER.pack(len(body)) + body


def encode_hello_reject(reason: str) -> bytes:
    body = MAGIC_HELLO + HelloReject(v=1, reason=reason).to_json_bytes()
    return _HEADER.pack(len(body)) + body


def decode_hello(frame: bytes) -> HelloMessage | HelloReject:
    """Decode a magic-prefixed handshake frame.

    Raises FrameError if the frame is not a handshake frame.
    """
    if not frame.startswith(MAGIC_HELLO):
        raise FrameError("not a handshake frame")
    payload = frame[len(MAGIC_HELLO) :]
    doc = json.loads(payload)
    if "reason" in doc:
        return HelloReject(v=int(doc["v"]), reason=doc["reason"])
    return HelloMessage.from_json_bytes(payload)
