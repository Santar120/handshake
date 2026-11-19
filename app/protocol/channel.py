"""Encrypted channel: ChaCha20-Poly1305 framing with monotonic nonces.

PROTOCOL.md §6:
    nonce(12) = rand_prefix(8) || counter(4, big-endian)

Each direction has its own counter (send / receive), so the two sides
never collide. A nonce is never reused within a session.
"""

from __future__ import annotations

import struct

from ..core.crypto import (
    NONCE_LEN,
    NONCE_PREFIX_LEN,
    COUNTER_LEN,
    chacha20_poly1305_decrypt,
    chacha20_poly1305_encrypt,
)

_COUNTER = struct.Struct(">I")


class ChannelError(Exception):
    pass


class EncryptedChannel:
    """Bidirectional AEAD framing for one session.

    ``send_prefix`` and ``recv_prefix`` are the two direction-specific nonce
    prefixes derived from the session key. They are distinct, so the two
    directions never share a nonce.
    """

    def __init__(self, session_key: bytes, send_prefix: bytes, recv_prefix: bytes) -> None:
        if len(session_key) != 32:
            raise ValueError("session key must be 32 bytes")
        if len(send_prefix) != NONCE_PREFIX_LEN:
            raise ValueError("send prefix must be 8 bytes")
        if len(recv_prefix) != NONCE_PREFIX_LEN:
            raise ValueError("recv prefix must be 8 bytes")
        self._key = session_key
        self._send_prefix = send_prefix
        self._recv_prefix = recv_prefix
        self._send_counter = 0
        self._recv_counter = 0

    # -- sending -----------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """Returns nonce(12) || ciphertext+tag (the frame payload)."""
        nonce = self._send_prefix + _COUNTER.pack(self._send_counter)
        self._send_counter += 1
        return nonce + chacha20_poly1305_encrypt(self._key, nonce, plaintext)

    # -- receiving ---------------------------------------------------------

    def decrypt(self, frame: bytes) -> bytes:
        """frame = nonce(12) || ciphertext+tag. Returns plaintext.

        Enforces the expected receive counter (reordering / replay
        protection within a session).
        """
        if len(frame) < NONCE_LEN + 16:
            raise ChannelError("frame too short")
        nonce, ct = frame[:NONCE_LEN], frame[NONCE_LEN:]
        if nonce[:NONCE_PREFIX_LEN] != self._recv_prefix:
            raise ChannelError("nonce prefix mismatch")
        (counter,) = _COUNTER.unpack(nonce[NONCE_PREFIX_LEN :])
        if counter != self._recv_counter:
            raise ChannelError(
                f"frame out of order: expected seq {self._recv_counter}, got {counter}"
            )
        self._recv_counter += 1
        try:
            return chacha20_poly1305_decrypt(self._key, nonce, ct)
        except Exception as exc:
            raise ChannelError(f"authentication failed: {exc}") from exc
