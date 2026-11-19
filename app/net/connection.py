"""PeerConnection: one TCP connection to a peer, full lifecycle.

Runs the PROTOCOL.md state machine:

    DISCONNECTED → CONNECTING → HANDSHAKE → CONNECTED → CLOSING → DISCONNECTED

Handles both roles (dialer and listener), the HELLO/HELLO_ACK exchange,
key confirmation, heartbeats, and drop detection.
"""

from __future__ import annotations

import asyncio
import time
from typing import Awaitable, Callable

from ..core.crypto import b64_decode, b64_encode
from ..core.identity import Identity
from ..core.vault import Peer
from ..protocol.channel import ChannelError, EncryptedChannel
from ..protocol.frames import (
    FrameError,
    FrameReader,
    HelloMessage,
    HelloReject,
    decode_hello,
    encode_hello,
    encode_hello_reject,
)
from ..protocol.handshake import (
    REJ_PSK_MISMATCH,
    REJ_UNKNOWN_PEER,
    HandshakeFailed,
    build_hello,
    build_hello_ack,
    channel_prefixes_for,
    derive_session,
    generate_ephemeral_x25519,
    verify_hello,
)
from ..protocol.messages import (
    CTL_CONNECT,
    CTL_DISCONNECT,
    CTL_KEYCHECK,
    CTL_PING,
    CTL_PONG,
    CTL_ROTATE,
    TYPE_CONTROL,
    Envelope,
)
from ..protocol.states import ConnState, StateMachine

HEARTBEAT_INTERVAL = 10.0  # seconds
KEEPALIVE_TIMEOUT = 30.0  # seconds
DIAL_TIMEOUT = 10.0  # seconds

Role = str  # "dialer" | "listener"

OnMessage = Callable[[Envelope], None]
OnState = Callable[[ConnState], None]
OnClosed = Callable[[str | None], None]
PeerLookup = Callable[[bytes, bytes], Peer | None]


class PeerConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        identity: Identity,
        role: Role,
        peer: Peer | None = None,
        peer_lookup: PeerLookup | None = None,
        on_message: OnMessage | None = None,
        on_state: OnState | None = None,
        on_closed: OnClosed | None = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._identity = identity
        self._role = role
        self._peer = peer  # set for dialer; resolved for listener
        self._peer_lookup = peer_lookup
        self._on_message = on_message
        self._on_state = on_state
        self._on_closed = on_closed

        self.sm = StateMachine()
        self.channel: EncryptedChannel | None = None
        self._frame_reader = FrameReader()
        self._frame_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._send_lock = asyncio.Lock()
        self._seq = 0
        self._closed = False
        self._close_reason: str | None = None
        self._last_recv = time.monotonic()
        self._tasks: list[asyncio.Task] = []
        self._expected_key_check: bytes | None = None
        self._closed_event = asyncio.Event()

    # -- public ------------------------------------------------------------

    @property
    def peer(self) -> Peer | None:
        return self._peer

    @property
    def state(self) -> ConnState:
        return self.sm.state

    @property
    def close_reason(self) -> str | None:
        return self._close_reason

    async def run(self) -> None:
        """Run the connection until it closes. Caller creates a task."""
        self._tasks = [asyncio.create_task(self._recv_loop())]
        try:
            if self._role == "dialer":
                await self._handshake_dialer()
            else:
                await self._handshake_listener()
            self._set_state(ConnState.CONNECTED)
            await self._send_control(CTL_CONNECT, alias=self._identity.alias)
            self._tasks += [
                asyncio.create_task(self._read_loop()),
                asyncio.create_task(self._heartbeat_loop()),
            ]
            await self._closed_event.wait()
        except (
            HandshakeFailed,
            ChannelError,
            FrameError,
            ConnectionError,
            asyncio.IncompleteReadError,
            OSError,
        ) as exc:
            self._close_reason = str(exc) or self._close_reason
        finally:
            await self._close()

    async def send(self, envelope: Envelope) -> None:
        # The keycheck frame is sent while still in HANDSHAKE; everything
        # else requires CONNECTED.
        if self.channel is None or self.sm.state not in (
            ConnState.CONNECTED,
            ConnState.HANDSHAKE,
        ):
            raise ConnectionError("not connected")
        frame = self.channel.encrypt(envelope.to_json())
        await self._write_raw(_frame_header(frame) + frame)

    async def send_envelope(self, envelope: Envelope) -> None:
        """Assign the next sequence number and send."""
        self._seq += 1
        envelope.seq = self._seq
        await self.send(envelope)

    async def close(self, reason: str | None = None) -> None:
        await self._close(reason)

    # -- handshake ---------------------------------------------------------

    async def _handshake_dialer(self) -> None:
        assert self._peer is not None
        self._set_state(ConnState.CONNECTING)
        eph = generate_ephemeral_x25519()
        hello = build_hello(self._identity, eph, self._peer.psk)
        await self._write_raw(encode_hello(hello))
        self._set_state(ConnState.HANDSHAKE)

        ack = await self._read_handshake_frame()
        if isinstance(ack, HelloReject):
            raise HandshakeFailed(ack.reason, "rejected by peer")
        verify_hello(ack, self._peer.to_identity(), self._peer.psk, is_ack=True)

        session_key, kc, prefix_a, prefix_b = derive_session(
            eph,
            ack.eph_pub,
            self._identity.fingerprint,
            self._peer.fingerprint,
            self._peer.psk,
        )
        send_prefix, recv_prefix = channel_prefixes_for(
            self._identity.fingerprint, self._peer.fingerprint, prefix_a, prefix_b
        )
        self.channel = EncryptedChannel(session_key, send_prefix, recv_prefix)
        self._expected_key_check = kc
        await self._send_control(CTL_KEYCHECK, key_check=b64_encode(kc))
        await self._await_keycheck()

    async def _handshake_listener(self) -> None:
        self._set_state(ConnState.CONNECTING)
        hello = await self._read_handshake_frame()
        if isinstance(hello, HelloReject):
            raise HandshakeFailed(hello.reason, "rejected by peer")

        peer = self._peer_lookup(hello.x25519, hello.ed25519)
        if peer is None:
            await self._write_raw(encode_hello_reject(REJ_UNKNOWN_PEER))
            raise HandshakeFailed(REJ_UNKNOWN_PEER, "not a configured peer")
        self._peer = peer

        try:
            verify_hello(hello, peer.to_identity(), peer.psk)
        except HandshakeFailed as exc:
            await self._write_raw(encode_hello_reject(exc.reason))
            raise

        eph = generate_ephemeral_x25519()
        ack = build_hello_ack(self._identity, eph, peer.psk)
        await self._write_raw(encode_hello(ack))
        self._set_state(ConnState.HANDSHAKE)

        session_key, kc, prefix_a, prefix_b = derive_session(
            eph,
            hello.eph_pub,
            self._identity.fingerprint,
            peer.fingerprint,
            peer.psk,
        )
        send_prefix, recv_prefix = channel_prefixes_for(
            self._identity.fingerprint, peer.fingerprint, prefix_a, prefix_b
        )
        self.channel = EncryptedChannel(session_key, send_prefix, recv_prefix)
        self._expected_key_check = kc
        await self._send_control(CTL_KEYCHECK, key_check=b64_encode(kc))
        await self._await_keycheck()

    async def _await_keycheck(self) -> None:
        """Read frames until the peer's keycheck arrives; verify it."""
        assert self.channel is not None
        while True:
            frame = await self._read_frame()
            self._last_recv = time.monotonic()
            env = Envelope.from_json(self.channel.decrypt(frame))
            if env.type != TYPE_CONTROL or env.payload.get("subtype") != CTL_KEYCHECK:
                # Not the keycheck — shouldn't happen before CONNECTED,
                # but be lenient: keep waiting.
                continue
            peer_kc = b64_decode(env.payload["key_check"])
            if peer_kc != self._expected_key_check:
                raise ChannelError("shared-secret-mismatch")
            return

    # -- read / heartbeat loops --------------------------------------------

    async def _read_loop(self) -> None:
        assert self.channel is not None
        try:
            while not self._closed:
                frame = await self._frame_queue.get()
                self._last_recv = time.monotonic()
                env = Envelope.from_json(self.channel.decrypt(frame))
                await self._handle(env)
        except (
            ChannelError,
            FrameError,
            ConnectionError,
            asyncio.IncompleteReadError,
            OSError,
        ) as exc:
            self._close_reason = str(exc) or "connection lost"
        finally:
            await self._close()

    async def _recv_loop(self) -> None:
        """Pump raw bytes from the socket into the frame queue."""
        try:
            while not self._closed:
                data = await self._reader.read(65536)
                if not data:
                    raise ConnectionError("peer closed connection")
                for frame in self._frame_reader.feed(data):
                    await self._frame_queue.put(frame)
        except (
            FrameError,
            ConnectionError,
            asyncio.IncompleteReadError,
            OSError,
        ) as exc:
            self._close_reason = str(exc) or "connection lost"
        finally:
            await self._close()

    async def _heartbeat_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self._closed:
                return
            if time.monotonic() - self._last_recv > KEEPALIVE_TIMEOUT:
                self._close_reason = "keepalive timeout"
                await self._close()
                return
            try:
                await self._send_control(CTL_PING)
            except Exception:
                return

    async def _handle(self, env: Envelope) -> None:
        if env.type == TYPE_CONTROL:
            subtype = env.payload.get("subtype")
            if subtype == CTL_PING:
                await self._send_control(CTL_PONG)
            elif subtype == CTL_DISCONNECT:
                self._close_reason = "peer disconnected"
                await self._close()
            elif subtype == CTL_ROTATE and self._on_message:
                self._on_message(env)
            # pong / connect / keycheck: nothing to do here
        else:
            if self._on_message:
                self._on_message(env)

    # -- plumbing ----------------------------------------------------------

    def _set_state(self, new: ConnState) -> None:
        self.sm.transition(new)
        if self._on_state:
            self._on_state(new)

    async def _write_raw(self, data: bytes) -> None:
        async with self._send_lock:
            self._writer.write(data)
            await self._writer.drain()

    async def _read_frame(self) -> bytes:
        """Wait for the next complete frame from the queue."""
        return await self._frame_queue.get()

    async def _read_handshake_frame(self) -> HelloMessage | HelloReject:
        frame = await self._read_frame()
        return decode_hello(frame)

    async def _send_control(self, subtype: str, **extra) -> None:
        env = Envelope.control(
            self._identity.fingerprint_display, 0, subtype, **extra
        )
        await self.send_envelope(env)

    async def _close(self, reason: str | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        if reason:
            self._close_reason = reason
        try:
            if self.sm.state not in (ConnState.DISCONNECTED, ConnState.CLOSING):
                self.sm.transition(ConnState.CLOSING)
                if self._on_state:
                    self._on_state(ConnState.CLOSING)
        except ValueError:
            pass
        # Best-effort clean-close notice.
        if self.channel is not None:
            try:
                await asyncio.wait_for(self._send_control(CTL_DISCONNECT), timeout=2.0)
            except Exception:
                pass
        self.sm.transition(ConnState.DISCONNECTED)
        if self._on_state:
            self._on_state(ConnState.DISCONNECTED)
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass
        for task in self._tasks:
            task.cancel()
        self._closed_event.set()
        if self._on_closed:
            self._on_closed(self._close_reason)


def _frame_header(payload: bytes) -> bytes:
    import struct

    return struct.pack(">I", len(payload))
