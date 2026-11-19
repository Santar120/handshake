"""Dialer: initiates outbound connections to configured peers."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from ..core.identity import Identity
from ..core.vault import Peer
from .connection import DIAL_TIMEOUT, PeerConnection

log = logging.getLogger(__name__)

OnMessage = Callable[[str, object], None]
OnState = Callable[[str, str], None]
OnClosed = Callable[[str, str | None], None]


class Dialer:
    """Dials peers by host:port and runs them as PeerConnections in the
    "dialer" role."""

    def __init__(
        self,
        identity: Identity,
        *,
        on_message: OnMessage | None = None,
        on_state: OnState | None = None,
        on_closed: OnClosed | None = None,
    ) -> None:
        self._identity = identity
        self._on_message = on_message
        self._on_state = on_state
        self._on_closed = on_closed
        self._conns: dict[str, PeerConnection] = {}  # by peer fp display
        self._tasks: set[asyncio.Task] = set()

    def connection_for(self, peer_fp_display: str) -> PeerConnection | None:
        return self._conns.get(peer_fp_display)

    @property
    def connections(self) -> list[PeerConnection]:
        return list(self._conns.values())

    async def connect(self, peer: Peer) -> PeerConnection:
        """Dial a peer. Raises on dial timeout / handshake failure."""
        existing = self._conns.get(peer.fingerprint_display)
        if existing is not None and existing.state.value == "connected":
            return existing

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(peer.host, peer.port), timeout=DIAL_TIMEOUT
        )
        conn = PeerConnection(
            reader,
            writer,
            identity=self._identity,
            role="dialer",
            peer=peer,
            on_message=self._make_msg_cb(peer),
            on_state=self._make_state_cb(peer),
            on_closed=self._make_closed_cb(peer),
        )
        self._conns[peer.fingerprint_display] = conn
        task = asyncio.create_task(self._run(conn, peer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return conn

    async def disconnect(self, peer_fp_display: str) -> None:
        conn = self._conns.get(peer_fp_display)
        if conn is not None:
            await conn.close("user disconnected")

    async def stop(self) -> None:
        for conn in list(self._conns.values()):
            await conn.close("dialer stopped")
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()

    def _make_msg_cb(self, peer: Peer):
        def cb(env) -> None:
            if self._on_message:
                self._on_message(peer.fingerprint_display, env)

        return cb

    def _make_state_cb(self, peer: Peer):
        def cb(state) -> None:
            if self._on_state:
                self._on_state(peer.fingerprint_display, state.value)

        return cb

    def _make_closed_cb(self, peer: Peer):
        def cb(reason: str | None) -> None:
            self._conns.pop(peer.fingerprint_display, None)
            if self._on_closed:
                self._on_closed(peer.fingerprint_display, reason)

        return cb

    async def _run(self, conn: PeerConnection, peer: Peer) -> None:
        try:
            await conn.run()
        finally:
            self._conns.pop(peer.fingerprint_display, None)
