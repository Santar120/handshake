"""Listener: accepts inbound TCP connections and runs them as peers."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from ..core.identity import Identity
from ..core.vault import Peer
from .connection import PeerConnection

log = logging.getLogger(__name__)

PeerLookup = Callable[[bytes, bytes], Peer | None]
OnMessage = Callable[[str, object], None]  # (peer_fingerprint_display, envelope)
OnState = Callable[[str, str], None]  # (peer_fingerprint_display, state)
OnClosed = Callable[[str, str | None], None]  # (peer_fingerprint_display, reason)


class Listener:
    """Listens on a TCP port; each accepted connection becomes a
    PeerConnection in the "listener" role."""

    def __init__(
        self,
        identity: Identity,
        peer_lookup: PeerLookup,
        *,
        on_message: OnMessage | None = None,
        on_state: OnState | None = None,
        on_closed: OnClosed | None = None,
    ) -> None:
        self._identity = identity
        self._peer_lookup = peer_lookup
        self._on_message = on_message
        self._on_state = on_state
        self._on_closed = on_closed
        self._server: asyncio.Server | None = None
        self._conns: dict[int, PeerConnection] = {}
        self._tasks: set[asyncio.Task] = set()

    @property
    def connections(self) -> list[PeerConnection]:
        return list(self._conns.values())

    def connection_for(self, peer_fp_display: str) -> PeerConnection | None:
        for conn in self._conns.values():
            if conn.peer is not None and conn.peer.fingerprint_display == peer_fp_display:
                return conn
        return None

    async def start(self, host: str, port: int) -> None:
        self._server = await asyncio.start_server(self._on_accept, host, port)
        log.info("listening on %s:%s", host, port)

    async def stop(self) -> None:
        for conn in list(self._conns.values()):
            await conn.close("listener stopped")
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Wait for the per-connection tasks to wind down so none are left
        # pending when the event loop closes (avoids shutdown noise).
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()

    async def _on_accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        log.info("inbound connection from %s", peername)

        # Construct first, then attach callbacks that need a reference to
        # the connection itself (they can't be passed into the constructor,
        # where ``conn`` is not yet bound).
        conn = PeerConnection(
            reader,
            writer,
            identity=self._identity,
            role="listener",
            peer_lookup=self._peer_lookup,
        )
        conn._on_message = self._make_msg_cb(conn)
        conn._on_state = self._make_state_cb(conn)
        conn._on_closed = self._make_closed_cb(conn)
        self._conns[id(conn)] = conn
        task = asyncio.create_task(self._run(conn))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _fp(self, conn: PeerConnection) -> str:
        if conn.peer is not None:
            return conn.peer.fingerprint_display
        return "unknown"

    def _make_msg_cb(self, conn: PeerConnection):
        def cb(env) -> None:
            if self._on_message:
                self._on_message(self._fp(conn), env)

        return cb

    def _make_state_cb(self, conn: PeerConnection):
        def cb(state) -> None:
            if self._on_state:
                self._on_state(self._fp(conn), state.value)

        return cb

    def _make_closed_cb(self, conn: PeerConnection):
        def cb(reason: str | None) -> None:
            self._conns.pop(id(conn), None)
            if self._on_closed:
                self._on_closed(self._fp(conn), reason)

        return cb

    async def _run(self, conn: PeerConnection) -> None:
        try:
            await conn.run()
        finally:
            self._conns.pop(id(conn), None)
