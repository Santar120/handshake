"""LAN peer discovery: opt-in, time-limited UDP broadcast presence.

When enabled, this announces the local identity on the local network and
listens for other Handshake instances doing the same. It is a *pre-connection*
presence channel only — it does not open the encrypted data connection. When a
new peer is seen, the UI can prompt the user to add it (dialing the port and
address carried on the beacon).

No new dependencies: plain UDP broadcast driven by the asyncio loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
from typing import Callable

from ..core.crypto import b64_decode, b64_encode
from ..core.identity import PeerIdentity

log = logging.getLogger(__name__)

DISCOVERY_MAGIC = "HANDSHAKE-DISCOVERY v1"
DEFAULT_CHANNEL_PORT = 41339
DEFAULT_BROADCAST_ADDR = "255.255.255.255"
DEFAULT_ANNOUNCE_INTERVAL = 2.0
DEFAULT_DURATION = 120.0  # seconds; auto-stop after this long


class Discovery:
    """Runs on the asyncio loop. Announces the local identity and listens for
    other Handshake instances on the LAN.

    ``on_discovered(peer, source_ip, beacon)`` is invoked (on the loop thread)
    once per newly seen peer. ``beacon`` is the raw beacon bytes, which the UI
    can hand straight to ``add_peer`` (it is a parseable identity card). The
    caller decides what to do with it (e.g. prompt to add).
    """

    def __init__(
        self,
        identity,
        on_discovered: Callable[[PeerIdentity, str, bytes], None],
        advertised_port: int,
        advertised_address: str = "",
        channel_port: int = DEFAULT_CHANNEL_PORT,
        broadcast_addr: str = DEFAULT_BROADCAST_ADDR,
        announce_interval: float = DEFAULT_ANNOUNCE_INTERVAL,
    ) -> None:
        self._identity = identity
        self._on_discovered = on_discovered
        self._advertised_port = int(advertised_port)
        self._advertised_address = advertised_address
        self._channel_port = channel_port
        self._broadcast_addr = broadcast_addr
        self._announce_interval = announce_interval

        self._sock: socket.socket | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._tasks: list[asyncio.Task] = []
        self._seen: dict[str, PeerIdentity] = {}
        self._beacon: bytes = b""
        self._own_fp = identity.fingerprint_display

    @property
    def port(self) -> int:
        """The actual bound channel port (useful when channel_port=0)."""
        if self._sock is not None:
            return self._sock.getsockname()[1]
        return self._channel_port

    def _build_beacon(self) -> bytes:
        doc = {
            "magic": DISCOVERY_MAGIC,
            "alias": self._identity.alias,
            "x25519": b64_encode(self._identity.x25519_pub),
            "ed25519": b64_encode(self._identity.ed25519_pub),
            "fingerprint": self._own_fp,
            "port": self._advertised_port,
        }
        if self._advertised_address:
            doc["address"] = self._advertised_address
        return json.dumps(doc, separators=(",", ":")).encode("utf-8")

    async def start(self) -> None:
        if self._sock is not None:
            return
        self._loop = asyncio.get_running_loop()
        self._beacon = self._build_beacon()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self._channel_port))
        self._sock = sock

        self._tasks = [
            asyncio.create_task(self._announce_loop()),
            asyncio.create_task(self._receive_loop()),
        ]
        log.info("discovery started on port %s", self.port)

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        log.info("discovery stopped")

    async def _announce_loop(self) -> None:
        assert self._loop is not None and self._sock is not None
        while True:
            try:
                await self._loop.sock_sendto(
                    self._sock, self._beacon, (self._broadcast_addr, self.port)
                )
            except Exception as exc:
                log.debug("discovery announce failed: %s", exc)
            await asyncio.sleep(self._announce_interval)

    async def _receive_loop(self) -> None:
        assert self._loop is not None and self._sock is not None
        while True:
            try:
                # sock_recvfrom returns (data, (host, port)) — we need the
                # source IP to know where the peer is reachable.
                data, addr = await self._loop.sock_recvfrom(self._sock, 65536)
            except (ConnectionResetError, OSError):
                break  # socket closed
            self._handle_beacon(data, addr[0])

    def _handle_beacon(self, data: bytes, source_ip: str) -> None:
        try:
            doc = json.loads(data.decode("utf-8"))
            if doc.get("magic") != DISCOVERY_MAGIC:
                return
            peer = PeerIdentity(
                alias=doc["alias"],
                x25519_pub=b64_decode(doc["x25519"]),
                ed25519_pub=b64_decode(doc["ed25519"]),
                port=int(doc.get("port", 0)) or None,
                address=doc.get("address") or None,
            )
            # Verify the fingerprint matches the public keys (tamper check).
            if peer.fingerprint_display != doc.get("fingerprint"):
                return
            if peer.fingerprint_display == self._own_fp:
                return  # our own echo
            if peer.fingerprint_display in self._seen:
                return  # already reported this session
            self._seen[peer.fingerprint_display] = peer
            self._on_discovered(peer, source_ip, data)
        except Exception as exc:
            log.debug("discovery: bad beacon from %s: %s", source_ip, exc)
