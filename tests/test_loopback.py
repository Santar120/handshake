"""Loopback integration test: two peers over localhost TCP.

This is the Phase 0 "done" criterion: two peers complete the full
handshake (HELLO/HELLO_ACK + keycheck) and exchange encrypted text in
both directions. Uses the real Listener + Dialer + PeerConnection stack.
Pure asyncio — no Qt involved.
"""

from __future__ import annotations

import asyncio
import socket

from app.core.identity import new_identity
from app.core.vault import Peer
from app.net.dialer import Dialer
from app.net.listener import Listener
from app.protocol.messages import TYPE_TEXT, Envelope
from app.protocol.states import ConnState


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _peer(alias: str, idn, host: str, port: int, psk: str | None) -> Peer:
    return Peer(
        alias=alias,
        x25519_pub=idn.x25519_pub,
        ed25519_pub=idn.ed25519_pub,
        host=host,
        port=port,
        psk=psk,
    )


async def _wait(cond, timeout: float = 10.0) -> None:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise TimeoutError("condition not met in time")
        await asyncio.sleep(0.01)


async def _run_scenario(psk: str | None) -> tuple[list[str], list[str]]:
    """Run one full loopback exchange. Returns (alice_rx, bob_rx) texts."""
    alice = new_identity("Alice")
    bob = new_identity("Bob")
    port = _free_port()

    # Each side's view of the other (as a configured peer).
    alice_view_of_bob = _peer("Bob", bob, "127.0.0.1", port, psk)
    bob_view_of_alice = _peer("Alice", alice, "127.0.0.1", port, psk)

    alice_rx: list[str] = []
    bob_rx: list[str] = []
    alice_connected = asyncio.Event()
    bob_connected = asyncio.Event()

    def _collect(rx: list[str]):
        def cb(fp: str, env) -> None:
            if env.type == TYPE_TEXT:
                rx.append(env.payload["text"])
        return cb

    def _state_cb(event: asyncio.Event):
        def cb(fp: str, state: str) -> None:
            if state == ConnState.CONNECTED.value:
                event.set()
        return cb

    # -- Bob: listener side ------------------------------------------------
    bob_listener = Listener(
        bob,
        peer_lookup=lambda x, e: bob_view_of_alice,
        on_message=_collect(bob_rx),
        on_state=_state_cb(bob_connected),
    )
    await bob_listener.start("127.0.0.1", port)

    # -- Alice: dialer side ------------------------------------------------
    alice_dialer = Dialer(
        alice,
        on_message=_collect(alice_rx),
        on_state=_state_cb(alice_connected),
    )

    try:
        conn = await alice_dialer.connect(alice_view_of_bob)

        # Wait for both sides to finish the handshake.
        await _wait(lambda: alice_connected.is_set() and bob_connected.is_set())
        assert conn.state == ConnState.CONNECTED

        # Alice -> Bob
        await conn.send_envelope(
            Envelope.text(alice.fingerprint_display, 0, "hello bob")
        )
        await _wait(lambda: len(bob_rx) == 1)

        # Bob -> Alice (via the listener's connection to Alice)
        bob_conn = bob_listener.connection_for(alice.fingerprint_display)
        assert bob_conn is not None
        await bob_conn.send_envelope(
            Envelope.text(bob.fingerprint_display, 0, "hi alice")
        )
        await _wait(lambda: len(alice_rx) == 1)

        return alice_rx, bob_rx
    finally:
        await alice_dialer.disconnect(alice_view_of_bob.fingerprint_display)
        await bob_listener.stop()


def test_loopback_no_psk():
    alice_rx, bob_rx = asyncio.run(_run_scenario(psk=None))
    assert bob_rx == ["hello bob"]
    assert alice_rx == ["hi alice"]


def test_loopback_with_psk():
    alice_rx, bob_rx = asyncio.run(_run_scenario(psk="shared-secret"))
    assert bob_rx == ["hello bob"]
    assert alice_rx == ["hi alice"]
