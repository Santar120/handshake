"""AppCore: the bridge between the asyncio networking layer and the Qt UI.

Runs a dedicated asyncio event loop on a background thread. The UI talks
to it through Qt signals (thread-safe) and coroutine-wrapping helper
methods. All state (vault, archive, listener, dialer) lives here.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal

from ..core.addresses import best_address, detect_lan_ip
from ..core.archive import Archive
from ..core.crypto import HandshakeError, fingerprint_parse
from ..core.identity import Identity, PeerIdentity, new_identity, parse_card
from ..core.paths import archive_dir, vault_path
from ..core.vault import Peer, Settings, Vault, VaultError
from ..net.dialer import Dialer
from ..net.discovery import Discovery
from ..net.listener import Listener
from ..protocol.messages import TYPE_CONTROL, TYPE_TEXT, Envelope
from ..protocol.states import ConnState

log = logging.getLogger(__name__)


class AppCore(QObject):
    # -- signals (emitted from the loop thread; Qt marshals to UI thread) --
    state_changed = Signal(str, str)  # peer_fp_display, state
    message_received = Signal(str, object)  # peer_fp_display, Envelope
    connection_lost = Signal(str, str)  # peer_fp_display, reason
    error = Signal(str)  # human-readable error
    # LAN discovery: (alias, fingerprint_display, host, port, beacon_text)
    peer_discovered = Signal(str, str, str, int, str)
    discovery_stopped = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

        self.vault: Vault | None = None
        self.archive: Archive | None = None
        self.listener: Listener | None = None
        self.dialer: Dialer | None = None
        self.discovery: Discovery | None = None
        self._discovery_timer: threading.Timer | None = None
        self._inactivity_lock: threading.Timer | None = None
        self._stopped = False

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Start the background event loop thread."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10)

    def stop(self) -> None:
        # Idempotent: the UI's closeEvent and main() both call stop().
        if self._stopped or self._loop is None:
            return
        self._stopped = True
        try:
            self._run(self.shutdown())
        except RuntimeError:
            # Loop already closed (e.g. a second stop) — nothing to do.
            pass
        try:
            self._loop.call_soon_threadsafe(self._loop.stop)
        except RuntimeError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()
        self._loop.close()

    def _run(self, coro) -> Any:
        """Submit a coroutine to the loop and wait for its result."""
        if self._loop is None:
            raise RuntimeError("AppCore not started")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=30)

    async def shutdown(self) -> None:
        # Both stop() methods close their connections AND await the
        # per-connection tasks, so nothing is left pending when the loop
        # closes (no "Event loop is closed" / "Task was destroyed" noise).
        if self.dialer is not None:
            await self.dialer.stop()
        if self.listener is not None:
            await self.listener.stop()
        if self.discovery is not None:
            await self.discovery.stop()
            self.discovery = None
            self.discovery_stopped.emit()

    # -- onboarding / vault ------------------------------------------------

    def has_vault(self) -> bool:
        return vault_path().exists()

    @property
    def has_pin(self) -> bool:
        """Whether the vault is PIN-protected (live vault, else on-disk)."""
        if self.vault is not None:
            return self.vault.has_pin
        if not self.has_vault():
            return False
        try:
            import json

            doc = json.loads(vault_path().read_text(encoding="utf-8"))
            return bool(doc.get("has_pin"))
        except Exception:
            return False

    def onboard(self, alias: str, pin: str | None) -> Identity:
        """First launch: create identity + vault, start listener."""
        identity = new_identity(alias)
        vault = Vault.create(vault_path(), identity, pin)
        self._adopt_vault(vault)
        return identity

    def unlock(self, pin: str | None) -> Identity:
        vault = Vault.open(vault_path(), pin)
        self._adopt_vault(vault)
        return vault.identity

    def verify_pin(self, pin: str | None) -> bool:
        """Check a PIN against the already-unlocked vault (lock screen).

        Does NOT re-open the vault or drop connections. A PIN-less vault
        accepts anything.
        """
        if self.vault is None:
            return False
        if not self.vault.has_pin:
            return True
        if not pin:
            return False
        from .crypto import derive_vault_key

        try:
            key, _ = derive_vault_key(pin, self.vault._salt)
        except Exception:
            return False
        # Re-derive and compare against the live key.
        return key == self.vault._key

    def _adopt_vault(self, vault: Vault) -> None:
        self.vault = vault
        self.archive = Archive(vault._key)
        self.dialer = Dialer(
            vault.identity,
            on_message=self._on_message,
            on_state=self._on_state,
            on_closed=self._on_closed,
        )
        self.listener = Listener(
            vault.identity,
            self._lookup_peer,
            on_message=self._on_message,
            on_state=self._on_state,
            on_closed=self._on_closed,
        )
        self._run(self.listener.start("0.0.0.0", vault.settings.listen_port))
        self._ensure_lan_ip()

    def _ensure_lan_ip(self) -> None:
        """Auto-fill the LAN IP on first launch so the Identity Card has a
        usable default address without the user opening Settings.

        Only fills an empty field — a value the user set (or a failed
        detection) is never overwritten. detect_lan_ip() makes no outbound
        network call, so this is safe to run at startup.
        """
        if self.vault is None:
            return
        if self.vault.settings.lan_ip.strip():
            return
        ip = detect_lan_ip()
        if ip:
            self.vault.update_settings(lan_ip=ip)

    def _lookup_peer(self, x25519_pub: bytes, ed25519_pub: bytes) -> Peer | None:
        if self.vault is None:
            return None
        for peer in self.vault.peers:
            if peer.x25519_pub == x25519_pub and peer.ed25519_pub == ed25519_pub:
                return peer
        return None

    # -- identity ----------------------------------------------------------

    @property
    def identity(self) -> Identity | None:
        return self.vault.identity if self.vault else None

    def advertised_address(self) -> str:
        """The host to put on the Identity Card (custom > public > LAN)."""
        assert self.vault is not None
        return best_address(self.vault.settings)

    def identity_card(self) -> str:
        assert self.identity is not None
        return self.identity.to_card(
            port=self.settings().listen_port,
            address=self.advertised_address() or None,
        )

    def identity_qr_png(self) -> bytes:
        assert self.identity is not None
        return self.identity.to_qr_png(
            port=self.settings().listen_port,
            address=self.advertised_address() or None,
        )

    def rotate_keys(self) -> Identity:
        assert self.vault is not None
        new_id = new_identity(self.vault.identity.alias)
        self.vault.rotate_identity(new_id)
        # Rebuild dialer/listener with the new identity.
        self._run(self.shutdown())
        self._adopt_vault(self.vault)
        return new_id

    # -- peers -------------------------------------------------------------

    def add_peer(self, card_text: str, host: str, port: int, psk: str | None) -> Peer:
        """Parse an Identity Card and store the peer. Raises on bad card."""
        assert self.vault is not None
        peer_id = parse_card(card_text)
        peer = Peer(
            alias=peer_id.alias,
            x25519_pub=peer_id.x25519_pub,
            ed25519_pub=peer_id.ed25519_pub,
            host=host,
            port=int(port),
            psk=psk or None,
        )
        self.vault.add_peer(peer)
        return peer

    def remove_peer(self, fingerprint_display: str) -> None:
        assert self.vault is not None
        self.vault.remove_peer(fingerprint_parse(fingerprint_display))

    def peers(self) -> list[Peer]:
        return list(self.vault.peers) if self.vault else []

    # -- LAN discovery -----------------------------------------------------

    def discovery_active(self) -> bool:
        return self.discovery is not None

    def start_discovery(self, duration: float = 120.0) -> None:
        """Start opt-in, time-limited LAN discovery.

        Announces this identity on the LAN and listens for others. Auto-stops
        after ``duration`` seconds (or immediately on shutdown).
        """
        assert self.vault is not None
        if self.discovery is not None:
            return
        self.discovery = Discovery(
            self.vault.identity,
            on_discovered=self._on_peer_discovered,
            advertised_port=self.vault.settings.listen_port,
            advertised_address=self.advertised_address(),
        )
        self._run(self.discovery.start())
        # Time-limited: auto-stop after the given duration.
        self._discovery_timer = threading.Timer(duration, self.stop_discovery)
        self._discovery_timer.daemon = True
        self._discovery_timer.start()

    def stop_discovery(self) -> None:
        if self._discovery_timer is not None:
            self._discovery_timer.cancel()
            self._discovery_timer = None
        if self.discovery is None:
            return
        discovery, self.discovery = self.discovery, None
        try:
            self._run(discovery.stop())
        except RuntimeError:
            pass  # loop already closed
        self.discovery_stopped.emit()

    def _on_peer_discovered(self, peer, source_ip: str, beacon: bytes) -> None:
        # Runs on the loop thread; emit a Qt signal for the UI.
        host = source_ip or (peer.address or "")
        port = peer.port or (self.vault.settings.listen_port if self.vault else 0)
        self.peer_discovered.emit(
            peer.alias, peer.fingerprint_display, host, port, beacon.decode("utf-8")
        )

    # -- connections -------------------------------------------------------

    def connect(self, fingerprint_display: str) -> None:
        assert self.vault is not None and self.dialer is not None
        try:
            fp = fingerprint_parse(fingerprint_display)
        except ValueError:
            self.error.emit(f"unknown peer: {fingerprint_display}")
            return
        peer = self.vault.find_peer_by_fingerprint(fp)
        if peer is None:
            self.error.emit(f"unknown peer: {fingerprint_display}")
            return
        try:
            self._run(self.dialer.connect(peer))
        except (OSError, asyncio.TimeoutError, HandshakeError) as exc:
            self.error.emit(f"connect failed: {exc}")

    def disconnect(self, fingerprint_display: str) -> None:
        if self.dialer is not None:
            self._run(self.dialer.disconnect(fingerprint_display))

    def is_connected(self, fingerprint_display: str) -> bool:
        if self.dialer is not None:
            conn = self.dialer.connection_for(fingerprint_display)
            if conn is not None and conn.state == ConnState.CONNECTED:
                return True
        if self.listener is not None:
            conn = self.listener.connection_for(fingerprint_display)
            if conn is not None and conn.state == ConnState.CONNECTED:
                return True
        return False

    # -- messaging ---------------------------------------------------------

    def send_text(self, fingerprint_display: str, text: str) -> None:
        conn = self._connection_for(fingerprint_display)
        if conn is None:
            self.error.emit("not connected to that peer")
            return
        assert self.identity is not None
        env = Envelope.text(self.identity.fingerprint_display, 0, text)
        # seq is assigned by the connection
        try:
            self._run(self._send_envelope(conn, env))
        except Exception as exc:
            self.error.emit(f"send failed: {exc}")

    async def _send_envelope(self, conn, env: Envelope) -> None:
        await conn.send_envelope(env)

    def _connection_for(self, fingerprint_display: str):
        if self.dialer is not None:
            conn = self.dialer.connection_for(fingerprint_display)
            if conn is not None:
                return conn
        if self.listener is not None:
            return self.listener.connection_for(fingerprint_display)
        return None

    # -- archive -----------------------------------------------------------

    def load_history(self, fingerprint_display: str) -> list[dict]:
        if self.archive is None:
            return []
        return self.archive.load(fingerprint_display)

    # -- settings ----------------------------------------------------------

    def settings(self) -> Settings:
        assert self.vault is not None
        return self.vault.settings

    def update_settings(self, **kwargs) -> None:
        assert self.vault is not None
        old_port = self.vault.settings.listen_port
        self.vault.update_settings(**kwargs)
        new_port = self.vault.settings.listen_port
        # A port change requires restarting the listener (peers must update
        # their address for this install).
        if new_port != old_port and self.listener is not None:
            self._run(self.listener.stop())
            self._run(self.listener.start("0.0.0.0", new_port))

    # -- export / import ----------------------------------------------------

    def export_card_json(self) -> str:
        """Public identity card as JSON (safe to share)."""
        assert self.identity is not None
        return self.identity.to_card_json(
            port=self.settings().listen_port,
            address=self.advertised_address() or None,
        )

    def export_bundle(self, path: str) -> None:
        """Export the full identity bundle (keys, peers, settings, history)."""
        assert self.vault is not None
        archive = self.archive.list_files() if self.archive is not None else {}
        text = self.vault.export_bundle(archive)
        Path(path).write_text(text, encoding="utf-8")

    def import_bundle(self, path: str, pin: str | None) -> None:
        
        text = Path(path).read_text(encoding="utf-8")
        vault = Vault.import_bundle(text, vault_path(), pin, archive_dir())
        self._run(self.shutdown())
        self._adopt_vault(vault)
        self.state_changed.emit("imported", "identity imported")

    # -- callbacks from the network layer (loop thread) --------------------

    def _on_message(self, fp: str, env: Envelope) -> None:
        if env.type == TYPE_TEXT:
            if self.archive is not None and self.vault is not None:
                if self.vault.settings.archive_enabled:
                    self.archive.append(fp, env.__dict__)
        self.message_received.emit(fp, env)

    def _on_state(self, fp: str, state: str) -> None:
        self.state_changed.emit(fp, state)

    def _on_closed(self, fp: str, reason: str | None) -> None:
        self.connection_lost.emit(fp, reason or "connection lost")
