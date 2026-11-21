"""Main window: sidebar (peers + identity) and chat/identity views."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from ..core.appcore import AppCore
from ..core.vault import Peer
from ..protocol.messages import TYPE_TEXT, Envelope
from ..protocol.states import ConnState
from .add_peer_dialog import AddPeerDialog
from .identity_card_widget import IdentityCardWidget
from .rotate_dialog import RotateKeysDialog, RotateResultDialog
from .screen_lock import ScreenLockWatcher
from .settings_dialog import SettingsDialog
from .theme import DARK_QSS, fingerprint_label, mono_label


class ClickableLabel(QLabel):
    """A QLabel that emits a signal when clicked (used for the sidebar)."""

    clicked = Signal()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class ChatView(QWidget):
    """Per-peer conversation view."""

    def __init__(self, core: AppCore, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._core = core
        self._peer_fp: str | None = None
        self._peer_alias = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # -- header ---------------------------------------------------------
        header = QFrame()
        header.setObjectName("card")
        hlayout = QHBoxLayout(header)
        hlayout.setContentsMargins(12, 8, 12, 8)
        self._title = QLabel("Chat")
        self._title.setObjectName("h2")
        self._fp_label = fingerprint_label("")
        self._status_pill = QLabel("disconnected")
        self._status_pill.setObjectName("pill")
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setObjectName("primary")
        self._connect_btn.clicked.connect(self._on_connect)
        self._disconnect_btn = QPushButton("Disconnect")
        self._disconnect_btn.setObjectName("danger")
        self._disconnect_btn.clicked.connect(self._on_disconnect)
        hlayout.addWidget(self._title)
        hlayout.addWidget(self._fp_label)
        hlayout.addStretch(1)
        hlayout.addWidget(self._status_pill)
        hlayout.addWidget(self._connect_btn)
        hlayout.addWidget(self._disconnect_btn)
        root.addWidget(header)

        # -- messages -------------------------------------------------------
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._msg_container = QWidget()
        self._msg_layout = QVBoxLayout(self._msg_container)
        self._msg_layout.setContentsMargins(12, 12, 12, 12)
        self._msg_layout.setSpacing(6)
        self._msg_layout.addStretch(1)
        self._scroll.setWidget(self._msg_container)
        root.addWidget(self._scroll, 1)

        # -- input ----------------------------------------------------------
        input_row = QHBoxLayout()
        self._input = QLineEdit()
        self._input.setPlaceholderText("Type a message… (Enter to send)")
        self._input.returnPressed.connect(self._send)
        send_btn = QPushButton("Send")
        send_btn.setObjectName("primary")
        send_btn.clicked.connect(self._send)
        input_row.addWidget(self._input, 1)
        input_row.addWidget(send_btn)
        root.addLayout(input_row)

    # -- API ----------------------------------------------------------------

    def set_peer(self, peer: Peer) -> None:
        self._peer_fp = peer.fingerprint_display
        self._peer_alias = peer.alias
        self._title.setText(peer.alias)
        self._fp_label.setText(peer.fingerprint_display)
        # clear messages (keep the trailing stretch at index 0)
        while self._msg_layout.count() > 1:
            item = self._msg_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self._load_history()
        self._refresh_status()

    def _load_history(self) -> None:
        if self._peer_fp is None:
            return
        for env_dict in self._core.load_history(self._peer_fp):
            try:
                env = Envelope(
                    type=env_dict["type"],
                    sender=env_dict["sender"],
                    group=env_dict.get("group"),
                    seq=int(env_dict["seq"]),
                    ts=float(env_dict["ts"]),
                    payload=env_dict.get("payload", {}),
                )
            except (KeyError, ValueError, TypeError):
                continue
            if env.type == TYPE_TEXT:
                self._add_bubble(env)

    def on_message(self, fp: str, env: Envelope) -> None:
        if fp != self._peer_fp or env.type != TYPE_TEXT:
            return
        self._add_bubble(env)

    def on_state(self, fp: str, state: str) -> None:
        if fp == self._peer_fp:
            self._refresh_status()

    def on_lost(self, fp: str, reason: str) -> None:
        if fp == self._peer_fp:
            self._refresh_status()

    def _refresh_status(self) -> None:
        if self._peer_fp is None:
            return
        connected = self._core.is_connected(self._peer_fp)
        if connected:
            self._status_pill.setText("connected")
            self._status_pill.setObjectName("pill_ok")
            self._connect_btn.setEnabled(False)
            self._disconnect_btn.setEnabled(True)
        else:
            self._status_pill.setText("disconnected")
            self._status_pill.setObjectName("pill_bad")
            self._connect_btn.setEnabled(True)
            self._disconnect_btn.setEnabled(False)
        # Force style refresh.
        self._status_pill.style().unpolish(self._status_pill)
        self._status_pill.style().polish(self._status_pill)

    def _add_bubble(self, env: Envelope) -> None:
        mine = self._core.identity is not None and env.sender == self._core.identity.fingerprint_display
        # Who sent it: "You" for our own messages, the peer's alias otherwise.
        sender_name = "You" if mine else (self._peer_alias or "Peer")

        bubble = QFrame()
        bubble.setObjectName("bubble_mine" if mine else "bubble_theirs")
        bubble.setMaximumWidth(480)
        bl = QVBoxLayout(bubble)
        bl.setContentsMargins(10, 6, 10, 6)
        bl.setSpacing(2)

        name = QLabel(sender_name)
        name.setObjectName("bubble_name")
        name.setStyleSheet("font-size: 11px; font-weight: 600;")

        text = QLabel(env.payload.get("text", ""))
        text.setWordWrap(True)
        text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        meta = QLabel(time.strftime("%H:%M", time.localtime(env.ts)))
        meta.setObjectName("muted")
        meta.setStyleSheet("font-size: 10px;")

        inner = (
            Qt.AlignmentFlag.AlignRight if mine else Qt.AlignmentFlag.AlignLeft
        )
        bl.addWidget(name, alignment=inner)
        bl.addWidget(text)
        bl.addWidget(meta, alignment=inner)

        # Left/right-align the bubble so "theirs" reads from the left and
        # "mine" from the right, like a normal chat.
        align = inner
        # insert before the trailing stretch
        self._msg_layout.insertWidget(self._msg_layout.count() - 1, bubble, align)
        self._scroll.verticalScrollBar().setValue(
            self._scroll.verticalScrollBar().maximum()
        )

    def _send(self) -> None:
        text = self._input.text().strip()
        if not text or self._peer_fp is None:
            return
        env = self._core.send_text(self._peer_fp, text)
        self._input.clear()
        if env is not None:
            # The sender never receives its own message back, so echo it
            # locally (it is styled as "mine" by _add_bubble).
            self._add_bubble(env)

    def _on_connect(self) -> None:
        if self._peer_fp is not None:
            self._core.connect(self._peer_fp)

    def _on_disconnect(self) -> None:
        if self._peer_fp is not None:
            self._core.disconnect(self._peer_fp)


class MainWindow(QMainWindow):
    def __init__(self, core: AppCore) -> None:
        super().__init__()
        self._core = core
        self.setWindowTitle("Handshake")
        self.resize(1000, 680)
        self.setStyleSheet(DARK_QSS)

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        # -- sidebar --------------------------------------------------------
        sidebar = QFrame()
        sidebar.setObjectName("card")
        sidebar.setFixedWidth(280)
        sl = QVBoxLayout(sidebar)
        sl.setContentsMargins(10, 10, 10, 10)
        sl.setSpacing(8)

        me = ClickableLabel("My identity")
        me.setObjectName("h2")
        me.setCursor(Qt.CursorShape.PointingHandCursor)
        me.setToolTip("Click to view and share your Identity Card")
        me.clicked.connect(self._show_identity_page)
        sl.addWidget(me)
        self._me_card_holder = QVBoxLayout()
        sl.addLayout(self._me_card_holder)

        peers_title = QLabel("Peers")
        peers_title.setObjectName("h2")
        sl.addWidget(peers_title)
        self._peer_list = QListWidget()
        self._peer_list.currentItemChanged.connect(self._peer_selected)
        self._peer_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._peer_list.customContextMenuRequested.connect(self._peer_context_menu)
        sl.addWidget(self._peer_list, 1)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add peer")
        add_btn.setObjectName("primary")
        add_btn.clicked.connect(self._add_peer)
        rotate_btn = QPushButton("Rotate keys")
        rotate_btn.setObjectName("danger")
        rotate_btn.clicked.connect(self._rotate_keys)
        btn_row.addWidget(add_btn)
        btn_row.addWidget(rotate_btn)
        sl.addLayout(btn_row)

        self._discover_btn = QPushButton("Find peers on this network")
        self._discover_btn.setCheckable(True)
        self._discover_btn.setToolTip(
            "Temporarily look for other Handshake apps on your local network. "
            "Turns off automatically after a couple of minutes."
        )
        self._discover_btn.clicked.connect(self._toggle_discovery)
        sl.addWidget(self._discover_btn)

        settings_btn = QPushButton("Settings")
        settings_btn.clicked.connect(self._open_settings)
        sl.addWidget(settings_btn)

        lock_btn = QPushButton("Lock")
        lock_btn.setToolTip(
            "Lock the app now. It also locks automatically when your "
            "screen locks."
        )
        lock_btn.clicked.connect(self.lock)
        sl.addWidget(lock_btn)

        root.addWidget(sidebar)

        # -- main area ------------------------------------------------------
        self._stack = QStackedWidget()
        self._identity_page = self._build_identity_page()
        self._chat_view = ChatView(core)
        self._stack.addWidget(self._identity_page)
        self._stack.addWidget(self._chat_view)
        root.addWidget(self._stack, 1)

        # -- status bar -----------------------------------------------------
        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._update_statusbar()

        # -- wire core signals ----------------------------------------------
        core.state_changed.connect(self._on_state)
        core.message_received.connect(self._on_message)
        core.connection_lost.connect(self._on_lost)
        core.error.connect(self._on_error)
        core.peer_discovered.connect(self._on_peer_discovered)
        core.discovery_stopped.connect(self._on_discovery_stopped)

        # -- screen lock ------------------------------------------------------
        # Re-lock when the OS screen locks (e.g. laptop lid closed / screen
        # locked), not on a fixed inactivity timer.
        self._screen_lock_watcher = ScreenLockWatcher(self)
        self._screen_lock_watcher.locked.connect(self.lock)

        self.refresh_identity()
        self.refresh_peers()

    # -- pages --------------------------------------------------------------

    def _build_identity_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        title = QLabel("My Identity Card")
        title.setObjectName("h1")
        layout.addWidget(title)
        desc = QLabel(
            "Share this card with people you want to talk to. They paste "
            "it (or scan the QR) into their Handshake to add you."
        )
        desc.setObjectName("muted")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        self._identity_card_holder = QVBoxLayout()
        layout.addLayout(self._identity_card_holder)
        layout.addStretch(1)
        return page

    # -- refresh ------------------------------------------------------------

    def refresh_identity(self) -> None:
        identity = self._core.identity
        if identity is None:
            return
        for holder in (self._me_card_holder, self._identity_card_holder):
            while holder.count():
                item = holder.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()
        # Sidebar gets a compact label; identity page gets the full card.
        me_label = ClickableLabel(f"{identity.alias}\n{identity.fingerprint_display}")
        me_label.setObjectName("mono")
        me_label.setWordWrap(True)
        me_label.setCursor(Qt.CursorShape.PointingHandCursor)
        me_label.setToolTip("Click to view and share your Identity Card")
        me_label.clicked.connect(self._show_identity_page)
        self._me_card_holder.addWidget(me_label)
        port = self._core.settings().listen_port
        address = self._core.advertised_address() or None
        self._identity_card_holder.addWidget(
            IdentityCardWidget(identity, port=port, address=address)
        )

    def refresh_peers(self) -> None:
        self._peer_list.blockSignals(True)
        current = self._current_peer_fp()
        self._peer_list.clear()
        for peer in self._core.peers():
            item = QListWidgetItem(self._peer_item_text(peer))
            item.setData(Qt.ItemDataRole.UserRole, peer.fingerprint_display)
            self._peer_list.addItem(item)
            if peer.fingerprint_display == current:
                self._peer_list.setCurrentItem(item)
        self._peer_list.blockSignals(False)
        self._update_statusbar()

    def _peer_item_text(self, peer: Peer) -> str:
        connected = self._core.is_connected(peer.fingerprint_display)
        mark = "●" if connected else "○"
        return f"{mark} {peer.alias}  ({peer.transport})"

    def _current_peer_fp(self) -> str | None:
        item = self._peer_list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _update_statusbar(self) -> None:
        identity = self._core.identity
        if identity is None:
            return
        port = self._core.settings().listen_port
        address = self._core.advertised_address()
        addr_text = f"{address}:{port}" if address else f"<your-ip>:{port}"
        self._status.showMessage(
            f"Listening on port {port} · your address: {addr_text} · "
            f"identity: {identity.fingerprint_display[:12]}…"
        )

    # -- slots --------------------------------------------------------------

    def _show_identity_page(self) -> None:
        """Return to the identity page (e.g. to reshare the card)."""
        # setCurrentItem(None) actually clears the current item, so picking a
        # peer again re-fires currentItemChanged (clearSelection() does not).
        self._peer_list.setCurrentItem(None)
        self._stack.setCurrentWidget(self._identity_page)

    def _peer_selected(self, current: QListWidgetItem | None, _prev) -> None:
        if current is None:
            return
        fp = current.data(Qt.ItemDataRole.UserRole)
        peer = next((p for p in self._core.peers() if p.fingerprint_display == fp), None)
        if peer is None:
            return
        self._chat_view.set_peer(peer)
        self._stack.setCurrentWidget(self._chat_view)

    def _peer_context_menu(self, pos) -> None:
        """Right-click a peer: offer to remove it."""
        item = self._peer_list.itemAt(pos)
        if item is None:
            return
        fp = item.data(Qt.ItemDataRole.UserRole)
        peer = next((p for p in self._core.peers() if p.fingerprint_display == fp), None)
        if peer is None:
            return
        menu = QMenu(self)
        remove_action = menu.addAction("Remove peer")
        chosen = menu.exec(self._peer_list.mapToGlobal(pos))
        if chosen is remove_action:
            self._remove_peer(peer)

    def _remove_peer(self, peer: Peer) -> None:
        was_current = self._current_peer_fp() == peer.fingerprint_display
        answer = QMessageBox.question(
            self,
            "Remove peer",
            f"Remove \"{peer.alias}\"?\n\n"
            "They will no longer appear in your list. If you're connected, "
            "the connection will be dropped. You can add them again later "
            "with their Identity Card.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            if self._core.is_connected(peer.fingerprint_display):
                self._core.disconnect(peer.fingerprint_display)
            self._core.remove_peer(peer.fingerprint_display)
        except Exception as exc:
            QMessageBox.critical(self, "Remove peer", str(exc))
            return
        if was_current:
            # The open chat was for the removed peer; go back to the identity page.
            self._peer_list.setCurrentItem(None)
            self._stack.setCurrentWidget(self._identity_page)
        self.refresh_peers()

    def _add_peer(self) -> None:
        dlg = AddPeerDialog(self)
        if dlg.exec() != AddPeerDialog.Accepted:
            return
        card_text, host, port, psk = dlg.peer_fields()
        try:
            self._core.add_peer(card_text, host, port, psk)
        except Exception as exc:
            QMessageBox.critical(self, "Add peer", str(exc))
            return
        self.refresh_peers()

    def _toggle_discovery(self) -> None:
        if self._core.discovery_active():
            self._core.stop_discovery()
            return
        if not self._core.start_discovery():
            return  # error already surfaced in the status bar
        self._discover_btn.setChecked(True)
        self._discover_btn.setText("Stop finding peers")
        self._status.showMessage(
            "Looking for other Handshake apps on this network… "
            "(turns off automatically in a couple of minutes)"
        )

    def _on_discovery_stopped(self) -> None:
        self._discover_btn.setChecked(False)
        self._discover_btn.setText("Find peers on this network")
        self._update_statusbar()

    def _on_peer_discovered(self, alias: str, fp: str, host: str, port: int, beacon: str) -> None:
        # Already added? Nothing to do.
        if any(p.fingerprint_display == fp for p in self._core.peers()):
            return
        answer = QMessageBox.question(
            self,
            "Peer found on this network",
            f"Found \"{alias}\" at {host}:{port}.\n\nAdd them to your peer list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._core.add_peer(beacon, host, port, None)
        except Exception as exc:
            QMessageBox.critical(self, "Add peer", str(exc))
            return
        self.refresh_peers()

    def _rotate_keys(self) -> None:
        confirm = RotateKeysDialog(self)
        if confirm.exec() != RotateKeysDialog.Accepted:
            return
        new_identity = self._core.rotate_keys()
        RotateResultDialog(new_identity, self).exec()
        self.refresh_identity()
        self.refresh_peers()
        QMessageBox.information(
            self,
            "Keys rotated",
            "Your identity has changed. Send your new Identity Card to your "
            "peers — they must add it before they can connect again.",
        )

    def _open_settings(self) -> None:
        dlg = SettingsDialog(
            self._core.settings(),
            self,
            core=self._core,
            on_imported=self._after_import,
        )
        if dlg.exec() == SettingsDialog.Accepted:
            # After an import the vault (and its settings) were replaced, so
            # don't write the pre-import settings back over them.
            if not dlg._imported:
                self._core.update_settings(
                    listen_port=dlg._settings.listen_port,
                    archive_enabled=dlg._settings.archive_enabled,
                    public_ip=dlg._settings.public_ip,
                    lan_ip=dlg._settings.lan_ip,
                    custom_url=dlg._settings.custom_url,
                )
            self._update_statusbar()

    def _after_import(self) -> None:
        """Refresh the UI after an identity bundle was imported."""
        self.refresh_identity()
        self.refresh_peers()
        self._update_statusbar()
        QMessageBox.information(
            self,
            "Identity imported",
            "Your identity, peers and chat history were restored from the "
            "bundle.",
        )

    def _on_state(self, fp: str, state: str) -> None:
        self.refresh_peers()
        self._chat_view.on_state(fp, state)

    def _on_message(self, fp: str, env: Envelope) -> None:
        self._chat_view.on_message(fp, env)

    def _on_lost(self, fp: str, reason: str) -> None:
        self.refresh_peers()
        self._chat_view.on_lost(fp, reason)

    def _on_error(self, message: str) -> None:
        self._status.showMessage(message, 8000)

    # -- lock ----------------------------------------------------------------

    def lock(self) -> None:
        """Re-lock the app (show lock screen)."""
        from .lock_screen import LockDialog

        has_pin = self._core.vault.has_pin if self._core.vault else False
        dlg = LockDialog(has_pin, self)
        if dlg.exec() != LockDialog.Accepted:
            self.close()
            return
        pin = dlg.result_pin()
        if not self._core.verify_pin(pin):
            QMessageBox.critical(self, "Unlock failed", "Wrong PIN.")
            self.close()
            return

    def closeEvent(self, event) -> None:  # noqa: N802
        self._core.stop()
        super().closeEvent(event)
