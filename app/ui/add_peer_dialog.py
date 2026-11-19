"""Add-peer dialog: paste Identity Card, set address + shared secret."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from ..core.identity import IdentityCardError, parse_card
from ..core.vault import DEFAULT_LISTEN_PORT


class AddPeerDialog(QDialog):
    """Collects an Identity Card + transport + optional shared secret.

    On accept: .peer_fields() returns (card_text, host, port, psk).
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add peer")
        self.resize(560, 520)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        intro = QLabel(
            "Paste the other person's Identity Card, then enter their "
            "address (host:port)."
        )
        intro.setObjectName("muted")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.card_edit = QPlainTextEdit()
        self.card_edit.setPlaceholderText(
            "HANDSHAKE-IDENTITY v1\nalias: ...\nx25519: ...\ned25519: ...\nfingerprint: ...\n"
        )
        self.card_edit.setFixedHeight(150)
        layout.addWidget(self.card_edit)

        self.card_status = QLabel("")
        self.card_status.setObjectName("muted")
        self.card_status.setWordWrap(True)
        layout.addWidget(self.card_status)
        self.card_edit.textChanged.connect(self._validate_card)

        form = QFormLayout()
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("e.g. 192.168.1.20 or their public IP")
        form.addRow("Host", self.host_edit)
        self.port_edit = QLineEdit(str(DEFAULT_LISTEN_PORT))
        self.port_edit.setPlaceholderText(str(DEFAULT_LISTEN_PORT))
        form.addRow("Port", self.port_edit)
        layout.addLayout(form)

        psk_group = QGroupBox("Shared secret (recommended)")
        psk_layout = QVBoxLayout(psk_group)
        psk_desc = QLabel(
            "A password only the two of you know. Both sides must set the "
            "same value. If it's wrong or missing on one side, the "
            "connection fails with a clear error."
        )
        psk_desc.setObjectName("muted")
        psk_desc.setWordWrap(True)
        psk_layout.addWidget(psk_desc)
        self.psk_edit = QLineEdit()
        self.psk_edit.setPlaceholderText("Leave empty to skip")
        psk_layout.addWidget(self.psk_edit)
        layout.addWidget(psk_group)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Add peer")
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _validate_card(self) -> None:
        text = self.card_edit.toPlainText().strip()
        if not text:
            self.card_status.setText("")
            return
        try:
            peer = parse_card(text)
            status = f"✓ Valid card — {peer.alias}  ({peer.fingerprint_display})"
            if peer.address:
                # Pre-fill the host from the card (user can still override).
                if self.host_edit.text().strip() != peer.address:
                    self.host_edit.setText(peer.address)
                status += f"  · address {peer.address}"
            if peer.port is not None:
                # Pre-fill the port from the card (user can still override).
                if self.port_edit.text().strip() != str(peer.port):
                    self.port_edit.setText(str(peer.port))
                status += f"  · port {peer.port}"
            self.card_status.setText(status)
            self.card_status.setStyleSheet("color: #4caf7d;")
        except IdentityCardError as exc:
            self.card_status.setText(f"✗ {exc}")
            self.card_status.setStyleSheet("color: #ff8f98;")

    def _accept(self) -> None:
        text = self.card_edit.toPlainText().strip()
        try:
            parse_card(text)
        except IdentityCardError as exc:
            QMessageBox.warning(self, "Identity Card", str(exc))
            return
        host = self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(self, "Address", "Please enter a host.")
            return
        port_text = self.port_edit.text().strip()
        if not (port_text.isdigit() and 1 <= int(port_text) <= 65535):
            QMessageBox.warning(self, "Address", "Port must be 1–65535.")
            return
        self.accept()

    def peer_fields(self) -> tuple[str, str, int, str | None]:
        return (
            self.card_edit.toPlainText().strip(),
            self.host_edit.text().strip(),
            int(self.port_edit.text().strip()),
            self.psk_edit.text().strip() or None,
        )
