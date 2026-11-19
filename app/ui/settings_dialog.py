"""Settings dialog: listen port, archive, lock timeout, theme, export/import."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from ..core.addresses import detect_lan_ip, detect_public_ip
from ..core.appcore import AppCore
from ..core.vault import Settings, VaultError


class SettingsDialog(QDialog):
    def __init__(
        self,
        settings: Settings,
        parent=None,
        core: AppCore | None = None,
        on_imported=None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.resize(460, 420)
        self._settings = settings
        self._core = core
        self._on_imported = on_imported
        self._imported = False

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Settings")
        title.setObjectName("h1")
        layout.addWidget(title)

        form = QFormLayout()

        self.port_edit = QLineEdit(str(settings.listen_port))
        self.port_edit.setPlaceholderText("41337")
        form.addRow("Listen port", self.port_edit)

        self.archive_check = QCheckBox("Encrypt & store chat history locally")
        self.archive_check.setChecked(settings.archive_enabled)
        form.addRow("", self.archive_check)

        self.lock_edit = QLineEdit(str(settings.lock_timeout_minutes))
        self.lock_edit.setPlaceholderText("5")
        form.addRow("Lock after (minutes)", self.lock_edit)

        layout.addLayout(form)

        # -- address --------------------------------------------------------
        addr = QFrame()
        addr.setObjectName("card")
        aform = QFormLayout(addr)
        aform.setContentsMargins(12, 12, 12, 12)
        aform.setSpacing(8)

        addr_title = QLabel("Your address")
        addr_title.setObjectName("h2")
        aform.addRow(addr_title)

        pub_row = QWidget()
        pub_l = QHBoxLayout(pub_row)
        pub_l.setContentsMargins(0, 0, 0, 0)
        pub_l.setSpacing(6)
        self.public_ip_edit = QLineEdit(settings.public_ip)
        self.public_ip_edit.setPlaceholderText("e.g. 203.0.113.5")
        pub_detect = QPushButton("Detect")
        pub_detect.setToolTip("Look up your public IP on the internet")
        pub_detect.clicked.connect(self._detect_public)
        pub_l.addWidget(self.public_ip_edit, 1)
        pub_l.addWidget(pub_detect)
        aform.addRow("Public IP", pub_row)

        lan_row = QWidget()
        lan_l = QHBoxLayout(lan_row)
        lan_l.setContentsMargins(0, 0, 0, 0)
        lan_l.setSpacing(6)
        self.lan_ip_edit = QLineEdit(settings.lan_ip)
        self.lan_ip_edit.setPlaceholderText("e.g. 192.168.1.20")
        lan_detect = QPushButton("Detect")
        lan_detect.setToolTip("Detect your address on the local network")
        lan_detect.clicked.connect(self._detect_lan)
        lan_l.addWidget(self.lan_ip_edit, 1)
        lan_l.addWidget(lan_detect)
        aform.addRow("Local (LAN) IP", lan_row)

        self.custom_url_edit = QLineEdit(settings.custom_url)
        self.custom_url_edit.setPlaceholderText("e.g. chat.example.com")
        aform.addRow("Custom URL", self.custom_url_edit)

        addr_note = QLabel(
            "This is what goes on your Identity Card so others can reach you. "
            "Priority: Custom URL, then Public IP, then Local IP. Leave the "
            "higher-priority ones empty to fall back."
        )
        addr_note.setObjectName("muted")
        addr_note.setWordWrap(True)
        aform.addRow(addr_note)

        layout.addWidget(addr)

        note = QLabel(
            "Changing the listen port means peers must update your address."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(note)

        # -- export / import ------------------------------------------------
        if self._core is not None:
            transfer = QFrame()
            transfer.setObjectName("card")
            grid = QGridLayout(transfer)
            grid.setContentsMargins(12, 12, 12, 12)
            grid.setSpacing(8)

            transfer_title = QLabel("Move to another computer")
            transfer_title.setObjectName("h2")
            grid.addWidget(transfer_title, 0, 0, 1, 2)

            export_btn = QPushButton("Export identity bundle…")
            export_btn.setToolTip(
                "Save your identity, peers, settings and chat history to one "
                "file (encrypted with your PIN)."
            )
            export_btn.clicked.connect(self._export_bundle)
            grid.addWidget(export_btn, 1, 0)

            import_btn = QPushButton("Import identity bundle…")
            import_btn.setToolTip(
                "Restore a bundle exported from another computer. Replaces "
                "the current identity."
            )
            import_btn.clicked.connect(self._import_bundle)
            grid.addWidget(import_btn, 1, 1)

            transfer_note = QLabel(
                "Importing replaces your current identity, peers and history."
            )
            transfer_note.setObjectName("muted")
            transfer_note.setWordWrap(True)
            grid.addWidget(transfer_note, 2, 0, 1, 2)

            layout.addWidget(transfer)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _save(self) -> None:
        port_text = self.port_edit.text().strip()
        if not (port_text.isdigit() and 1 <= int(port_text) <= 65535):
            QMessageBox.warning(self, "Settings", "Port must be 1–65535.")
            return
        lock_text = self.lock_edit.text().strip()
        if not (lock_text.isdigit() and 0 <= int(lock_text) <= 1440):
            QMessageBox.warning(self, "Settings", "Lock timeout must be 0–1440 minutes.")
            return
        self._settings.listen_port = int(port_text)
        self._settings.archive_enabled = self.archive_check.isChecked()
        self._settings.lock_timeout_minutes = int(lock_text)
        self._settings.public_ip = self.public_ip_edit.text().strip()
        self._settings.lan_ip = self.lan_ip_edit.text().strip()
        self._settings.custom_url = self.custom_url_edit.text().strip()
        self.accept()

    def _detect_public(self) -> None:
        # Synchronous (a few seconds at most); keeps the code simple and safe.
        self.public_ip_edit.setText("Looking up…")
        self.public_ip_edit.setEnabled(False)
        self.processEvents()
        ip = detect_public_ip()
        self.public_ip_edit.setEnabled(True)
        if ip:
            self.public_ip_edit.setText(ip)
        else:
            self.public_ip_edit.setText("")
            QMessageBox.warning(
                self, "Detect public IP", "Could not detect your public IP."
            )

    def _detect_lan(self) -> None:
        ip = detect_lan_ip()
        if ip:
            self.lan_ip_edit.setText(ip)
        else:
            QMessageBox.warning(
                self, "Detect local IP", "Could not detect your local IP."
            )

    # -- export / import ----------------------------------------------------

    def _export_bundle(self) -> None:
        assert self._core is not None
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Identity Bundle",
            "handshake-identity.json",
            "JSON (*.json)",
        )
        if not path:
            return
        try:
            self._core.export_bundle(path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(
            self,
            "Bundle exported",
            "Your identity, peers, settings and chat history were saved to:\n"
            f"{path}\n\n"
            "Keep this file safe — it contains your private keys."
            + (
                " It is encrypted with your PIN."
                if self._core.vault is not None and self._core.vault.has_pin
                else " Your vault has no PIN, so the file is NOT encrypted."
            ),
        )

    def _import_bundle(self) -> None:
        assert self._core is not None
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Identity Bundle",
            "",
            "JSON (*.json)",
        )
        if not path:
            return
        # Peek at the file to see whether it is PIN-protected.
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as exc:
            QMessageBox.critical(self, "Import failed", f"Could not read file: {exc}")
            return
        if doc.get("magic") != "HANDSHAKE-BUNDLE":
            QMessageBox.critical(
                self, "Import failed", "That file is not a Handshake bundle."
            )
            return
        pin: str | None = None
        if doc.get("encrypted"):
            pin, ok = QInputDialog.getText(
                self,
                "Bundle PIN",
                "This bundle is PIN-protected. Enter the PIN:",
                QLineEdit.EchoMode.Password,
            )
            if not ok:
                return
        confirm = QMessageBox.question(
            self,
            "Import identity",
            "This replaces your current identity, peers and chat history.\n"
            "Continue?",
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            self._core.import_bundle(path, pin)
        except VaultError as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Import failed", str(exc))
            return
        self._imported = True
        if self._on_imported is not None:
            self._on_imported()
        self.accept()
