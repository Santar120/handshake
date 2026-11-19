"""Onboarding (first launch): set PIN → choose alias → Identity Card."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.identity import Identity
from .identity_card_widget import IdentityCardWidget


class OnboardingDialog(QDialog):
    """Three-step onboarding. On accept, .identity() is available."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Welcome to Handshake")
        self.resize(640, 560)
        self._identity: Identity | None = None

        self._stack = QVBoxLayout(self)
        self._stack.setSpacing(12)

        # -- Step 1: PIN ----------------------------------------------------
        self._pin_page = QWidget()
        pin_layout = QVBoxLayout(self._pin_page)
        pin_layout.setSpacing(10)
        h = QLabel("Set a PIN")
        h.setObjectName("h1")
        pin_layout.addWidget(h)
        desc = QLabel(
            "This PIN encrypts your identity and chat history on this "
            "computer. Choose 6–8 digits.\n\nYou can skip this — but then "
            "your identity is stored unencrypted."
        )
        desc.setObjectName("muted")
        desc.setWordWrap(True)
        pin_layout.addWidget(desc)

        self.pin_edit = QLineEdit()
        self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_edit.setMaxLength(8)
        self.pin_edit.setPlaceholderText("6–8 digit PIN")
        pin_layout.addWidget(self.pin_edit)

        self.pin_confirm = QLineEdit()
        self.pin_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.pin_confirm.setMaxLength(8)
        self.pin_confirm.setPlaceholderText("Repeat PIN")
        pin_layout.addWidget(self.pin_confirm)

        self.skip_pin = QCheckBox("Skip PIN (store identity unencrypted)")
        self.skip_pin.toggled.connect(self._pin_toggled)
        pin_layout.addWidget(self.skip_pin)
        self._pin_toggled(self.skip_pin.isChecked())

        next_btn = QPushButton("Next")
        next_btn.setObjectName("primary")
        next_btn.clicked.connect(self._step1_next)
        pin_layout.addWidget(next_btn, alignment=Qt.AlignmentFlag.AlignRight)
        pin_layout.addStretch(1)

        # -- Step 2: alias --------------------------------------------------
        self._alias_page = QWidget()
        alias_layout = QVBoxLayout(self._alias_page)
        alias_layout.setSpacing(10)
        h2 = QLabel("Choose an alias")
        h2.setObjectName("h1")
        alias_layout.addWidget(h2)
        desc2 = QLabel("This name appears on your Identity Card and in chats.")
        desc2.setObjectName("muted")
        alias_layout.addWidget(desc2)
        self.alias_edit = QLineEdit()
        self.alias_edit.setPlaceholderText("e.g. Alice")
        self.alias_edit.setMaxLength(32)
        alias_layout.addWidget(self.alias_edit)
        back2 = QPushButton("Back")
        back2.clicked.connect(lambda: self._show_page(self._pin_page))
        next2 = QPushButton("Create my identity")
        next2.setObjectName("primary")
        next2.clicked.connect(self._step2_next)
        row2 = _hrow(back2, next2)
        alias_layout.addLayout(row2)
        alias_layout.addStretch(1)

        # -- Step 3: identity card ------------------------------------------
        self._card_page = QWidget()
        card_layout = QVBoxLayout(self._card_page)
        card_layout.setSpacing(10)
        h3 = QLabel("Your Identity Card")
        h3.setObjectName("h1")
        card_layout.addWidget(h3)
        desc3 = QLabel(
            "Share this card with the people you want to talk to — paste "
            "the text or show the QR code. They add it to their Handshake."
        )
        desc3.setObjectName("muted")
        desc3.setWordWrap(True)
        card_layout.addWidget(desc3)
        self._card_holder = QVBoxLayout()
        card_layout.addLayout(self._card_holder)
        done = QPushButton("Done")
        done.setObjectName("primary")
        done.clicked.connect(self.accept)
        card_layout.addWidget(done, alignment=Qt.AlignmentFlag.AlignRight)
        card_layout.addStretch(1)

        self._stack.addWidget(self._pin_page)
        self._stack.addWidget(self._alias_page)
        self._stack.addWidget(self._card_page)
        self._show_page(self._pin_page)

    # -- helpers -----------------------------------------------------------

    def _show_page(self, page: QWidget) -> None:
        for w in (self._pin_page, self._alias_page, self._card_page):
            w.setVisible(w is page)

    def _pin_toggled(self, skipped: bool) -> None:
        self.pin_edit.setEnabled(not skipped)
        self.pin_confirm.setEnabled(not skipped)

    def _step1_next(self) -> None:
        if self.skip_pin.isChecked():
            self._pin = None
        else:
            pin = self.pin_edit.text().strip()
            if not (pin.isdigit() and 6 <= len(pin) <= 8):
                QMessageBox.warning(self, "PIN", "PIN must be 6–8 digits.")
                return
            if pin != self.pin_confirm.text().strip():
                QMessageBox.warning(self, "PIN", "PINs do not match.")
                return
            self._pin = pin
        self._show_page(self._alias_page)
        self.alias_edit.setFocus()

    def _step2_next(self) -> None:
        alias = self.alias_edit.text().strip()
        if not alias:
            QMessageBox.warning(self, "Alias", "Please choose an alias.")
            return
        from ..core.identity import new_identity

        self._identity = new_identity(alias)
        card = IdentityCardWidget(self._identity)
        self._card_holder.addWidget(card)
        self._show_page(self._card_page)

    # -- results -----------------------------------------------------------

    def pin(self) -> str | None:
        return getattr(self, "_pin", None)

    def identity(self) -> Identity | None:
        return self._identity


def _hrow(*widgets: QWidget) -> "QHBoxLayout":
    from PySide6.QtWidgets import QHBoxLayout

    row = QHBoxLayout()
    row.addStretch(1)
    for w in widgets:
        row.addWidget(w)
    return row
