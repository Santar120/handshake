"""Lock screen: PIN entry (or skip, for PIN-less vaults)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


class LockDialog(QDialog):
    """Modal PIN entry. Returns the PIN via .result_pin() on accept."""

    def __init__(self, has_pin: bool, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Handshake — Unlock")
        self.setFixedSize(360, 200)
        self._has_pin = has_pin
        self._pin: str | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Handshake")
        title.setObjectName("h1")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        if has_pin:
            sub = QLabel("Enter your PIN to unlock your identity.")
            sub.setObjectName("muted")
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(sub)

            self.pin_edit = QLineEdit()
            self.pin_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.pin_edit.setMaxLength(8)
            self.pin_edit.setPlaceholderText("6–8 digit PIN")
            self.pin_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.pin_edit.setMinimumWidth(160)
            self.pin_edit.returnPressed.connect(self._try_unlock)
            layout.addWidget(self.pin_edit, alignment=Qt.AlignmentFlag.AlignCenter)
            self.pin_edit.setFocus()
        else:
            sub = QLabel("This install has no PIN set.")
            sub.setObjectName("muted")
            sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(sub)

        buttons = QDialogButtonBox()
        if has_pin:
            unlock = QPushButton("Unlock")
            unlock.setObjectName("primary")
            unlock.clicked.connect(self._try_unlock)
            buttons.addButton(unlock, QDialogButtonBox.ButtonRole.AcceptRole)
        else:
            unlock = QPushButton("Continue")
            unlock.setObjectName("primary")
            unlock.clicked.connect(self.accept)
            buttons.addButton(unlock, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _try_unlock(self) -> None:
        pin = self.pin_edit.text().strip()
        if not (pin.isdigit() and 6 <= len(pin) <= 8):
            self.pin_edit.selectAll()
            self.pin_edit.setFocus()
            return
        self._pin = pin
        self.accept()

    def result_pin(self) -> str | None:
        return self._pin
