"""Key rotation dialog: explains the flow, shows the new Identity Card."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
)

from ..core.identity import Identity
from .identity_card_widget import IdentityCardWidget


class RotateKeysDialog(QDialog):
    """Two steps: confirm rotation, then show the new Identity Card."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Rotate my keys")
        self.resize(640, 560)
        self._new_identity: Identity | None = None

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel("Rotate my keys")
        title.setObjectName("h1")
        layout.addWidget(title)

        desc = QLabel(
            "This generates a brand-new identity (new keys, new "
            "fingerprint) and wipes the old private key.\n\n"
            "⚠ After rotating, every peer must add your NEW Identity Card "
            "before they can connect to you again. You'll be able to copy "
            "the new card right after confirming."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

        self._card_holder = QVBoxLayout()
        layout.addLayout(self._card_holder)

        buttons = QDialogButtonBox()
        confirm = QPushButton("Rotate now")
        confirm.setObjectName("danger")
        confirm.clicked.connect(self.accept)
        buttons.addButton(confirm, QDialogButtonBox.ButtonRole.DestructiveRole)
        cancel = QPushButton("Cancel")
        buttons.addButton(cancel, QDialogButtonBox.ButtonRole.RejectRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class RotateResultDialog(QDialog):
    """Shown after rotation: displays the new Identity Card."""

    def __init__(self, identity: Identity, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Identity Card")
        self.resize(640, 560)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        title = QLabel("Your new Identity Card")
        title.setObjectName("h1")
        layout.addWidget(title)
        desc = QLabel(
            "Send this to your peers — they must add it to replace your "
            "old identity."
        )
        desc.setObjectName("muted")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        layout.addWidget(IdentityCardWidget(identity))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
