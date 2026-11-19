"""Identity Card widget: alias, keys, fingerprint, QR, copy button."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core.identity import Identity
from .theme import fingerprint_label, mono_label


class IdentityCardWidget(QFrame):
    """Displays an Identity Card with QR code and copy button."""

    def __init__(
        self,
        identity: Identity,
        parent: QWidget | None = None,
        port: int | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self._identity = identity
        self._port = port

        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(10)

        row = QHBoxLayout()
        title = QLabel(f"Identity — {identity.alias}")
        title.setObjectName("h2")
        row.addWidget(title)
        row.addStretch(1)
        outer.addLayout(row)

        body = QHBoxLayout()
        body.setSpacing(16)

        # Left: text fields
        left = QVBoxLayout()
        left.setSpacing(6)
        left.addWidget(self._field("Alias", identity.alias))
        left.addWidget(self._field("X25519", self._b64(identity.x25519_pub)))
        left.addWidget(self._field("Ed25519", self._b64(identity.ed25519_pub)))
        if self._port is not None:
            left.addWidget(self._field("Port", str(self._port)))
        fp = fingerprint_label(identity.fingerprint_display)
        left.addWidget(QLabel("Fingerprint"))
        left.addWidget(fp)
        body.addLayout(left, 1)

        # Right: QR
        qr = QLabel()
        qr.setPixmap(self._qr_pixmap())
        qr.setFixedSize(180, 180)
        qr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.addWidget(qr)

        outer.addLayout(body)

        # Copy + Export buttons
        btn_row = QHBoxLayout()
        copy = QPushButton("Copy Identity Card")
        copy.setObjectName("primary")
        copy.clicked.connect(self._copy)
        export = QPushButton("Export JSON")
        export.setToolTip("Save the public identity card as a JSON file")
        export.clicked.connect(self._export_json)
        btn_row.addWidget(copy)
        btn_row.addWidget(export)
        outer.addLayout(btn_row)

    def _field(self, name: str, value: str) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(1)
        label = QLabel(name)
        label.setObjectName("muted")
        mono = mono_label(value)
        mono.setWordWrap(True)
        v.addWidget(label)
        v.addWidget(mono)
        return w

    @staticmethod
    def _b64(data: bytes) -> str:
        import base64

        return base64.b64encode(data).decode("ascii")

    def _qr_pixmap(self) -> QPixmap:
        img = QImage()
        img.loadFromData(self._identity.to_qr_png(port=self._port))
        return QPixmap.fromImage(img).scaled(
            180, 180, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )

    def _copy(self) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._identity.to_card(port=self._port))

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Identity Card",
            f"{self._identity.alias}.json",
            "JSON (*.json)",
        )
        if not path:
            return
        Path(path).write_text(
            self._identity.to_card_json(port=self._port), encoding="utf-8"
        )
