"""Dark theme (QSS) and small shared UI helpers."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel

MONO_FAMILY = "Menlo, SF Mono, Consolas, DejaVu Sans Mono, monospace"

DARK_QSS = """
* {
    font-family: -apple-system, "Segoe UI", "Helvetica Neue", sans-serif;
}
QMainWindow, QWidget {
    background-color: #14161a;
    color: #e6e6e6;
    font-size: 14px;
}
QLabel#h1 { font-size: 22px; font-weight: 600; }
QLabel#h2 { font-size: 17px; font-weight: 600; }
QLabel#muted { color: #8a8f98; }
QLabel#mono { font-family: Menlo, "SF Mono", Consolas, "DejaVu Sans Mono", monospace; }
QLabel#fingerprint {
    font-family: Menlo, "SF Mono", Consolas, "DejaVu Sans Mono", monospace;
    font-size: 15px;
    letter-spacing: 1px;
    color: #7fd1ff;
}
QPushButton {
    background-color: #23262d;
    border: 1px solid #33373f;
    border-radius: 6px;
    padding: 7px 14px;
}
QPushButton:hover { background-color: #2b2f37; }
QPushButton:disabled { color: #5a5f68; background-color: #1b1e23; }
QPushButton#primary {
    background-color: #2f6feb;
    border: none;
    color: white;
}
QPushButton#primary:hover { background-color: #3b7cf5; }
QPushButton#danger {
    background-color: #3a2226;
    border: 1px solid #5c2b31;
    color: #ff8f98;
}
QPushButton#danger:hover { background-color: #4a2a30; }
QLineEdit, QSpinBox, QComboBox {
    background-color: #1b1e23;
    border: 1px solid #33373f;
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: #2f6feb;
}
QLineEdit:focus, QSpinBox:focus { border: 1px solid #2f6feb; }
QFrame#card {
    background-color: #1b1e23;
    border: 1px solid #2a2e35;
    border-radius: 10px;
}
QFrame#bubble_mine {
    background-color: #2f6feb;
    border-radius: 10px;
}
QFrame#bubble_theirs {
    background-color: #2c313a;
    border: 1px solid #3a4048;
    border-radius: 10px;
}
QFrame#divider_line { background-color: #2a2e35; max-height: 1px; min-height: 1px; }
QLabel#date_divider { color: #8a8f98; font-size: 11px; padding: 0 8px; }
QFrame#pill {
    background-color: #23262d;
    border-radius: 10px;
    padding: 2px 10px;
}
QFrame#pill_ok { background-color: #1d3327; }
QFrame#pill_bad { background-color: #3a2226; }
QScrollArea { border: none; background: transparent; }
QScrollBar:vertical {
    background: #14161a; width: 10px; margin: 0;
}
QScrollBar::handle:vertical {
    background: #33373f; border-radius: 5px; min-height: 30px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QGroupBox {
    border: 1px solid #2a2e35; border-radius: 8px;
    margin-top: 12px; padding-top: 8px;
    font-weight: 600;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QCheckBox { spacing: 8px; }
QTabWidget::pane { border: 1px solid #2a2e35; border-radius: 8px; }
QTabBar::tab {
    background: #1b1e23; padding: 8px 16px; margin-right: 2px;
    border-top-left-radius: 6px; border-top-right-radius: 6px;
}
QTabBar::tab:selected { background: #2f6feb; color: white; }
QStatusBar { background: #101216; color: #8a8f98; }
QToolTip { background: #1b1e23; color: #e6e6e6; border: 1px solid #33373f; }
"""


def mono_label(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName("mono")
    label.setTextInteractionFlags(
        label.textInteractionFlags() | Qt.TextInteractionFlag.TextSelectableByMouse
    )
    label.setFont(QFont("Menlo", 10))
    return label


def fingerprint_label(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setObjectName("fingerprint")
    label.setTextInteractionFlags(
        label.textInteractionFlags() | Qt.TextInteractionFlag.TextSelectableByMouse
    )
    return label
