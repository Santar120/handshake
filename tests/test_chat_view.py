"""Tests for ChatView: date dividers and bubble context menu wiring."""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel

from app.core.appcore import AppCore
from app.core.identity import new_identity
from app.core.vault import Vault
from app.protocol.messages import Envelope
from app.ui.main_window import ChatView

PEER_FP = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH"


def _core(tmp_path: Path) -> AppCore:
    core = AppCore()
    core.vault = Vault.create(tmp_path / "vault.json", new_identity("Alice"), None)
    core.dialer = None
    core.listener = None
    return core


def _view(qapp, tmp_path: Path) -> ChatView:
    cv = ChatView(_core(tmp_path))
    cv.show()
    qapp.processEvents()
    return cv


def _dividers(cv: ChatView) -> list[str]:
    return [
        lbl.text()
        for lbl in cv.findChildren(QLabel)
        if lbl.objectName() == "date_divider"
    ]


def _text_env(sender: str, seq: int, text: str, ts: float | None = None) -> Envelope:
    env = Envelope.text(sender, seq, text)
    if ts is not None:
        env.ts = ts
    return env


def test_date_divider_between_days(qapp, tmp_path: Path):
    cv = _view(qapp, tmp_path)
    my_fp = cv._core.identity.fingerprint_display

    cv._add_bubble(_text_env(PEER_FP, 1, "old", ts=time.time() - 86400))
    cv._add_bubble(_text_env(my_fp, 2, "newer"))
    qapp.processEvents()

    # One divider per day boundary: yesterday's message, then today's.
    assert _dividers(cv) == ["Yesterday", "Today"]


def test_no_divider_within_same_day(qapp, tmp_path: Path):
    cv = _view(qapp, tmp_path)
    my_fp = cv._core.identity.fingerprint_display

    cv._add_bubble(_text_env(PEER_FP, 1, "one"))
    cv._add_bubble(_text_env(my_fp, 2, "two"))
    cv._add_bubble(_text_env(PEER_FP, 3, "three"))
    qapp.processEvents()

    assert _dividers(cv) == ["Today"]


def test_bubble_has_context_menu(qapp, tmp_path: Path):
    cv = _view(qapp, tmp_path)
    my_fp = cv._core.identity.fingerprint_display

    cv._add_bubble(_text_env(my_fp, 1, "right click me"))
    qapp.processEvents()

    bubbles = cv.findChildren(QFrame, "bubble_mine")
    assert len(bubbles) == 1
    assert (
        bubbles[0].contextMenuPolicy()
        == Qt.ContextMenuPolicy.CustomContextMenu
    )
