"""Tests for screen-lock detection and the ScreenLockWatcher transition logic."""

from __future__ import annotations

import pytest

from app.ui.screen_lock import ScreenLockWatcher, screen_is_locked
from conftest import spin_until


def test_screen_is_locked_returns_bool(qapp):
    assert isinstance(screen_is_locked(), bool)


def test_watcher_emits_on_unlocked_to_locked(qapp):
    state = {"locked": False, "polls": 0}

    def checker():
        state["polls"] += 1
        return state["locked"]

    watcher = ScreenLockWatcher(qapp, poll_interval_ms=10, checker=checker)
    events = []
    watcher.locked.connect(lambda: events.append(1))

    # Still unlocked: no event.
    qapp.processEvents()
    assert events == []

    # Screen locks: exactly one event.
    state["locked"] = True
    assert spin_until(qapp, lambda: len(events) == 1, timeout=2.0)
    qapp.processEvents()
    assert events == [1]

    # Unlocks, then locks again: a second event.
    state["locked"] = False
    polls_at_unlock = state["polls"]
    # Wait until a poll observes the unlocked state (resets the watcher).
    assert spin_until(qapp, lambda: state["polls"] > polls_at_unlock, timeout=2.0)
    state["locked"] = True
    assert spin_until(qapp, lambda: len(events) == 2, timeout=2.0)
    assert events == [1, 1]

    watcher._timer.stop()


def test_watcher_starts_locked_emits_nothing(qapp):
    # If the screen is already locked when the watcher starts, it must not
    # fire (the app is already behind a lock screen at that point).
    state = {"polls": 0}

    def checker():
        state["polls"] += 1
        return True

    watcher = ScreenLockWatcher(qapp, poll_interval_ms=10, checker=checker)
    events = []
    watcher.locked.connect(lambda: events.append(1))
    # Let a few polls run, then assert nothing fired.
    assert spin_until(qapp, lambda: state["polls"] >= 3, timeout=2.0)
    assert events == []
    watcher._timer.stop()
