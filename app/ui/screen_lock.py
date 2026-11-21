"""Detect when the OS screen locks so the app can re-lock itself.

On macOS we read ``CGSSessionScreenIsLocked`` from the current session
dictionary via CoreGraphics. This uses only the standard library (``ctypes``)
plus system frameworks that are always present, so no third-party dependency
is required. On other platforms the screen is reported as never locked.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import QObject, QTimer, Signal

# kCFStringEncodingUTF8
_CF_UTF8 = 0x08000100


def screen_is_locked() -> bool:
    """Return ``True`` if the OS screen is currently locked.

    Always returns ``False`` on non-macOS platforms, and ``False`` if the
    value cannot be read (so a detection failure never locks the user out).
    """
    if sys.platform != "darwin":
        return False
    try:
        import ctypes
        from ctypes import c_bool, c_char_p, c_int, c_void_p

        cf = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        cg = ctypes.CDLL(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
        )
        cf.CFStringCreateWithCString.restype = c_void_p
        cf.CFStringCreateWithCString.argtypes = [c_void_p, c_char_p, c_int]
        cf.CFDictionaryGetValue.restype = c_void_p
        cf.CFDictionaryGetValue.argtypes = [c_void_p, c_void_p]
        cf.CFBooleanGetValue.restype = c_bool
        cf.CFBooleanGetValue.argtypes = [c_void_p]
        cf.CFRelease.argtypes = [c_void_p]
        cg.CGSessionCopyCurrentDictionary.restype = c_void_p

        d = cg.CGSessionCopyCurrentDictionary()
        if not d:
            return False
        try:
            key = cf.CFStringCreateWithCString(
                None, b"CGSSessionScreenIsLocked", _CF_UTF8
            )
            val = cf.CFDictionaryGetValue(d, key)
            return bool(cf.CFBooleanGetValue(val)) if val else False
        finally:
            cf.CFRelease(key)
            cf.CFRelease(d)
    except Exception:
        return False


class ScreenLockWatcher(QObject):
    """Emits ``locked`` when the screen transitions from unlocked to locked.

    Polls ``screen_is_locked`` on a timer. The checker is injectable so the
    transition logic can be unit-tested without a real screen lock.
    """

    locked = Signal()

    def __init__(
        self,
        parent: QObject | None = None,
        poll_interval_ms: int = 3000,
        checker=None,
    ) -> None:
        super().__init__(parent)
        self._checker = checker or screen_is_locked
        self._was_locked = self._checker()
        self._timer = QTimer(self)
        self._timer.setInterval(poll_interval_ms)
        self._timer.timeout.connect(self._poll)
        self._timer.start()

    def _poll(self) -> None:
        locked = self._checker()
        if locked and not self._was_locked:
            self._was_locked = True
            self.locked.emit()
        elif not locked:
            self._was_locked = False
