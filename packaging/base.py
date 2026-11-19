"""Shared PyInstaller build settings for Handshake.

Imported by the per-OS spec files (handshake-mac.spec, handshake-win.spec,
handshake-linux.spec). Keep platform-specific bits in those files; anything
common lives here.
"""

import os

# This file lives in <root>/packaging/, so the project root is one level up.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP_NAME = "Handshake"
ENTRY = os.path.join(ROOT, "app", "main.py")

# PySide6 ships Qt plugins and resources that PyInstaller's default hooks do
# not always pick up. Collecting the whole package is the reliable way to get
# a working GUI bundle.
COLLECT = ["PySide6"]

# Common analysis kwargs shared by every platform spec.
COMMON = dict(
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc", "pytest"],
    noarchive=False,
)
