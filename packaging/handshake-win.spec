# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Windows — produces dist/Handshake/Handshake.exe."""

from PyInstaller.utils.hooks import collect_all

from base import APP_NAME, COLLECT, COMMON, ENTRY  # noqa: E402

datas, binaries, hiddenimports = [], [], []
for pkg in COLLECT:
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    [ENTRY],
    **COMMON,
    datas=datas,
    binaries=binaries,
    hiddenimports=hiddenimports,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=APP_NAME,
    debug=False,
    strip=False,
    upx=False,
    console=False,  # GUI app: no console window
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name=APP_NAME,
)
