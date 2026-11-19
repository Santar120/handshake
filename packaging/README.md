# Packaging

Handshake is packaged with **PyInstaller** — one spec per OS, one build
script per OS. Everything is driven from the project root.

## Layout

```
packaging/
  base.py              # shared settings (entry point, PySide6 collection)
  handshake-mac.spec   # macOS  -> dist/Handshake.app
  handshake-win.spec   # Windows -> dist/Handshake/Handshake.exe
  handshake-linux.spec # Linux  -> dist/Handshake/  (runnable folder)
  build-mac.sh
  build-win.sh
  build-linux.sh
```

## Building

Build **on the target OS** (PyInstaller does not cross-compile).

| OS      | Command                     | Output                          |
|---------|-----------------------------|---------------------------------|
| macOS   | `./packaging/build-mac.sh`  | `dist/Handshake.app`            |
| Windows | `packaging/build-win.sh`    | `dist/Handshake/Handshake.exe`  |
| Linux   | `./packaging/build-linux.sh`| `dist/Handshake/` (folder)      |

Each script uses the project `.venv` if present, installs PyInstaller if
missing, and cleans previous build artifacts.

## Why `collect_all("PySide6")`

PySide6 ships Qt plugins (platform plugins, styles, image formats) and
resources that PyInstaller's default hooks do not always collect.
`collect_all` grabs the whole package so the GUI reliably finds its platform
plugin (`libqmetal.so` / `qwindows.dll` / `libqxcb.so`).

## macOS signing & notarization (for distribution)

The build script produces an **unsigned** app. For personal use on your own
machine that's fine (right-click → Open the first time). To distribute:

```bash
codesign --deep --force --sign "Developer ID Application: <You>" dist/Handshake.app
xcrun notarytool submit dist/Handshake.app --wait
```

## Windows

The folder layout (`dist/Handshake/`) is the recommended default — fast
startup, easy to zip and share. For a single `.exe`, add `--onefile` to the
PyInstaller invocation in `build-win.sh` (expect a slower start and a larger
file).

## Linux

The bundle is a folder; `dist/Handshake/Handshake` is the executable. The
target machine needs the Qt runtime libraries (libGL, libEGL, xcb). For
distribution, consider wrapping the folder in an AppImage or .deb.

## Troubleshooting

- **App starts, then crashes with "could not load or find the Qt platform
  plugin"** → the PySide6 collection didn't run; make sure you're building
  with the spec files (not a bare `pyinstaller app/main.py`).
- **Missing `qrcode`/`Pillow` data files** → they are pure-Python and are
  picked up automatically; if you add data files later, add them to `datas`
  in `base.py`.
- **Stale build** → the scripts pass `--clean --noconfirm`; if you still see
  odd behavior, delete `build/` and `dist/` manually.
