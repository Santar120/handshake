#!/usr/bin/env bash
# Build Handshake.exe for Windows (run on Windows, or via Git Bash / WSL).
#
# Usage:  packaging/build-win.sh
# Output: dist/Handshake/Handshake.exe  (portable folder)
#
# Notes:
#   - PyInstaller is not cross-platform: build on Windows to get a Windows
#     binary. This script is written for bash (Git Bash works out of the box).
#   - For a single-file .exe, add --onefile to the PyInstaller call (slower
#     startup, larger file). The folder layout is the recommended default.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -x .venv/Scripts/python.exe ]; then
    PY=.venv/Scripts/python.exe
elif [ -x .venv/bin/python ]; then
    PY=.venv/bin/python
else
    PY=python
fi

"$PY" -c "import PyInstaller" 2>/dev/null || "$PY" -m pip install pyinstaller

echo "==> Building Handshake.exe (Windows)..."
"$PY" -m PyInstaller --noconfirm --clean packaging/handshake-win.spec

echo
echo "Done. Portable app: dist/Handshake/Handshake.exe"
