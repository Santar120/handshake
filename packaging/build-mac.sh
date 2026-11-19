#!/usr/bin/env bash
# Build Handshake.app for macOS.
#
# Usage:  ./packaging/build-mac.sh
# Output: dist/Handshake.app
#
# Notes:
#   - Run on macOS. The .app is only valid for the architecture you build on
#     (Apple Silicon vs Intel). Build on the target machine for best results.
#   - The app is unsigned. To distribute it, sign + notarize it (see README).
set -euo pipefail

cd "$(dirname "$0")/.."

# Use the project venv if present, otherwise the system python.
if [ -x .venv/bin/python ]; then
    PY=.venv/bin/python
else
    PY=python3
fi

# Make sure PyInstaller is available.
"$PY" -c "import PyInstaller" 2>/dev/null || "$PY" -m pip install pyinstaller

echo "==> Building Handshake.app (macOS)..."
"$PY" -m PyInstaller --noconfirm --clean packaging/handshake-mac.spec

echo
echo "Done. App bundle: dist/Handshake.app"
echo "Test it with:  open dist/Handshake.app"
