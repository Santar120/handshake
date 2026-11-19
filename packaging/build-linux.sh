#!/usr/bin/env bash
# Build the Handshake Linux bundle.
#
# Usage:  ./packaging/build-linux.sh
# Output: dist/Handshake/  (runnable folder; dist/Handshake/Handshake is the
#         executable)
#
# Notes:
#   - Build on the target distro (or a matching container) — Qt/PySide6
#     binaries are not portable across distros.
#   - The host needs the usual GUI dev libraries for PySide6 to run at all
#     (libGL, libEGL, xcb plugins). If the bundle fails to start on a minimal
#     system, install the Qt runtime libs there.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -x .venv/bin/python ]; then
    PY=.venv/bin/python
else
    PY=python3
fi

"$PY" -c "import PyInstaller" 2>/dev/null || "$PY" -m pip install pyinstaller

echo "==> Building Handshake (Linux)..."
"$PY" -m PyInstaller --noconfirm --clean packaging/handshake-linux.spec

echo
echo "Done. Runnable folder: dist/Handshake/"
echo "Test it with:  dist/Handshake/Handshake"
