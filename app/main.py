"""Handshake — application entry point.

    python -m app.main

Boots the Qt event loop, the AppCore (background asyncio loop), and the
main window.
"""

from __future__ import annotations

import logging
import sys


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

    from .core.appcore import AppCore
    from .core.vault import VaultError
    from .ui.lock_screen import LockDialog
    from .ui.main_window import MainWindow
    from .ui.onboarding import OnboardingDialog

    app = QApplication(sys.argv)
    app.setApplicationName("Handshake")
    app.setOrganizationName("Handshake")

    core = AppCore()
    core.start()

    if not core.has_vault():
        # First run: create the identity and (optionally) a PIN.
        onboarding = OnboardingDialog()
        if onboarding.exec() != QDialog.Accepted:
            core.stop()
            return 1
        core.onboard(onboarding.identity().alias, onboarding.pin())
    else:
        # Returning user: unlock the vault.
        lock = LockDialog(has_pin=core.has_pin)
        if lock.exec() != QDialog.Accepted:
            core.stop()
            return 1
        try:
            core.unlock(lock.result_pin())
        except VaultError as exc:
            QMessageBox.critical(None, "Handshake", str(exc))
            core.stop()
            return 1

    window = MainWindow(core)
    window.show()

    code = app.exec()
    core.stop()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
