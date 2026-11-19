# Contributing to Handshake

Thanks for your interest in helping build Handshake! This is a peer-to-peer,
serverless, encrypted chat app. We welcome contributions of any size — bug
reports, documentation fixes, new features, and test coverage all help.

## Ground rules

- **Read the code first.** The architecture is documented in `docs/`
  (protocol, security model, setup). Understanding *why* something is built a
  certain way will save you time.
- **No home-rolled crypto.** All cryptography uses the `cryptography` library
  (X25519, Ed25519, ChaCha20-Poly1305, AES-256-GCM, argon2id). If a change
  touches crypto, it must use well-vetted primitives and be reviewed carefully.
  See `docs/SECURITY.md`.
- **Keep it serverless.** The whole point is no central server, no cloud, no
  accounts, no telemetry. Don't add dependencies on external services.
- **Tests are required.** The suite must stay green. Add tests for new
  behavior and for any bug you fix.

## Setting up your environment

You need **Python 3.13**.

```bash
# 1. Clone the repo
git clone https://github.com/Santar120/handshake.git
cd handshake

# 2. Create a virtual environment
python3.13 -m venv .venv

# 3. Install the app and dev dependencies
.venv/bin/pip install -e ".[dev]"

# 4. Run the test suite
.venv/bin/pytest

# 5. Run the app
.venv/bin/python -m app.main
```

> **macOS note:** if `python3.13` isn't on your PATH, install it with
> `brew install python@3.13` and use `/opt/homebrew/bin/python3.13`.

## Project layout

```
app/
  core/       # identity, crypto, vault, archive, AppCore (Qt bridge)
  protocol/   # handshake, encrypted channel, frames, messages, states
  net/        # asyncio listener + dialer
  ui/         # PySide6 widgets (onboarding, chat, identity card, settings)
  main.py     # entry point
tests/        # pytest suite (unit + loopback integration)
docs/         # PROTOCOL.md, SECURITY.md, SETUP.md
packaging/    # PyInstaller specs + build scripts (mac/win/linux)
```

## Making a change

1. **Fork** the repo and create a branch from `main`:
   ```bash
   git checkout -b my-feature
   ```
2. Make your changes. Keep commits focused and write clear commit messages.
3. **Run the full test suite** and make sure it passes:
   ```bash
   .venv/bin/pytest
   ```
4. Push your branch and open a **pull request** against `main`.
   - Describe *what* you changed and *why*.
   - Link any issue it fixes.
   - For crypto or protocol changes, explain the reasoning in detail.

## Reporting bugs

Open an issue with:
- What you expected to happen vs. what actually happened.
- Your OS and Python version.
- Steps to reproduce (the more specific, the better).
- Any error messages or logs.

## Good first issues

Look for issues labeled `good first issue` or `help wanted`. If you're not
sure where to start, improving documentation or adding test coverage for
under-tested modules are great ways to get familiar with the codebase.

## License

By contributing, you agree that your contributions will be licensed under the
[GNU General Public License v3.0](LICENSE).
