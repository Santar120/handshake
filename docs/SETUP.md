# Handshake — Setup

## Development

Requires Python 3.11+.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest            # run the test suite
.venv/bin/python -m app.main   # launch the app
```

## First launch (onboarding)

1. Set a PIN (6–8 digits) — or skip it (the app warns that your identity
   will then be stored unencrypted).
2. Choose an alias.
3. Your **Identity Card** is shown: alias, both public keys, fingerprint,
   QR code. Copy it or show the QR to the other person.

## Adding a peer

1. The other person sends you their Identity Card (paste or QR).
2. In Handshake: **Add peer** → paste the card (or scan).
3. Optionally set a **shared secret** for this peer (recommended). Both
   sides must use the same secret.
4. Enter their address `host:port` (e.g. `192.168.1.20:41337`).
5. **Connect.** Either side can initiate — the app both listens and dials.

## Where things live

| Platform | Config directory |
|----------|------------------|
| Linux    | `~/.config/handshake/` |
| macOS    | `~/Library/Application Support/handshake/` |
| Windows  | `%APPDATA%/handshake/` |

Override with the `HANDSHAKE_HOME` environment variable.

Contents:

- `vault.json` — encrypted (or, if PIN skipped, plain) identity + peers
- `archive/` — per-peer / per-group encrypted chat archives
- `settings.json` — listen port, lock timeout, archive on/off, theme

## Building installers

See `packaging/README.md`. One PyInstaller spec per OS:

```bash
./packaging/build-mac.sh
./packaging/build-win.sh
./packaging/build-linux.sh
```
