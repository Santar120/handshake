# Handshake

Cross-platform, **GUI-only**, peer-to-peer encrypted chat for macOS, Linux,
and Windows from a single codebase.

**No central server. No cloud. No accounts. No discovery service. No
telemetry.**

Two (or more) people each run the app, exchange their public identity keys
out-of-band (paste or QR), add each other, and talk over a direct, fully
encrypted channel.

## How it works (plain terms)

- Every install generates its own **identity**: a pair of cryptographic
  keys. The private key never leaves your machine. The public side becomes
  your **Identity Card** (alias, public keys, fingerprint, QR code).
- You add a person by pasting their Identity Card. Optionally you agree on
  a **shared secret** (a password) that both sides set — an extra lock that
  makes impersonation fail loudly.
- Either side can start the conversation. The app listens *and* dials.
- Everything on the wire is encrypted with the same primitives used by
  Signal and WireGuard (X25519, Ed25519, ChaCha20-Poly1305), with
  **forward secrecy**: each connection uses fresh throwaway keys.
- A **PIN** (optional, recommended) encrypts your identity and chat
  history on disk.
- Chat history is session-scoped and optionally written to a local
  **encrypted archive** so either side can pull it back after a restart.

## Status

**Phase 0 (MVP)** — onboarding, PIN, Identity Card, vault, add peer,
connect/disconnect with full state machine and heartbeats, encrypted 1:1
text chat, encrypted session archive, PyInstaller packaging for all three
OSes.

See `docs/` for the protocol, security model, and setup.

## Development

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/python -m app.main
```

## Roadmap

- **Phase 1** — groups, key-rotation UX polish, typing indicators
- **Phase 1.5** — relay peer mode (NAT escape hatch), best-effort hole punching
- **Phase 2** — voice, then video (WebRTC over the existing channel)
- **Phase 3** — screen share / remote control with per-session permissions
