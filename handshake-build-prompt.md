# HANDSHAKE — Project Build Prompt

> **How to use:** Create a fresh repo, open it in VS Code (or Cursor), and paste this
> entire document as the first message to your coding agent. Then tell it:
> "Start with Section 11, and do not begin the next phase until I say so."

---

## 1. Mission

Build **Handshake** — a cross-platform, GUI-only, peer-to-peer encrypted chat
application for **macOS, Linux, and Windows** from a **single codebase**.
There is **no central server**, no cloud, no accounts, no discovery service.
Two (or more) users each run the app, manually exchange their public identity
keys out-of-band, add each other's configuration, and then talk over a direct,
fully encrypted channel. Later phases add voice, video, and screen
share / remote desktop.

## 2. Hard constraints (do not violate)

- One codebase → 3 native desktop apps (macOS, Windows, Linux). No web client,
  no webview, no mobile.
- **GUI only.** No CLI usage for end users (build/packaging scripts are fine).
- **No central server of any kind.** No cloud, no accounts, no DNS-based
  discovery. The only network is the internet / local LAN.
- **No telemetry, analytics, crash reporting, or any outbound network call
  except to user-configured peer or relay addresses.**
- Identity is keypair-based: each install generates its own private key
  (which never leaves the machine) and a public key shared out-of-band
  (paste or QR code).
- The other party's information is entered **manually**: alias, public
  identity, address (host:port). No auto-discovery, ever.
- Either peer can initiate **or** receive; the app automatically does both
  (it listens AND dials).
- Either peer can disconnect at any time, breaking the connection cleanly.
- **Key rotation**: a peer can rotate its keypair; the other side must then
  add the new public identity to re-establish the connection (or start a new
  setup).
- A **PIN** protects the local app/vault.
- Chat history is **session-scoped**: kept in memory for the session and
  optionally written to a local encrypted archive so either side can pull it
  back after a restart. It is never stored on any server (there is no server).

## 3. Stack (locked — do not deviate without explicit approval)

- Python 3.11+
- UI: **PySide6** (Qt 6), single-window app
- Crypto: the `cryptography` library **only** — X25519 (ECDH), Ed25519
  (signing/fingerprints), HKDF-SHA256 (session key derivation),
  XChaCha20-Poly1305 (AEAD for every frame). **No home-rolled crypto.**
  No TLS stack — we implement the small handshake defined in Section 4.
- Local storage: JSON/SQLite plus AES-GCM file encryption for the optional
  chat archive; **argon2id** hash for the PIN (`argon2-cffi`)
- QR codes: `qrcode` + `Pillow`
- Packaging: **PyInstaller** with one spec per OS + a build script per OS
- Media (Phase 2+): WebRTC via `pywebRTC`, riding alongside the encrypted
  data channel — not before Phase 2
- Tests: `pytest`; unit tests for crypto and protocol, integration test for
  loopback peer-to-peer connections

## 4. Identity & security model

### Onboarding (first launch)
1. User sets a PIN (4–8 digits).
2. App generates an **X25519** keypair and an **Ed25519** keypair.
3. Fingerprint = SHA-256 of both public keys, displayed as 8 groups of 4
   base32 characters.
4. App displays the **Identity Card**: app version, user-chosen alias,
   both public keys (base64), fingerprint. Must be copyable as text and
   renderable as a QR code.
5. Private keys are encrypted at rest in a local **vault** (AES-256-GCM;
   vault key derived from the PIN via argon2id + HKDF). Vault lives in the
   platform app-data directory.

### Trust model
You trust exactly the peers whose public identities you typed in
out-of-band. No CA, no PKI, no trust-on-first-use magic.

### Handshake (symmetric — works whether A dials B or B dials A)
1. Dialer sends its Identity Card.
2. Listener verifies the card matches a configured peer (public key
   equality). Mismatch → reject and close.
3. Both sides compute ECDH both directions
   (ECDH(local_priv, peer_pub) + ECDH(peer_priv, local_pub)) and run HKDF
   over the concatenation to derive the session key.
4. Each side proves key ownership by signing a HELLO with its Ed25519 key;
   verify before proceeding.
5. All subsequent frames: `[nonce | ciphertext+tag]` via XChaCha20-Poly1305,
   with the nonce built from a per-session random prefix + monotonic counter.
   Finalize exact frame layout in `docs/PROTOCOL.md` before implementing.

### Session lifecycle
- Session keys are re-derived on **every** connection; discarded on close.
- Reconnect = full handshake again. No state is reused across sessions.

### Key rotation
- "Rotate my keys" generates a fresh keypair, issues a new Identity Card,
  and wipes the old private key.
- A peer must update the stored identity with the new public key before it
  can connect again. The rotation dialog must explain this plainly and hand
  the user the new Identity Card immediately.

## 5. Networking model

- Every install **listens** on a configurable TCP port (default `41337`) —
  the receiving side.
- A peer entry is: `{ alias, identity_card, transport: "host:port" }`.
- Connecting to a peer:
  1. Dial their `host:port` directly (they are always listening).
  2. Run the Section 4 handshake. Success → data channel up.
  3. If the dial times out (peer unreachable — both behind NAT, wrong
     address, they're offline), show a clear status: "Peer unreachable —
     keep this app open; they can connect to you at your address." Keep the
     local listener up and retry with backoff.
  4. **Phase 1.5 (best effort):** UDP hole-punch attempt. Optional; must
     never block MVP.
  5. **Phase 1.5 — Relay peer mode (the designed NAT escape hatch):** a
     third install marked as "relay" accepts connections from two of the
     user's configured peers and forwards opaque frames between them. The
     relay **never decrypts** — it only relays bytes end-to-end. Setup is
     still manual: both parties add the relay to their config.
- Connection state machine:
  `DISCONNECTED → CONNECTING → HANDSHAKE → CONNECTED → CLOSING → DISCONNECTED`
- Either side may drop at any time. The other side detects it via encrypted
  10-second heartbeats + 30-second keep-alive timeout and shows
  "Connection lost."
- One install maintains many simultaneous peer connections (this is how
  groups work).

## 6. Messaging

- Envelope (JSON, then AEAD-sealed as a whole frame):
  `{ type, sender_fingerprint, group?, seq, ts, payload }`
- Types: `text` (MVP), `typing` (Phase 1), `media` (Phase 2+),
  `control` (connect / disconnect / rotate notices).
- **Personal message**: sent over the 1:1 channel.
- **Group message**: a group is a named roster of members (each with an
  Identity Card + transport). A group message is **individually encrypted
  per member and sent over each member's own connection** (PGP
  mailing-list style — no server holding groups). Every member stores a
  copy. Each message is Ed25519-signed so members can verify authorship.
- **Storage policy**: in-memory session store always; optional per-peer and
  per-group encrypted archive files (AES-GCM, vault key) that survive
  restarts. This satisfies "the chat can be pulled on either side."

## 7. UI (PySide6, single window, dark theme, monospace for keys)

1. **Lock screen** — PIN entry; shown on launch and after inactivity.
2. **Onboarding** (first launch) — set PIN → choose alias → show Identity
   Card (keys, fingerprint, QR, copy button) → done.
3. **Home / Connections** — configured peers with live status,
   Connect / Disconnect buttons; "Add peer" (paste Identity Card); group
   list; "My Identity Card"; "Rotate my keys."
4. **Chat view** — per-peer or per-group conversation; bubbles with
   timestamp + short sender fingerprint; input box; connection status pill;
   disconnect button.
5. **Key rotation dialog** — explains the flow, issues the new Identity
   Card, marks the old key as retired.
6. **Settings** — listen port, relay peers, archive on/off, lock timeout,
   theme (dark default).

All key material must always be one click away from copy-as-text.

## 8. Phases & definition of done

**Phase 0 — Chat MVP (build this first):**
- Onboarding, PIN, Identity Card, vault
- Add peer by pasting an Identity Card
- Connect / disconnect, full state machine, heartbeats, drop detection
- Encrypted 1:1 text chat, verified by a loopback integration test
- Encrypted session archive (on by default)
- Three PyInstaller specs + build scripts (mac / win / linux)
- ✅ Done when: two machines (same LAN, or one with a reachable address)
  onboard, add each other, connect, chat, disconnect, restart, and reload
  the conversation.

**Phase 1** — Groups, rotation UX polish, typing indicators.
**Phase 1.5** — Relay peer mode, best-effort hole punching.
**Phase 2** — Voice first, then video, over WebRTC on the existing channel.
**Phase 3** — Screen share and remote control with explicit per-session
permission toggles (view-only vs view+control). Remote input must be
deny-by-default and revocable mid-session.

## 9. Repo layout

```
handshake/
  app/
    ui/        # PySide6 windows, dialogs
    core/      # identity, vault, handshake, channel, storage
    protocol/  # frame codec, message types, state machine
    net/       # listener, dialer, relay
    media/     # (Phase 2+)
  tests/
  packaging/   # pyinstaller specs + per-OS build scripts
  docs/        # PROTOCOL.md, SECURITY.md, SETUP.md
  pyproject.toml
  README.md
```

## 10. Conventions

- Full type hints; dataclasses for messages; enums for states.
- No global state. The core is a small event-driven protocol engine; the
  UI subscribes to it via Qt signals. Core must run and be tested without
  the UI.
- Write `docs/PROTOCOL.md` **before** implementing the handshake; unit-test
  the crypto and codec against fixed test vectors.
- Structured logging to file + a debug panel in the UI.
- Every phase ends with a green `pytest` run and a clean app launch.
- Secrets zeroized from memory on exit (best effort).

## 11. Start here (first commit)

Scaffold the repo per Section 9. Implement: vault (PIN → key), identity
generation, fingerprint, Identity Card encoding/decoding — with tests.
Then write `docs/PROTOCOL.md` for the handshake and frame layout.
**Do not build the UI yet.** Stop and report when done.
