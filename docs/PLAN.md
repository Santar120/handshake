# Handshake — Roadmap & Back-Burner

Decisions are locked in with the user; items are ordered by priority.
Build incrementally: finish the top item, then move down.

## Phase 1 — SQLite archive (DONE)

- [x] Chat archive moved from per-peer JSON files to `archive/archive.db`
      (SQLite, one row per message, per-message AES-256-GCM with the
      vault key). See PROTOCOL.md §11.
- [x] Every envelope now carries a globally unique message id
      (`id`, 128 random bits, base64url) — the "GRID". Archive inserts
      are idempotent (`INSERT OR IGNORE`), so re-deliveries and future
      syncs can't create duplicates.
- [x] Legacy JSON archives auto-migrate on first open.

## UI polish (in progress)

- [x] Chat bubbles: removed the in-bubble name + time header so
      messages read like a normal chat (iPhone-style). Date dividers
      stay; left/right alignment stays.
- [x] Chat header: shows only the peer's name (fingerprint removed).
- [x] Connect/Disconnect: only the relevant button is shown
      (Connect when disconnected, Disconnect when connected).
- [x] Fingerprint moved to a right-click → "Properties…" popup on a
      peer (also still in a message's Details).
- [x] Sidebar: minimize/expand toggle (collapses to a thin strip).

## Phase 2 — Add a second device (export/import over the encrypted channel)

Goal: user sets up a second personal device (e.g. a second laptop).
It becomes a full mirror of the first — same identity, same chats.

- [ ] Settings → "Add device": enter the new device's fingerprint
      (identifiers), confirm on the existing laptop.
- [ ] Over the existing encrypted channel, transfer the vault
      (shared key approach: device B gets a copy of the private key)
      and the full archive.
- [ ] Device B can then sign in with the same PIN and sees everything.
- [ ] UX: "add device → enter identifiers → confirm on laptop →
      mirror vault + archive".

## Phase 3 — Continuous mirroring

- [ ] After the initial mirror, keep both devices in sync: new
      messages, new peers, settings changes.
- [ ] Sync uses message ids for dedup (already in place) and
      last-write-wins for editable data (aliases, settings).
- [ ] Primary device is the source of truth when both are online.

## Phase 4 — Conflict rules

- [ ] Document and enforce: append-only messages merge cleanly;
      editable fields use last-write-wins; primary device wins ties.

## Back burner (recorded, not scheduled)

### Relay system

- Individuals run their own relays on home networks (or ask a friend).
- A relay only advertises who is available and where to connect —
  it never sees message content.
- Solves the coffee-shop case: on an outgoing-only network the user
  can still reach people, and incoming connections arrive via the
  relay.

### Passive check / passive listen

- Periodically check whether the other party is reachable, and
  listen for them to appear, so connections re-establish
  automatically without manual dialing.

### Per-chat settings

- Each conversation gets its own settings (e.g. notifications,
  archive on/off, per-peer options) in the future.
