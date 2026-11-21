# Handshake Protocol — v1

This document is the normative wire format. Implementation must match it
exactly. Changes require a version bump and a migration note.

## 1. Transport

- TCP. Every install listens on a configurable port (default `41337`).
- All data on the wire is framed:

  ```
  frame = u32be(length) | frame_bytes
  frame_bytes = nonce(12) | ciphertext+tag(variable)
  ```

  `length` is the byte length of `frame_bytes` (NOT including the 4 length
  bytes). Maximum frame size: **16 MiB**; larger frames → close connection.

- Before the session key exists, handshake messages are sent **unencrypted**
  as:

  ```
  hello_frame = u32be(length) | b"HSK1" | json_bytes
  ```

  (magic `HSK1` distinguishes handshake frames from encrypted frames).

## 2. Encoding conventions

- Public keys: raw 32 bytes, base64 (standard, with padding) in text forms.
- Fingerprints: see §3.
- JSON: UTF-8, no requirement on key order (canonical serialization is used
  only for signatures, §5).
- All integers on the wire: big-endian.

## 3. Identity

Each install holds:

- an **X25519** keypair (long-term; identity continuity),
- an **Ed25519** keypair (long-term; signing / key-ownership proof).

**Fingerprint** = first 160 bits (20 bytes) of
`SHA-256(x25519_pub || ed25519_pub)`, rendered as **8 groups of 4 uppercase
RFC 4648 base32 characters** (no padding), space-separated:

```
ABCD EFGH IJKL MNOP QRST UVWX YZAB CDEF
```

### Identity Card (text form, paste-able and QR-encodable)

```
HANDSHAKE-IDENTITY v1
alias: Alice
x25519: <base64 32 bytes>
ed25519: <base64 32 bytes>
fingerprint: ABCD EFGH IJKL MNOP QRST UVWX YZAB CDEF
```

Parsing is line-based and tolerant of surrounding whitespace. The
fingerprint line is **verified** against the two public keys on import;
mismatch → reject the card.

## 4. Handshake

Symmetric: works whether A dials B or B dials A. **Ephemeral** X25519 keys
provide forward secrecy; long-term keys are never used for key exchange.

1. Each side generates a fresh **ephemeral X25519 keypair** for this
   connection only.
2. **Dialer → Listener: `HELLO`** (unencrypted, §1 hello_frame):

   ```json
   {
     "v": 1,
     "alias": "Alice",
     "x25519": "<b64>",
     "ed25519": "<b64>",
     "fingerprint": "ABCD ...",
     "eph_pub": "<b64 32 bytes>",
     "psk_flag": true,
     "sig": "<b64 Ed25519 signature>"
   }
   ```

   `sig` = Ed25519 signature (with the dialer's long-term Ed25519 key) over
   the canonical serialization (§5).
3. **Listener** verifies, in order:
   1. `v == 1`.
   2. `x25519` + `ed25519` match a **configured peer** (public-key
      equality). Mismatch → send `HELLO_REJECT(reason="unknown-peer")`,
      close.
   3. Fingerprint matches the derived value for those keys.
   4. `sig` verifies under the peer's Ed25519 public key.
   5. `psk_flag` equals the listener's own PSK flag for this peer.
      Mismatch → `HELLO_REJECT(reason="psk-mismatch")`, close.
4. **Listener → Dialer: `HELLO_ACK`** (unencrypted):

   ```json
   {
     "v": 1,
     "alias": "Bob",
     "x25519": "<b64>",
     "ed25519": "<b64>",
     "fingerprint": "WXYZ ...",
     "eph_pub": "<b64 32 bytes>",
     "psk_flag": true,
     "sig": "<b64>"
   }
   ```

   The dialer performs the same verifications (its peer entry must match).
5. **Session key derivation** (both sides, independently):

   ```
   eph_shared = X25519(local_ephemeral_priv, peer_ephemeral_pub)
   (fp_a, fp_b) = sorted([fp_local, fp_peer])        # canonical order
   session_key = HKDF-SHA256(
       ikm  = eph_shared,
       salt = b"",
       info = b"handshake-v1"
              || fp_a(20) || fp_b(20)                 # raw fingerprint bytes
              || (psk_bytes if psk_flag else b""),
       length = 32
   )
   ```

   `psk_bytes` is the UTF-8 encoding of the shared secret. The two
   fingerprints are sorted (byte-wise) so both sides derive the same key
   regardless of which is local.

   Two direction-specific 8-byte nonce prefixes are also derived from the
   session key:

   ```
   prefix_a = HKDF-SHA256(session_key, info = b"handshake-v1-nonce-a", length = 8)
   prefix_b = HKDF-SHA256(session_key, info = b"handshake-v1-nonce-b", length = 8)
   ```

   The side whose fingerprint sorts **first** sends with `prefix_a` and
   receives with `prefix_b`; the other side does the reverse. Distinct
   prefixes per direction guarantee the two directions never share a nonce.
6. **Key confirmation.** Each side computes
   `key_check = SHA-256(session_key)[:16]`. The **first encrypted frame**
   each side sends is a `keycheck` control message carrying its
   `key_check`. A side that receives a mismatched `key_check` closes with
   reason `shared-secret-mismatch`. (This is how a wrong PSK surfaces as a
   clear error instead of a silent auth failure.)
7. From then on, all frames are encrypted (§6). Ephemeral keys are
   discarded immediately after derivation.

### Rejection

`HELLO_REJECT` (unencrypted): `{ "v": 1, "reason": "unknown-peer" |
"psk-mismatch" | "bad-signature" | "bad-fingerprint" | "unsupported-version" }`
The sender closes the connection right after sending it.

## 5. Canonical serialization (for signatures)

```
HELLO:     b"HELLO-v1"     || u8(v) || u16be(len(alias)) || alias
           || x25519_pub(32) || ed25519_pub(32) || eph_pub(32) || u8(psk_flag)
HELLO_ACK: b"HELLO_ACK-v1" || ... (same fields)
```

## 6. Encrypted frames

- Cipher: **ChaCha20-Poly1305** (AEAD), 12-byte nonce.
- Nonce layout: `nonce(12) = prefix(8) || counter(4, big-endian)`.
  `prefix` is the direction-specific prefix derived in §4.5 (each side sends
  with its own prefix and receives with the other's); `counter` starts at 0
  and increments by 1 per frame sent. **Never reuse a (prefix, counter)
  pair.** The per-direction prefix plus the monotonic counter guarantees a
  unique nonce for every frame in a session.
- AAD: empty.
- Plaintext: the JSON envelope (§7), UTF-8.

## 7. Message envelope

```json
{
  "id": "dGhpcyBpcyBhIG1lc3NhZ2UgaWQ",
  "type": "text",
  "sender": "ABCD EFGH ...",
  "group": null,
  "seq": 1,
  "ts": 1700000000.123,
  "payload": { "text": "hello" }
}
```

- `id`: globally unique message id — 128 random bits, base64url
  (22 chars). Generated by the sender; used for deduplication in the
  local archive and (later) for cross-device sync.
- `type`: `text` | `typing` | `control` | `media` (Phase 2+).
- `sender`: sender's fingerprint (display form).
- `group`: group name, or null for 1:1.
- `seq`: per-sender, per-connection monotonic counter (starts at 1).
- `ts`: Unix seconds (float).
- `payload`: type-specific object.

### Control messages (`type: "control"`)

`payload = { "subtype": ..., ... }`:

| subtype    | extra fields            | meaning |
|------------|-------------------------|---------|
| `keycheck` | `key_check` (b64 16)    | first encrypted frame, §4.6 |
| `ping`     | —                       | heartbeat, every 10 s |
| `pong`     | —                       | reply to ping |
| `connect`  | `alias`                 | "I'm connected" notice |
| `disconnect` | —                     | clean close notice |
| `rotate`   | `new_card` (text)       | key-rotation notice |

## 8. Heartbeats & drop detection

- Each side sends `ping` every **10 s** while connected.
- Receiving a `ping` → reply `pong` immediately.
- If **no frame at all** is received for **30 s** → connection lost;
  transition to `DISCONNECTED`, notify UI.

## 9. Connection state machine

```
DISCONNECTED → CONNECTING → HANDSHAKE → CONNECTED → CLOSING → DISCONNECTED
```

- `CONNECTING`: TCP dial in progress (or listener accepted, awaiting HELLO).
- `HANDSHAKE`: HELLO/HELLO_ACK exchange + key confirmation.
- `CONNECTED`: data channel up.
- `CLOSING`: either side initiated close; `disconnect` control sent best-effort.
- Any state → `DISCONNECTED` on error/timeout.

## 10. Versioning

- Protocol version `1` is carried in HELLO/HELLO_ACK (`v`).
- A side receiving an unsupported `v` sends
  `HELLO_REJECT(reason="unsupported-version")` and closes.

## 11. Local archive (SQLite)

Each device stores its own copy of every conversation in
`archive/archive.db` (SQLite). One row per message:

| column  | type   | meaning                                        |
|---------|--------|------------------------------------------------|
| `id`    | TEXT   | message id (§7) — primary key, dedup on insert |
| `peer`  | TEXT   | peer fingerprint (display form)                |
| `ts`    | REAL   | Unix seconds (float)                           |
| `data`  | BLOB   | envelope JSON, AES-256-GCM with the vault key  |

- `data` is encrypted per message with the vault key (same key that
  protects the vault file); without a PIN it is stored as plaintext
  JSON. The fingerprint and timestamp are kept as plain columns for
  querying — they are not secret.
- Insert is `INSERT OR IGNORE`: a message id seen twice (e.g. a
  re-delivery or a sync from a second device) is dropped, so the
  archive is append-only and idempotent.
- Legacy per-peer JSON files (`archive/<fingerprint>.json`) are
  imported automatically on first open and then removed.
