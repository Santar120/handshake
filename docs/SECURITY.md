# Handshake — Security Model

## Threat model

Handshake protects against:

- **Passive network eavesdroppers** — all frames after the handshake are
  AEAD-encrypted (ChaCha20-Poly1305); handshake frames carry only public
  keys and signatures.
- **Active attackers on the path** — identity is proven by Ed25519
  signatures over the HELLO; session keys come from **ephemeral** X25519
  keys, so a MITM cannot inject itself without holding a peer's private
  key.
- **Forward secrecy** — session keys are derived from per-connection
  ephemeral keys and discarded on close. Compromising a long-term key does
  **not** expose past sessions.
- **Local disk theft** — the vault (private keys, peer list, shared
  secrets, chat archive) is AES-256-GCM encrypted with a key derived from
  the PIN via argon2id + HKDF. If the user skips the PIN, the vault is
  stored unencrypted and the app warns plainly.

Handshake does **not** protect against:

- A fully compromised machine (malware with access to the unlocked app).
- Social engineering — the user must verify the peer's fingerprint or
  shared secret out-of-band. The app makes both easy to compare.

## Key hierarchy

```
PIN (6–8 digits, optional)
  └─ argon2id (m=64 MiB, t=3, p=4) → 32-byte vault key material
       └─ HKDF-SHA256(info="handshake-vault-v1") → vault_key (32)
            ├─ AES-256-GCM: identity private keys
            ├─ AES-256-GCM: peer list (incl. shared secrets)
            └─ AES-256-GCM: chat archive files

Per-connection:
  ephemeral X25519 pair (both sides)
    └─ ECDH → HKDF-SHA256(info="handshake-v1" || fp_min || fp_max || psk?)
         → session_key (32)
              ├─ HKDF → prefix_a (8), prefix_b (8)   # one per direction
              └─ ChaCha20-Poly1305, nonce = prefix(8) || counter4
```

## Shared secret (PSK)

- Optional per peer, recommended.
- Mixed into the session-key HKDF `info` when both sides have it enabled.
- A flag mismatch (one side has a PSK, the other doesn't) is rejected
  during the handshake with a clear reason.
- A wrong PSK surfaces as a `keycheck` mismatch → "shared secret mismatch".

## Fingerprint

First 160 bits of `SHA-256(x25519_pub || ed25519_pub)`, 8 groups of 4
uppercase base32 chars. 160 bits is the same size Tor uses for host keys —
ample for human verification.

## Key rotation

- "Rotate my keys" generates fresh X25519 + Ed25519 keypairs, re-encrypts
  the vault, and issues a new Identity Card.
- Peers must update the stored identity before connecting again.
- Old private keys are wiped (overwritten) from the vault.

## What is NOT done (deliberately)

- No TLS, no certificates, no CA/PKI — identity is the keypair itself.
- No trust-on-first-use: a peer is trusted only after its card is entered
  manually.
- No telemetry, no crash reporting, no outbound calls except to
  user-configured peers/relays.
