"""Encrypted chat archive (SQLite).

Chat history is session-scoped (in memory). Optionally, each 1:1
conversation is also written to a local SQLite database so either side
can pull the conversation back after a restart.

Storage:
    archive/archive.db

Every message row stores the full envelope as JSON, AES-256-GCM
encrypted with the vault key (or plaintext when the user skipped the
PIN — same tradeoff as the vault). The peer fingerprint and timestamp
are plain columns for querying; the fingerprint is a public identifier,
not a secret.

Each message carries a globally unique id (``Envelope.id``). Appending
is a dedup by that id, so the same message is never stored twice — the
foundation for future multi-device sync.

Legacy per-peer JSON archive files (``archive/<fingerprint>.json``) are
migrated into the database automatically on first open, then removed.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from ..protocol.messages import new_message_id
from .crypto import aes_gcm_decrypt, aes_gcm_encrypt, b64_decode
from .paths import archive_dir

DB_FILENAME = "archive.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    peer TEXT NOT NULL,
    ts REAL NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_peer_ts ON messages(peer, ts);
"""


class Archive:
    def __init__(self, key: bytes | None, directory: Path | None = None) -> None:
        self._key = key
        self._dir = directory or archive_dir()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self._dir / DB_FILENAME, check_same_thread=False
        )
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate_legacy_json()

    # -- public API ---------------------------------------------------------

    def load(self, peer_fingerprint_display: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM messages WHERE peer = ? ORDER BY ts, rowid",
                (peer_fingerprint_display,),
            ).fetchall()
        out: list[dict] = []
        for (blob,) in rows:
            doc = self._decrypt(blob)
            if doc is None:
                return []  # wrong key / corrupt — treat as empty (old behavior)
            out.append(doc)
        return out

    def append(self, peer_fingerprint_display: str, envelope: dict) -> None:
        """Store one envelope; a duplicate message id is ignored (dedup)."""
        msg_id = envelope.get("id") or new_message_id()
        ts = float(envelope.get("ts", 0.0))
        blob = self._encrypt(json.dumps(envelope, sort_keys=True).encode("utf-8"))
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO messages (id, peer, ts, data) "
                "VALUES (?, ?, ?, ?)",
                (msg_id, peer_fingerprint_display, ts, blob),
            )
            self._conn.commit()

    def clear(self, peer_fingerprint_display: str) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM messages WHERE peer = ?",
                (peer_fingerprint_display,),
            )
            self._conn.commit()

    def list_files(self) -> dict[str, list[dict]]:
        """All archived conversations: {peer_fingerprint_display: [envelope, ...]}."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT peer, data FROM messages ORDER BY peer, ts, rowid"
            ).fetchall()
        out: dict[str, list[dict]] = {}
        for peer, blob in rows:
            doc = self._decrypt(blob)
            if doc is None:
                continue
            out.setdefault(peer, []).append(doc)
        return out

    def import_messages(
        self, peer_fingerprint_display: str, messages: list[dict]
    ) -> None:
        """Bulk-import envelopes for a peer (used by bundle import)."""
        for msg in messages:
            self.append(peer_fingerprint_display, msg)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- internals ------------------------------------------------------------

    def _encrypt(self, plaintext: bytes) -> bytes:
        if self._key is not None:
            return aes_gcm_encrypt(self._key, plaintext)
        return plaintext

    def _decrypt(self, blob: bytes) -> dict | None:
        try:
            raw = (
                aes_gcm_decrypt(self._key, blob)
                if self._key is not None
                else blob
            )
            return json.loads(raw)
        except Exception:
            return None

    def _migrate_legacy_json(self) -> None:
        """Import legacy per-peer JSON archive files, then remove them."""
        for path in sorted(self._dir.glob("*.json")):
            fp_display = path.stem.replace("_", " ")
            try:
                raw = path.read_bytes()
                if self._key is not None:
                    doc = json.loads(
                        aes_gcm_decrypt(self._key, b64_decode(raw.decode("ascii")))
                    )
                else:
                    doc = json.loads(raw)
            except Exception:
                continue  # unreadable (wrong key or corrupt) — leave the file
            if doc.get("version") != 1:
                continue
            messages = doc.get("messages", [])
            for msg in messages:
                self.append(fp_display, msg)
            if messages:
                path.unlink()
