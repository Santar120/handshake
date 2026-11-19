"""Encrypted chat archive.

Chat history is session-scoped (in memory). Optionally, each 1:1
conversation is also written to a per-peer encrypted archive file so
either side can pull the conversation back after a restart.

File layout (one file per peer, keyed by the peer's fingerprint):

    archive/<fingerprint-display>.json

File format:
    {
      "version": 1,
      "peer_fingerprint": "<display>",
      "messages": [ {envelope}, ... ]
    }

The whole file is AES-256-GCM encrypted with the vault key (or, when the
user skipped the PIN, stored in plaintext — same tradeoff as the vault).
"""

from __future__ import annotations

import json
from pathlib import Path

from .crypto import aes_gcm_decrypt, aes_gcm_encrypt, b64_decode, b64_encode
from .paths import archive_dir

ARCHIVE_VERSION = 1


class Archive:
    def __init__(self, key: bytes | None, directory: Path | None = None) -> None:
        self._key = key
        self._dir = directory or archive_dir()

    def _path_for(self, peer_fingerprint_display: str) -> Path:
        # Fingerprint display is safe as a filename (A-Z 2-7 spaces).
        safe = peer_fingerprint_display.replace(" ", "_")
        return self._dir / f"{safe}.json"

    def load(self, peer_fingerprint_display: str) -> list[dict]:
        path = self._path_for(peer_fingerprint_display)
        if not path.exists():
            return []
        raw = path.read_bytes()
        if self._key is not None:
            try:
                doc = json.loads(aes_gcm_decrypt(self._key, b64_decode(raw.decode("ascii"))))
            except Exception:
                return []
        else:
            try:
                doc = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                return []
        if doc.get("version") != ARCHIVE_VERSION:
            return []
        return doc.get("messages", [])

    def append(self, peer_fingerprint_display: str, envelope: dict) -> None:
        messages = self.load(peer_fingerprint_display)
        messages.append(envelope)
        self._write(peer_fingerprint_display, messages)

    def _write(self, peer_fingerprint_display: str, messages: list[dict]) -> None:
        doc = {
            "version": ARCHIVE_VERSION,
            "peer_fingerprint": peer_fingerprint_display,
            "messages": messages,
        }
        payload = json.dumps(doc, sort_keys=True).encode("utf-8")
        if self._key is not None:
            blob = b64_encode(aes_gcm_encrypt(self._key, payload)).encode("ascii")
        else:
            blob = payload
        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._path_for(peer_fingerprint_display)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        tmp.replace(path)

    def clear(self, peer_fingerprint_display: str) -> None:
        path = self._path_for(peer_fingerprint_display)
        if path.exists():
            path.unlink()

    def list_files(self) -> dict[str, list[dict]]:
        """All archived conversations: {peer_fingerprint_display: [envelope, ...]}."""
        out: dict[str, list[dict]] = {}
        if not self._dir.exists():
            return out
        for path in sorted(self._dir.glob("*.json")):
            fp_display = path.stem.replace("_", " ")
            msgs = self.load(fp_display)
            if msgs:
                out[fp_display] = msgs
        return out
