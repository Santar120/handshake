"""Vault: local storage for identity, peers, and settings.

The vault file lives in the platform app-data directory
(``~/.config/handshake/vault.json`` etc.). When a PIN is set, the payload
is AES-256-GCM encrypted with a key derived from the PIN (argon2id +
HKDF). When the user skips the PIN, the payload is stored in plaintext
and the app warns the user at onboarding.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from .crypto import (
    VaultError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    b64_decode,
    b64_encode,
    derive_vault_key,
)
from .identity import Identity, PeerIdentity

VAULT_VERSION = 1
BUNDLE_VERSION = 1
# Default listen port. Override with HANDSHAKE_PORT (useful for running a
# second instance on the same machine, e.g. for local two-user testing).
DEFAULT_LISTEN_PORT = int(os.environ.get("HANDSHAKE_PORT", "41337"))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Peer:
    """A configured peer: identity + transport + optional shared secret."""

    alias: str
    x25519_pub: bytes
    ed25519_pub: bytes
    host: str
    port: int
    psk: str | None = None  # shared secret (optional, recommended)

    @property
    def fingerprint(self) -> bytes:
        from .crypto import fingerprint_bytes

        return fingerprint_bytes(self.x25519_pub, self.ed25519_pub)

    @property
    def fingerprint_display(self) -> str:
        from .crypto import fingerprint_display

        return fingerprint_display(self.fingerprint)

    @property
    def transport(self) -> str:
        return f"{self.host}:{self.port}"

    def to_identity(self) -> PeerIdentity:
        return PeerIdentity(
            alias=self.alias,
            x25519_pub=self.x25519_pub,
            ed25519_pub=self.ed25519_pub,
        )

    def to_dict(self) -> dict:
        return {
            "alias": self.alias,
            "x25519_pub": b64_encode(self.x25519_pub),
            "ed25519_pub": b64_encode(self.ed25519_pub),
            "host": self.host,
            "port": self.port,
            "psk": self.psk,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Peer":
        return cls(
            alias=d["alias"],
            x25519_pub=b64_decode(d["x25519_pub"]),
            ed25519_pub=b64_decode(d["ed25519_pub"]),
            host=d["host"],
            port=int(d["port"]),
            psk=d.get("psk") or None,
        )


@dataclass
class Settings:
    listen_port: int = DEFAULT_LISTEN_PORT
    archive_enabled: bool = True
    lock_timeout_minutes: int = 5
    theme: str = "dark"

    def to_dict(self) -> dict:
        return {
            "listen_port": self.listen_port,
            "archive_enabled": self.archive_enabled,
            "lock_timeout_minutes": self.lock_timeout_minutes,
            "theme": self.theme,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Settings":
        return cls(
            listen_port=int(d.get("listen_port", DEFAULT_LISTEN_PORT)),
            archive_enabled=bool(d.get("archive_enabled", True)),
            lock_timeout_minutes=int(d.get("lock_timeout_minutes", 5)),
            theme=d.get("theme", "dark"),
        )


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


class Vault:
    """In-memory vault bound to a file on disk."""

    def __init__(
        self,
        path: Path,
        identity: Identity,
        peers: list[Peer],
        settings: Settings,
        has_pin: bool,
        salt: bytes | None,
        _key: bytes | None,
    ) -> None:
        self.path = path
        self.identity = identity
        self.peers = peers
        self.settings = settings
        self.has_pin = has_pin
        self._salt = salt
        self._key = _key  # None when PIN was skipped

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        identity: Identity,
        pin: str | None,
    ) -> "Vault":
        if path.exists():
            raise VaultError(f"vault already exists at {path}")
        salt = os.urandom(16) if pin else None
        key, salt = (derive_vault_key(pin, salt) if pin else (None, None))
        vault = cls(
            path=path,
            identity=identity,
            peers=[],
            settings=Settings(),
            has_pin=bool(pin),
            salt=salt,
            _key=key,
        )
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, pin: str | None) -> "Vault":
        if not path.exists():
            raise VaultError(f"no vault at {path}")
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultError(f"vault file is unreadable: {exc}") from None
        if doc.get("version") != VAULT_VERSION:
            raise VaultError("unsupported vault version")

        if doc.get("has_pin"):
            if not pin:
                raise VaultError("this vault is PIN-protected")
            salt = b64_decode(doc["salt"])
            key, _ = derive_vault_key(pin, salt)
            try:
                payload = aes_gcm_decrypt(key, b64_decode(doc["data"]))
            except Exception as exc:
                raise VaultError("wrong PIN or corrupt vault") from exc
        else:
            if pin:
                # A PIN was provided but the vault has none — accept it,
                # the vault simply isn't PIN-protected.
                pass
            key = None
            payload = json.dumps(doc["plain"]).encode("utf-8")

        data = json.loads(payload)
        identity = _identity_from_dict(data["identity"])
        peers = [Peer.from_dict(p) for p in data.get("peers", [])]
        settings = Settings.from_dict(data.get("settings", {}))
        return cls(
            path=path,
            identity=identity,
            peers=peers,
            settings=settings,
            has_pin=bool(doc.get("has_pin")),
            salt=b64_decode(doc["salt"]) if doc.get("has_pin") else None,
            _key=key,
        )

    def save(self) -> None:
        data = {
            "identity": _identity_to_dict(self.identity),
            "peers": [p.to_dict() for p in self.peers],
            "settings": self.settings.to_dict(),
        }
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        if self._key is not None:
            assert self._salt is not None
            doc = {
                "version": VAULT_VERSION,
                "has_pin": True,
                "salt": b64_encode(self._salt),
                "data": b64_encode(aes_gcm_encrypt(self._key, payload)),
            }
        else:
            doc = {
                "version": VAULT_VERSION,
                "has_pin": False,
                "plain": data,
            }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    # -- export / import bundle --------------------------------------------

    def export_bundle(self, archive: dict[str, list[dict]] | None = None) -> str:
        """Full identity bundle (identity + peers + settings + chat history).

        When the vault is PIN-protected the payload is AES-256-GCM encrypted
        with the vault key, so the file is useless without the PIN. A
        PIN-less vault exports in plaintext (same tradeoff as the vault file).
        """
        data = {
            "identity": _identity_to_dict(self.identity),
            "peers": [p.to_dict() for p in self.peers],
            "settings": self.settings.to_dict(),
            "archive": archive or {},
        }
        payload = json.dumps(data, sort_keys=True).encode("utf-8")
        if self._key is not None:
            assert self._salt is not None
            doc = {
                "magic": "HANDSHAKE-BUNDLE",
                "version": BUNDLE_VERSION,
                "encrypted": True,
                "salt": b64_encode(self._salt),
                "data": b64_encode(aes_gcm_encrypt(self._key, payload)),
            }
        else:
            doc = {
                "magic": "HANDSHAKE-BUNDLE",
                "version": BUNDLE_VERSION,
                "encrypted": False,
                "plain": data,
            }
        return json.dumps(doc, indent=2)

    @classmethod
    def import_bundle(
        cls,
        text: str,
        path: Path,
        pin: str | None,
        archive_dir: Path | None = None,
    ) -> "Vault":
        """Restore a vault (and its archive) from an exported bundle.

        Refuses to overwrite an existing vault. Returns the new Vault.
        """
        if path.exists():
            raise VaultError(
                "a vault already exists here — delete it first to import"
            )
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise VaultError(f"not a valid bundle file: {exc}") from None
        if doc.get("magic") != "HANDSHAKE-BUNDLE":
            raise VaultError("not a Handshake bundle file")
        if doc.get("version") != BUNDLE_VERSION:
            raise VaultError("unsupported bundle version")

        if doc.get("encrypted"):
            if not pin:
                raise VaultError("this bundle is PIN-protected — enter the PIN")
            salt = b64_decode(doc["salt"])
            key, _ = derive_vault_key(pin, salt)
            try:
                payload = aes_gcm_decrypt(key, b64_decode(doc["data"]))
            except Exception as exc:
                raise VaultError("wrong PIN or corrupt bundle") from exc
        else:
            key = None
            payload = json.dumps(doc["plain"]).encode("utf-8")

        data = json.loads(payload)
        identity = _identity_from_dict(data["identity"])
        peers = [Peer.from_dict(p) for p in data.get("peers", [])]
        settings = Settings.from_dict(data.get("settings", {}))
        vault = cls(
            path=path,
            identity=identity,
            peers=peers,
            settings=settings,
            has_pin=key is not None,
            salt=b64_decode(doc["salt"]) if doc.get("encrypted") else None,
            _key=key,
        )
        vault.save()

        # Restore the chat archive next to the vault.
        archive = data.get("archive") or {}
        if archive:
            from .archive import Archive

            arch = Archive(key, archive_dir)
            for fp_display, messages in archive.items():
                arch._write(fp_display, messages)
        return vault

    # -- peers -------------------------------------------------------------

    def find_peer_by_fingerprint(self, fp: bytes) -> Peer | None:
        for peer in self.peers:
            if peer.fingerprint == fp:
                return peer
        return None

    def add_peer(self, peer: Peer) -> None:
        existing = self.find_peer_by_fingerprint(peer.fingerprint)
        if existing is not None:
            # Update transport/psk for an existing identity.
            existing.host = peer.host
            existing.port = peer.port
            existing.psk = peer.psk
            existing.alias = peer.alias
        else:
            self.peers.append(peer)
        self.save()

    def remove_peer(self, fingerprint: bytes) -> None:
        self.peers = [p for p in self.peers if p.fingerprint != fingerprint]
        self.save()

    # -- identity ----------------------------------------------------------

    def rotate_identity(self, new_identity: Identity) -> None:
        """Replace the identity with a fresh keypair (old keys wiped)."""
        self.identity = new_identity
        self.save()

    # -- settings ----------------------------------------------------------

    def update_settings(self, **kwargs) -> None:
        for k, v in kwargs.items():
            if not hasattr(self.settings, k):
                raise ValueError(f"unknown setting: {k}")
            setattr(self.settings, k, v)
        self.save()


# ---------------------------------------------------------------------------
# (De)serialization of the identity (private keys)
# ---------------------------------------------------------------------------


def _identity_to_dict(identity: Identity) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )

    x_priv = identity.x25519.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    e_priv = identity.ed25519.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    return {
        "alias": identity.alias,
        "x25519_priv": b64_encode(x_priv),
        "ed25519_priv": b64_encode(e_priv),
    }


def _identity_from_dict(d: dict) -> Identity:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )

    x_priv = X25519PrivateKey.from_private_bytes(b64_decode(d["x25519_priv"]))
    e_priv = Ed25519PrivateKey.from_private_bytes(b64_decode(d["ed25519_priv"]))
    return Identity(alias=d["alias"], x25519=x_priv, ed25519=e_priv)
