"""Identity: keypairs, fingerprints, Identity Cards (text + QR)."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .crypto import (
    ED25519_PUB_LEN,
    X25519_PUB_LEN,
    IdentityCardError,
    b64_decode,
    b64_encode,
    fingerprint_bytes,
    fingerprint_display,
    fingerprint_parse,
    generate_ed25519,
    generate_x25519,
)

CARD_MAGIC = "HANDSHAKE-IDENTITY v1"


@dataclass(frozen=True)
class Identity:
    """A full identity: alias + both keypairs (private keys included)."""

    alias: str
    x25519: X25519PrivateKey
    ed25519: Ed25519PrivateKey

    @property
    def x25519_pub(self) -> bytes:
        return self.x25519.public_key().public_bytes_raw()

    @property
    def ed25519_pub(self) -> bytes:
        return self.ed25519.public_key().public_bytes_raw()

    @property
    def fingerprint(self) -> bytes:
        return fingerprint_bytes(self.x25519_pub, self.ed25519_pub)

    @property
    def fingerprint_display(self) -> str:
        return fingerprint_display(self.fingerprint)

    def sign(self, data: bytes) -> bytes:
        return self.ed25519.sign(data)

    def to_card(
        self, port: int | None = None, address: str | None = None
    ) -> str:
        return render_card(
            self.alias, self.x25519_pub, self.ed25519_pub, port, address
        )

    def to_card_json(
        self, port: int | None = None, address: str | None = None
    ) -> str:
        """Public identity card as JSON (safe to share)."""
        doc = {
            "magic": CARD_MAGIC,
            "alias": self.alias,
            "x25519": b64_encode(self.x25519_pub),
            "ed25519": b64_encode(self.ed25519_pub),
            "fingerprint": self.fingerprint_display,
        }
        if port is not None:
            doc["port"] = int(port)
        if address:
            doc["address"] = address
        return json.dumps(doc, indent=2)

    def to_qr_png(
        self,
        port: int | None = None,
        address: str | None = None,
        box_size: int = 8,
        border: int = 2,
    ) -> bytes:
        import qrcode
        from qrcode.image.pil import PilImage

        img: PilImage = qrcode.make(
            self.to_card(port, address), box_size=box_size, border=border
        )
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()


@dataclass(frozen=True)
class PeerIdentity:
    """A peer's public identity (no private keys)."""

    alias: str
    x25519_pub: bytes
    ed25519_pub: bytes
    port: int | None = None
    address: str | None = None

    @property
    def fingerprint(self) -> bytes:
        return fingerprint_bytes(self.x25519_pub, self.ed25519_pub)

    @property
    def fingerprint_display(self) -> str:
        return fingerprint_display(self.fingerprint)

    def verify_signature(self, data: bytes, sig: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(self.ed25519_pub)
            pub.verify(sig, data)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Card rendering / parsing
# ---------------------------------------------------------------------------


def render_card(
    alias: str,
    x25519_pub: bytes,
    ed25519_pub: bytes,
    port: int | None = None,
    address: str | None = None,
) -> str:
    fp = fingerprint_display(fingerprint_bytes(x25519_pub, ed25519_pub))
    lines = [
        CARD_MAGIC,
        f"alias: {alias}",
        f"x25519: {b64_encode(x25519_pub)}",
        f"ed25519: {b64_encode(ed25519_pub)}",
        f"fingerprint: {fp}",
    ]
    if port is not None:
        lines.append(f"port: {int(port)}")
    if address:
        lines.append(f"address: {address}")
    return "\n".join(lines) + "\n"


def parse_card(text: str) -> PeerIdentity:
    """Parse an Identity Card (text or JSON). Verifies the fingerprint against
    the public keys; raises IdentityCardError on any problem."""
    stripped = text.strip()
    if stripped.startswith("{"):
        return _parse_card_json(stripped)
    lines: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == CARD_MAGIC:
            continue
        if ":" not in line:
            raise IdentityCardError(f"unrecognized line: {line!r}")
        key, _, value = line.partition(":")
        lines[key.strip().lower()] = value.strip()

    try:
        alias = lines["alias"]
        x25519_pub = b64_decode(lines["x25519"])
        ed25519_pub = b64_decode(lines["ed25519"])
        fp_text = lines["fingerprint"]
    except KeyError as missing:
        raise IdentityCardError(f"missing field: {missing.args[0]}") from None
    except Exception as exc:
        raise IdentityCardError(f"malformed field: {exc}") from None

    if len(x25519_pub) != X25519_PUB_LEN:
        raise IdentityCardError("x25519 key must be 32 bytes")
    if len(ed25519_pub) != ED25519_PUB_LEN:
        raise IdentityCardError("ed25519 key must be 32 bytes")
    if not alias:
        raise IdentityCardError("alias must not be empty")

    try:
        fp = fingerprint_parse(fp_text)
    except ValueError as exc:
        raise IdentityCardError(f"bad fingerprint: {exc}") from None
    if fp != fingerprint_bytes(x25519_pub, ed25519_pub):
        raise IdentityCardError(
            "fingerprint does not match the public keys — card is corrupt "
            "or has been tampered with"
        )

    port = _parse_optional_port(lines.get("port"))
    address = lines.get("address") or None
    return PeerIdentity(
        alias=alias,
        x25519_pub=x25519_pub,
        ed25519_pub=ed25519_pub,
        port=port,
        address=address,
    )


def _parse_card_json(text: str) -> PeerIdentity:
    """Parse a JSON identity card with the same validation as the text card."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IdentityCardError(f"invalid JSON: {exc}") from None
    try:
        alias = doc["alias"]
        x25519_pub = b64_decode(doc["x25519"])
        ed25519_pub = b64_decode(doc["ed25519"])
        fp_text = doc["fingerprint"]
    except (KeyError, TypeError) as exc:
        raise IdentityCardError(f"missing field: {exc}") from None
    except Exception as exc:
        raise IdentityCardError(f"malformed field: {exc}") from None

    if len(x25519_pub) != X25519_PUB_LEN:
        raise IdentityCardError("x25519 key must be 32 bytes")
    if len(ed25519_pub) != ED25519_PUB_LEN:
        raise IdentityCardError("ed25519 key must be 32 bytes")
    if not alias:
        raise IdentityCardError("alias must not be empty")

    try:
        fp = fingerprint_parse(fp_text)
    except ValueError as exc:
        raise IdentityCardError(f"bad fingerprint: {exc}") from None
    if fp != fingerprint_bytes(x25519_pub, ed25519_pub):
        raise IdentityCardError(
            "fingerprint does not match the public keys — card is corrupt "
            "or has been tampered with"
        )
    port = _parse_optional_port(doc.get("port"))
    address = doc.get("address") or None
    return PeerIdentity(
        alias=alias,
        x25519_pub=x25519_pub,
        ed25519_pub=ed25519_pub,
        port=port,
        address=address,
    )


def _parse_optional_port(value) -> int | None:
    """Parse an optional port field from a card. Returns None if absent."""
    if value is None:
        return None
    if isinstance(value, bool):
        raise IdentityCardError(f"bad port: {value!r}")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise IdentityCardError(f"bad port: {value!r}") from None
    if not (1 <= port <= 65535):
        raise IdentityCardError(f"port out of range: {port}")
    return port


def new_identity(alias: str) -> Identity:
    return Identity(
        alias=alias,
        x25519=generate_x25519(),
        ed25519=generate_ed25519(),
    )
