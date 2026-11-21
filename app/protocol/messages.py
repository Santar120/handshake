"""Message envelopes and control subtypes (PROTOCOL.md §7)."""

from __future__ import annotations

import base64
import os
import time
from dataclasses import dataclass, field
from typing import Any

# Message types
TYPE_TEXT = "text"
TYPE_TYPING = "typing"
TYPE_CONTROL = "control"
TYPE_MEDIA = "media"  # Phase 2+

# Control subtypes
CTL_KEYCHECK = "keycheck"
CTL_PING = "ping"
CTL_PONG = "pong"
CTL_CONNECT = "connect"
CTL_DISCONNECT = "disconnect"
CTL_ROTATE = "rotate"


def new_message_id() -> str:
    """Globally unique message id (128 random bits, base64url).

    Assigned once by the sender; used for deduplication and sync so the
    same message is never stored twice, no matter how many times or from
    how many devices it is seen.
    """
    return base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")


@dataclass
class Envelope:
    type: str
    sender: str  # fingerprint display form
    seq: int
    ts: float
    payload: dict[str, Any] = field(default_factory=dict)
    group: str | None = None
    id: str = field(default_factory=new_message_id)

    def to_json(self) -> bytes:
        import json

        doc = {
            "type": self.type,
            "sender": self.sender,
            "group": self.group,
            "seq": self.seq,
            "ts": self.ts,
            "payload": self.payload,
            "id": self.id,
        }
        return json.dumps(doc, sort_keys=True).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> "Envelope":
        import json

        doc = json.loads(data)
        return cls(
            type=doc["type"],
            sender=doc["sender"],
            group=doc.get("group"),
            seq=int(doc["seq"]),
            ts=float(doc["ts"]),
            payload=doc.get("payload", {}),
            id=doc.get("id") or new_message_id(),
        )

    # -- constructors ------------------------------------------------------

    @classmethod
    def text(cls, sender: str, seq: int, text: str, group: str | None = None) -> "Envelope":
        return cls(
            type=TYPE_TEXT,
            sender=sender,
            seq=seq,
            ts=time.time(),
            payload={"text": text},
            group=group,
        )

    @classmethod
    def typing(cls, sender: str, seq: int) -> "Envelope":
        return cls(type=TYPE_TYPING, sender=sender, seq=seq, ts=time.time())

    @classmethod
    def control(
        cls, sender: str, seq: int, subtype: str, **extra: Any
    ) -> "Envelope":
        payload = {"subtype": subtype, **extra}
        return cls(type=TYPE_CONTROL, sender=sender, seq=seq, ts=time.time(), payload=payload)
