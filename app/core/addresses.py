"""Address helpers: detect LAN/public IP and pick the address to advertise.

The "address" is the host part of where others can reach this machine
(e.g. a public IP, a LAN IP, or a custom domain). It is shown in Settings,
put on the Identity Card, and used to pre-fill the host when a peer adds you.
"""

from __future__ import annotations

import socket
import urllib.request


def detect_lan_ip() -> str:
    """Best-effort LAN IP via the UDP socket trick.

    Opens a UDP socket "connected" to a public address (no packets are
    actually sent) and reads back the local interface address. No external
    network call is made, so this is safe and fast.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


def detect_public_ip(timeout: float = 4.0) -> str:
    """Best-effort public IP via a lightweight service.

    Returns "" on any failure (no internet, timeout, blocked, etc.). This
    makes an outbound request to a third party, so it is only run when the
    user explicitly clicks "Detect" in Settings.
    """
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "handshake/0.1"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                value = resp.read().decode("ascii").strip()
            if value and _is_ip(value):
                return value
        except Exception:
            continue
    return ""


def _is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except Exception:
        return False


def best_address(settings) -> str:
    """Pick the address to advertise on the Identity Card.

    Priority: custom URL > public IP > LAN IP. An explicitly set custom
    URL wins (it's the user's own domain); otherwise prefer the public IP
    (reachable from the internet), then the LAN IP (local network).
    """
    for candidate in (settings.custom_url, settings.public_ip, settings.lan_ip):
        if candidate and candidate.strip():
            return candidate.strip()
    return ""
