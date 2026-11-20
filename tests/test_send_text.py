"""Tests for AppCore.send_text's return contract.

send_text returns the Envelope it handed to the connection (so the UI can
echo the message locally — the sender never receives its own message back)
and None when nothing was sent.
"""

from __future__ import annotations

from pathlib import Path

from app.core.appcore import AppCore
from app.core.identity import new_identity
from app.core.vault import Vault
from app.protocol.messages import TYPE_TEXT


class _FakeConn:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list = []
        self._fail = fail

    async def send_envelope(self, env) -> None:
        if self._fail:
            raise OSError("boom")
        self.sent.append(env)


def _core_with_conn(qapp, tmp_path: Path, conn) -> AppCore:
    """A real (unstarted) AppCore with a vault and a stubbed _run."""
    core = AppCore()
    core.vault = Vault.create(tmp_path / "vault.json", new_identity("Alice"), None)
    core.dialer = None
    core.listener = None
    core._connection_for = lambda fp: conn  # type: ignore[method-assign]

    def _run(coro):
        import asyncio

        return asyncio.run(coro)

    core._run = _run  # type: ignore[method-assign]
    return core


def test_send_text_returns_envelope(qapp, tmp_path: Path):
    conn = _FakeConn()
    core = _core_with_conn(qapp, tmp_path, conn)

    env = core.send_text("AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH", "hello")

    assert env is not None
    assert env.type == TYPE_TEXT
    assert env.payload["text"] == "hello"
    assert env.sender == core.identity.fingerprint_display
    assert conn.sent == [env]


def test_send_text_returns_none_when_not_connected(qapp, tmp_path: Path):
    core = _core_with_conn(qapp, tmp_path, None)

    assert core.send_text("AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH", "hi") is None


def test_send_text_returns_none_on_send_failure(qapp, tmp_path: Path):
    core = _core_with_conn(qapp, tmp_path, _FakeConn(fail=True))
    errors: list[str] = []
    core.error.connect(errors.append)

    env = core.send_text("AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH", "hi")

    assert env is None
    assert any("send failed" in e for e in errors)
