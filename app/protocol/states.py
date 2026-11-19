"""Connection state machine (PROTOCOL.md §9)."""

from __future__ import annotations

from enum import Enum


class ConnState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    HANDSHAKE = "handshake"
    CONNECTED = "connected"
    CLOSING = "closing"


# Allowed transitions. Any state may go to DISCONNECTED on error.
TRANSITIONS: dict[ConnState, set[ConnState]] = {
    ConnState.DISCONNECTED: {ConnState.CONNECTING},
    ConnState.CONNECTING: {ConnState.HANDSHAKE, ConnState.CLOSING},
    ConnState.HANDSHAKE: {ConnState.CONNECTED, ConnState.CLOSING},
    ConnState.CONNECTED: {ConnState.CLOSING},
    ConnState.CLOSING: {ConnState.DISCONNECTED},
}


class StateMachine:
    def __init__(self) -> None:
        self._state = ConnState.DISCONNECTED

    @property
    def state(self) -> ConnState:
        return self._state

    def transition(self, new: ConnState) -> None:
        if new == ConnState.DISCONNECTED:
            self._state = new
            return
        allowed = TRANSITIONS.get(self._state, set())
        if new not in allowed:
            raise ValueError(
                f"illegal state transition: {self._state.value} -> {new.value}"
            )
        self._state = new

    def reset(self) -> None:
        self._state = ConnState.DISCONNECTED
