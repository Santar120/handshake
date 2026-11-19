"""Unit tests for app.protocol.states and app.protocol.messages."""

from __future__ import annotations

import pytest

from app.protocol.messages import (
    TYPE_CONTROL,
    TYPE_TEXT,
    CTL_PING,
    Envelope,
)
from app.protocol.states import ConnState, StateMachine


def test_state_machine_happy_path():
    sm = StateMachine()
    assert sm.state == ConnState.DISCONNECTED
    sm.transition(ConnState.CONNECTING)
    sm.transition(ConnState.HANDSHAKE)
    sm.transition(ConnState.CONNECTED)
    sm.transition(ConnState.CLOSING)
    sm.transition(ConnState.DISCONNECTED)


def test_state_machine_illegal_transition():
    sm = StateMachine()
    with pytest.raises(ValueError):
        sm.transition(ConnState.CONNECTED)  # must go through CONNECTING


def test_state_machine_any_to_disconnected():
    sm = StateMachine()
    sm.transition(ConnState.CONNECTING)
    sm.transition(ConnState.HANDSHAKE)
    sm.transition(ConnState.DISCONNECTED)  # allowed from anywhere
    sm.reset()
    assert sm.state == ConnState.DISCONNECTED


def test_envelope_json_roundtrip():
    env = Envelope.text("FP", 1, "hello world")
    back = Envelope.from_json(env.to_json())
    assert back.type == TYPE_TEXT
    assert back.sender == "FP"
    assert back.seq == 1
    assert back.payload["text"] == "hello world"


def test_envelope_control_roundtrip():
    env = Envelope.control("FP", 2, CTL_PING)
    back = Envelope.from_json(env.to_json())
    assert back.type == TYPE_CONTROL
    assert back.payload["subtype"] == CTL_PING


def test_envelope_group_roundtrip():
    env = Envelope.text("FP", 3, "hi", group="grp-1")
    back = Envelope.from_json(env.to_json())
    assert back.group == "grp-1"
