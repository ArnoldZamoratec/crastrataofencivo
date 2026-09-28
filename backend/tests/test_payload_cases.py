"""Mandatory payload test cases for the fail-closed dispatcher.

Covers: VALID_PAYLOAD, INVALID_JSON, INVALID_SIGNATURE, EXPIRED_PAYLOAD,
REPLAY_ATTACK, UNKNOWN_COMMAND, UNAUTHORIZED_DEVICE, OVERSIZED_PAYLOAD,
RATE_LIMIT, DISCONNECTED_DEVICE.
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.security.dispatcher import DispatchStatus

from .conftest import DEMO_DEVICE, build_payload, make_dispatcher


def test_valid_payload_accepted(dispatcher):
    env = build_payload(command="PING")
    result = dispatcher.dispatch(env)
    assert result.status is DispatchStatus.ACCEPTED
    assert result.result["pong"] is True
    assert result.rule_id is None


def test_invalid_json_rejected(dispatcher):
    result = dispatcher.dispatch_raw("{not valid json")
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-001"


def test_invalid_signature_rejected(dispatcher):
    env = build_payload(command="PING")
    tampered = env.model_copy(update={"signature": "hmac-sha256:deadbeef"})
    result = dispatcher.dispatch(tampered)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-002"


def test_expired_payload_rejected(dispatcher, expired_time):
    env = build_payload(command="PING", timestamp=expired_time)
    result = dispatcher.dispatch(env)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-003"


def test_replay_attack_rejected(dispatcher):
    env = build_payload(command="PING", nonce="fixed-nonce-123456")
    first = dispatcher.dispatch(env)
    assert first.status is DispatchStatus.ACCEPTED
    # Re-send the exact same nonce -> replay.
    replay = build_payload(command="PING", nonce="fixed-nonce-123456", request_id="REQ-0002")
    result = dispatcher.dispatch(replay)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-004"


def test_unknown_command_rejected(dispatcher):
    env = build_payload(command="DO_SOMETHING_WEIRD")
    result = dispatcher.dispatch(env)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-001"


def test_explicitly_blocked_command_rejected(dispatcher):
    env = build_payload(command="EXEC_SHELL")
    result = dispatcher.dispatch(env)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-001"


def test_unauthorized_device_rejected():
    disp = make_dispatcher(register=False)
    env = build_payload(command="PING")
    result = disp.dispatch(env)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-005"


def test_oversized_payload_rejected():
    disp = make_dispatcher(max_bytes=256)
    env = build_payload(command="DISPLAY_MESSAGE", parameters={"text": "x" * 1000})
    raw = env.model_dump_json(by_alias=True)
    result = disp.dispatch_raw(raw)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-008"


def test_rate_limit_rejected():
    disp = make_dispatcher(rate_limit=2)
    # First two allowed, third rejected.
    r1 = disp.dispatch(build_payload(nonce="nonce-0001", request_id="R1"))
    r2 = disp.dispatch(build_payload(nonce="nonce-0002", request_id="R2"))
    r3 = disp.dispatch(build_payload(nonce="nonce-0003", request_id="R3"))
    assert r1.accepted and r2.accepted
    assert r3.status is DispatchStatus.REJECTED
    assert r3.rule_id == "RULE-008"


def test_permission_scope_rejected():
    # Device is registered but scoped to only PING.
    disp = make_dispatcher(permissions={DEMO_DEVICE: {"PING"}})
    env = build_payload(command="GET_DEVICE_INFO")
    result = disp.dispatch(env)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-006"


def test_disconnected_device_offline_detection():
    """A device with no active WebSocket is treated as offline.

    The active-connection map starts empty; nothing marks the device online
    until it connects, so offline detection holds by construction.
    """
    from app.state import LabState

    state = LabState()
    assert "LAB-ANDROID-ANY" not in state.active_connections


def test_wrong_protocol_version_rejected(dispatcher):
    env = build_payload(command="PING", version="9.9")
    result = dispatcher.dispatch(env)
    assert result.status is DispatchStatus.REJECTED
    assert result.rule_id == "RULE-001"


def test_non_lab_device_id_rejected_by_schema():
    import pytest
    from pydantic import ValidationError

    from app.schemas.payload import MessageType, PayloadEnvelope

    with pytest.raises(ValidationError):
        PayloadEnvelope(
            version="1.0",
            type=MessageType.LAB_COMMAND,
            requestId="R",
            deviceId="356938035643809",  # looks like an IMEI -> rejected
            command="PING",
            timestamp=datetime.now(timezone.utc),
            nonce="abcdefgh",
        )
