"""Unit tests for the Security Engine rule registry and event logging."""
from __future__ import annotations

from app.security.commands import ALLOWED_COMMANDS, BLOCKED_COMMANDS
from app.security.engine import RULES, SecurityEngine, Severity


def test_all_eight_rules_present():
    assert set(RULES) == {f"RULE-00{i}" for i in range(1, 9)}


def test_rule_severities():
    assert RULES["RULE-002"][1] is Severity.CRITICAL
    assert RULES["RULE-005"][1] is Severity.CRITICAL
    assert RULES["RULE-001"][1] is Severity.HIGH


def test_event_log_carries_no_secret_fields():
    engine = SecurityEngine()
    event = engine.raise_event(
        "RULE-002", device_id="LAB-ANDROID-X", request_id="R1", detail="signature mismatch"
    )
    log = event.to_log()
    assert log["event"] == "RULE-002"
    assert log["level"] == "CRITICAL"
    assert set(log) == {
        "timestamp", "level", "service", "event", "name", "deviceId", "requestId", "detail",
    }
    # Never a field that could hold a secret or personal data.
    for forbidden in ("password", "token", "secret", "signature", "phone", "imei"):
        assert forbidden not in log


def test_allow_and_block_lists_are_disjoint():
    assert ALLOWED_COMMANDS.isdisjoint(BLOCKED_COMMANDS)
    assert "EXEC_SHELL" in BLOCKED_COMMANDS
    assert "PING" in ALLOWED_COMMANDS
