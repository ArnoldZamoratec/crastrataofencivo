"""Security Engine — detection rules RULE-001..008.

Each rule maps a rejection condition to a typed security event with a
severity. The engine is pure: it records events into an injected sink so it
can be unit-tested without a database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Rule registry: id -> (name, severity)
RULES: dict[str, tuple[str, Severity]] = {
    "RULE-001": ("Unknown command", Severity.HIGH),
    "RULE-002": ("Invalid signature", Severity.CRITICAL),
    "RULE-003": ("Expired payload", Severity.MEDIUM),
    "RULE-004": ("Replay detected", Severity.HIGH),
    "RULE-005": ("Unauthorized device", Severity.CRITICAL),
    "RULE-006": ("Unexpected permission", Severity.MEDIUM),
    "RULE-007": ("Unauthorized connection", Severity.HIGH),
    "RULE-008": ("Oversized payload", Severity.MEDIUM),
}


@dataclass(frozen=True)
class SecurityEvent:
    rule_id: str
    name: str
    severity: Severity
    device_id: str | None
    request_id: str | None
    detail: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_log(self) -> dict:
        # Structured log line. Never carries secrets or personal data.
        return {
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "level": self.severity.value,
            "service": "security-engine",
            "event": self.rule_id,
            "name": self.name,
            "deviceId": self.device_id,
            "requestId": self.request_id,
            "detail": self.detail,
        }


class SecurityEngine:
    def __init__(self, sink: Callable[[SecurityEvent], None] | None = None) -> None:
        self.events: list[SecurityEvent] = []
        self._sink = sink

    def raise_event(
        self,
        rule_id: str,
        *,
        device_id: str | None = None,
        request_id: str | None = None,
        detail: str = "",
    ) -> SecurityEvent:
        name, severity = RULES[rule_id]
        event = SecurityEvent(
            rule_id=rule_id,
            name=name,
            severity=severity,
            device_id=device_id,
            request_id=request_id,
            detail=detail,
        )
        self.events.append(event)
        if self._sink is not None:
            self._sink(event)
        return event
