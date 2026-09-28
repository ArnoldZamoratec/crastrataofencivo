"""Non-executable JSON payload schemas.

A payload is *data*, never code. These Pydantic models define the signed
envelope described in ``docs/payload-protocol.md``. Nothing in this module
interprets, compiles, or executes any field value.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class MessageType(str, Enum):
    LAB_COMMAND = "LAB_COMMAND"
    HEARTBEAT = "HEARTBEAT"
    RESPONSE = "RESPONSE"
    SECURITY_EVENT = "SECURITY_EVENT"


class PayloadEnvelope(BaseModel):
    """The signed envelope exchanged over the lab WebSocket / REST surface.

    Field semantics mirror ``docs/payload-protocol.md``. ``parameters`` is a
    plain mapping validated per-command by the dispatcher; it is never a code
    object and is never evaluated.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    version: str = Field(..., description="Protocol version, e.g. '1.0'.")
    type: MessageType = Field(...)
    request_id: str = Field(..., alias="requestId", min_length=1, max_length=128)
    device_id: str = Field(..., alias="deviceId", min_length=1, max_length=64)
    command: str = Field(..., min_length=1, max_length=64)
    parameters: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(...)
    nonce: str = Field(..., min_length=8, max_length=128)
    signature: str | None = Field(default=None, max_length=256)
    integrity_hash: str | None = Field(
        default=None, alias="integrityHash", max_length=256
    )

    @field_validator("timestamp")
    @classmethod
    def _tz_aware_utc(cls, v: datetime) -> datetime:
        # Normalise to timezone-aware UTC so freshness math is unambiguous.
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("device_id")
    @classmethod
    def _lab_device_id(cls, v: str) -> str:
        # Enforce synthetic lab identifiers. Never accept an IMEI/IMSI/phone.
        if not v.startswith("LAB-ANDROID-"):
            raise ValueError("deviceId must be a synthetic 'LAB-ANDROID-' identifier")
        return v

    def canonical_signing_bytes(self) -> bytes:
        """Deterministic byte string the signature is computed over.

        Excludes ``signature`` itself. Uses sorted, separator-fixed JSON so
        both ends agree on the exact bytes.
        """
        import json

        payload = {
            "version": self.version,
            "type": self.type.value,
            "requestId": self.request_id,
            "deviceId": self.device_id,
            "command": self.command,
            "parameters": self.parameters,
            "timestamp": self.timestamp.astimezone(timezone.utc).isoformat().replace(
                "+00:00", "Z"
            ),
            "nonce": self.nonce,
        }
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def integrity_bytes(self) -> bytes:
        """Bytes hashed for ``integrityHash`` (the body, excluding hashes/sig)."""
        return self.canonical_signing_bytes()


class HeartbeatMessage(BaseModel):
    """Telemetry heartbeat. Carries no personal data."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    type: str = Field(default="heartbeat")
    device_id: str = Field(..., alias="deviceId")
    timestamp: datetime = Field(...)
    status: str = Field(default="online")
