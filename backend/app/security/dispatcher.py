"""The 7-stage, fail-closed command dispatcher.

Pipeline: Payload -> Schema Validation -> Authentication -> Command Allowlist
-> Permission Check -> Command Handler -> Response.

A failure at any stage stops the pipeline, records a Security Engine event,
and returns a typed rejection. The handler never runs on unvalidated input.
There is no arbitrary/dynamic/reflection execution anywhere in this path.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import ValidationError

from ..schemas.payload import PayloadEnvelope
from .commands import is_allowed, is_explicitly_blocked
from .engine import SecurityEngine
from .handlers import HANDLERS
from .ratelimit import RateLimiter
from .replay import NonceCache, is_fresh
from .signing import DeviceSecretRegistry, verify_integrity_hash, verify_signature


class DispatchStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


@dataclass
class DispatchResult:
    status: DispatchStatus
    request_id: str | None
    device_id: str | None
    reason: str | None = None
    rule_id: str | None = None
    result: dict[str, Any] | None = None

    @property
    def accepted(self) -> bool:
        return self.status is DispatchStatus.ACCEPTED


class CommandDispatcher:
    def __init__(
        self,
        *,
        engine: SecurityEngine,
        secrets: DeviceSecretRegistry,
        nonce_cache: NonceCache,
        rate_limiter: RateLimiter,
        protocol_version: str,
        payload_ttl_seconds: int,
        max_payload_bytes: int,
        device_permissions: dict[str, set[str]] | None = None,
    ) -> None:
        self.engine = engine
        self.secrets = secrets
        self.nonce_cache = nonce_cache
        self.rate_limiter = rate_limiter
        self.protocol_version = protocol_version
        self.payload_ttl_seconds = payload_ttl_seconds
        self.max_payload_bytes = max_payload_bytes
        # Optional per-device permission scopes (command -> allowed).
        self.device_permissions = device_permissions or {}

    def _reject(
        self, rule_id: str, *, device_id=None, request_id=None, detail=""
    ) -> DispatchResult:
        event = self.engine.raise_event(
            rule_id, device_id=device_id, request_id=request_id, detail=detail
        )
        return DispatchResult(
            status=DispatchStatus.REJECTED,
            request_id=request_id,
            device_id=device_id,
            reason=event.name,
            rule_id=rule_id,
        )

    def dispatch_raw(self, raw: bytes | str) -> DispatchResult:
        """Full pipeline starting from raw bytes/str (as received on the wire)."""
        # Stage 0: size guard (RULE-008) before we even parse.
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        if len(raw_bytes) > self.max_payload_bytes:
            return self._reject(
                "RULE-008", detail=f"payload {len(raw_bytes)}B exceeds limit"
            )

        # Stage 1: schema validation. Invalid JSON / schema -> reject.
        try:
            envelope = PayloadEnvelope.model_validate_json(raw_bytes)
        except ValidationError as exc:
            # Invalid schema is not one of the numbered rules on its own; log
            # under RULE-001 family as an unprocessable payload with detail.
            return self._reject("RULE-001", detail=f"invalid schema: {exc.error_count()} errors")
        except ValueError as exc:
            return self._reject("RULE-001", detail=f"invalid json: {exc}")

        return self.dispatch(envelope, raw_bytes=raw_bytes)

    def dispatch(
        self, envelope: PayloadEnvelope, *, raw_bytes: bytes | None = None
    ) -> DispatchResult:
        did, rid = envelope.device_id, envelope.request_id

        # Protocol version guard.
        if envelope.version != self.protocol_version:
            return self._reject(
                "RULE-001", device_id=did, request_id=rid,
                detail=f"unsupported protocol version {envelope.version}",
            )

        # Rate limiting (DoS guard), keyed by device.
        if not self.rate_limiter.allow(did):
            return self._reject(
                "RULE-008", device_id=did, request_id=rid, detail="rate limit exceeded"
            )

        # Stage 2: authentication — device registration + signature.
        if not self.secrets.is_registered(did):
            return self._reject(
                "RULE-005", device_id=did, request_id=rid, detail="unregistered device"
            )

        secret = self.secrets.secret_for(did)
        signing_bytes = envelope.canonical_signing_bytes()
        if not verify_integrity_hash(envelope.integrity_bytes(), envelope.integrity_hash):
            return self._reject(
                "RULE-002", device_id=did, request_id=rid, detail="integrity hash mismatch"
            )
        if not verify_signature(secret, signing_bytes, envelope.signature):
            return self._reject(
                "RULE-002", device_id=did, request_id=rid, detail="signature mismatch"
            )

        # Replay defense: freshness window (RULE-003) + nonce (RULE-004).
        if not is_fresh(envelope.timestamp, self.payload_ttl_seconds):
            return self._reject(
                "RULE-003", device_id=did, request_id=rid, detail="payload expired"
            )
        if not self.nonce_cache.check_and_store(envelope.nonce):
            return self._reject(
                "RULE-004", device_id=did, request_id=rid, detail="duplicate nonce"
            )

        # Stage 3: allowlist. Explicitly-blocked or unknown -> reject.
        if is_explicitly_blocked(envelope.command) or not is_allowed(envelope.command):
            return self._reject(
                "RULE-001", device_id=did, request_id=rid,
                detail=f"command not allowlisted: {envelope.command}",
            )

        # Stage 4: permission scope check (RULE-006).
        scopes = self.device_permissions.get(did)
        if scopes is not None and envelope.command not in scopes:
            return self._reject(
                "RULE-006", device_id=did, request_id=rid,
                detail=f"command outside device scope: {envelope.command}",
            )

        # Stage 5: handler (static lookup, never reflection).
        handler = HANDLERS[envelope.command]
        result = handler(did, envelope.parameters)

        # Stage 6: response.
        return DispatchResult(
            status=DispatchStatus.ACCEPTED,
            request_id=rid,
            device_id=did,
            result=result,
        )
