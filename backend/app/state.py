"""Process-wide lab state: the dispatcher and its collaborators.

Constructed once at startup. The Security Engine sink persists events to the
database when a session factory is available.
"""
from __future__ import annotations

from .config import get_settings
from .security.dispatcher import CommandDispatcher
from .security.engine import SecurityEngine, SecurityEvent
from .security.ratelimit import RateLimiter
from .security.replay import NonceCache
from .security.signing import DeviceSecretRegistry


class LabState:
    def __init__(self) -> None:
        s = get_settings()
        self.settings = s
        self.secrets = DeviceSecretRegistry(fallback_secret=s.hmac_secret)
        self.nonce_cache = NonceCache(ttl_seconds=s.nonce_cache_ttl_seconds)
        self.rate_limiter = RateLimiter(per_minute=s.rate_limit_per_minute)
        self.engine = SecurityEngine(sink=self._persist_event)
        self.dispatcher = CommandDispatcher(
            engine=self.engine,
            secrets=self.secrets,
            nonce_cache=self.nonce_cache,
            rate_limiter=self.rate_limiter,
            protocol_version=s.protocol_version,
            payload_ttl_seconds=s.payload_ttl_seconds,
            max_payload_bytes=s.max_payload_bytes,
        )
        # Track active WebSocket connections for offline detection.
        self.active_connections: dict[str, str] = {}

    def _persist_event(self, event: SecurityEvent) -> None:
        # Best-effort persistence; never raise into the request path.
        try:
            from .database import SessionLocal
            from .models import SecurityEventRow

            with SessionLocal() as db:
                db.add(
                    SecurityEventRow(
                        rule_id=event.rule_id,
                        name=event.name,
                        severity=event.severity.value,
                        device_id=event.device_id,
                        request_id=event.request_id,
                        detail=event.detail,
                    )
                )
                db.commit()
        except Exception:  # pragma: no cover - persistence is best-effort
            pass

    def seed_demo_device(self) -> tuple[str, str]:
        """Register a demo lab device so the app is usable out of the box."""
        device_id = "LAB-ANDROID-DEMO0001"
        secret = self.settings.hmac_secret
        self.secrets.register(device_id, secret)
        return device_id, secret


lab_state = LabState()
