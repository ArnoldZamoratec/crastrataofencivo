"""Shared test fixtures and a signed-payload factory."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.schemas.payload import MessageType, PayloadEnvelope
from app.security.dispatcher import CommandDispatcher
from app.security.engine import SecurityEngine
from app.security.ratelimit import RateLimiter
from app.security.replay import NonceCache
from app.security.signing import (
    DeviceSecretRegistry,
    compute_integrity_hash,
    compute_signature,
)

DEMO_DEVICE = "LAB-ANDROID-TEST0001"
DEMO_SECRET = "unit-test-lab-secret"


def build_payload(
    *,
    device_id: str = DEMO_DEVICE,
    secret: str = DEMO_SECRET,
    command: str = "PING",
    timestamp: datetime | None = None,
    nonce: str | None = None,
    request_id: str = "REQ-0001",
    parameters: dict | None = None,
    version: str = "1.0",
    sign: bool = True,
) -> PayloadEnvelope:
    """Construct a (by default correctly signed) payload envelope."""
    env = PayloadEnvelope(
        version=version,
        type=MessageType.LAB_COMMAND,
        requestId=request_id,
        deviceId=device_id,
        command=command,
        parameters=parameters or {},
        timestamp=timestamp or datetime.now(timezone.utc),
        nonce=nonce or uuid.uuid4().hex,
    )
    if not sign:
        return env
    signature = compute_signature(secret, env.canonical_signing_bytes())
    integrity = compute_integrity_hash(env.integrity_bytes())
    return env.model_copy(update={"signature": signature, "integrity_hash": integrity})


def make_dispatcher(
    *,
    rate_limit: int = 60,
    ttl: int = 30,
    max_bytes: int = 8192,
    permissions: dict[str, set[str]] | None = None,
    register: bool = True,
) -> CommandDispatcher:
    secrets = DeviceSecretRegistry(fallback_secret="fallback")
    if register:
        secrets.register(DEMO_DEVICE, DEMO_SECRET)
    return CommandDispatcher(
        engine=SecurityEngine(),
        secrets=secrets,
        nonce_cache=NonceCache(ttl_seconds=120),
        rate_limiter=RateLimiter(per_minute=rate_limit),
        protocol_version="1.0",
        payload_ttl_seconds=ttl,
        max_payload_bytes=max_bytes,
        device_permissions=permissions,
    )


@pytest.fixture
def dispatcher() -> CommandDispatcher:
    return make_dispatcher()


@pytest.fixture
def expired_time() -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=600)
