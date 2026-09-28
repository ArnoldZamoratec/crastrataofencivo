"""HMAC-SHA256 payload signing and integrity hashing.

Secrets come from a per-device registry (see ``DeviceSecretRegistry``); no
secret is hardcoded here. Comparison uses ``hmac.compare_digest`` to avoid
timing side channels.
"""
from __future__ import annotations

import hashlib
import hmac


def compute_signature(secret: str, signing_bytes: bytes) -> str:
    digest = hmac.new(secret.encode("utf-8"), signing_bytes, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_signature(secret: str, signing_bytes: bytes, signature: str | None) -> bool:
    if not signature:
        return False
    expected = compute_signature(secret, signing_bytes)
    return hmac.compare_digest(expected, signature)


def compute_integrity_hash(body_bytes: bytes) -> str:
    return f"sha256:{hashlib.sha256(body_bytes).hexdigest()}"


def verify_integrity_hash(body_bytes: bytes, integrity_hash: str | None) -> bool:
    if not integrity_hash:
        # Integrity hash is optional; absence is not a failure on its own.
        return True
    return hmac.compare_digest(compute_integrity_hash(body_bytes), integrity_hash)


class DeviceSecretRegistry:
    """In-memory map of ``deviceId`` -> HMAC secret for the lab.

    Real deployments would back this with the database + ``.env``; for the
    lab it is a simple registry seeded at startup.
    """

    def __init__(self, fallback_secret: str) -> None:
        self._secrets: dict[str, str] = {}
        self._fallback = fallback_secret

    def register(self, device_id: str, secret: str) -> None:
        self._secrets[device_id] = secret

    def is_registered(self, device_id: str) -> bool:
        return device_id in self._secrets

    def secret_for(self, device_id: str) -> str:
        return self._secrets.get(device_id, self._fallback)
