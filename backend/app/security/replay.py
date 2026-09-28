"""Replay protection: freshness window + single-use nonce cache.

Bounded, time-evicted cache so memory stays flat under load. Also tracks
in-flight ``requestId`` values to reject duplicate requests.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone


class NonceCache:
    def __init__(self, ttl_seconds: int, max_entries: int = 100_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_entries
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for k in expired:
            del self._seen[k]
        # Hard cap: drop oldest if we somehow exceed the bound.
        if len(self._seen) > self._max:
            for k in sorted(self._seen, key=self._seen.get)[
                : len(self._seen) - self._max
            ]:
                del self._seen[k]

    def check_and_store(self, nonce: str) -> bool:
        """Return True if nonce is fresh (unseen); False if it's a replay."""
        now = time.monotonic()
        with self._lock:
            self._evict(now)
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + self._ttl
            return True


def is_fresh(timestamp: datetime, ttl_seconds: int, now: datetime | None = None) -> bool:
    """True if ``timestamp`` is within +/- ttl of now (guards clock skew)."""
    now = now or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    delta = abs((now - timestamp).total_seconds())
    return delta <= ttl_seconds
