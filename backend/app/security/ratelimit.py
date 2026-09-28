"""Simple fixed-window rate limiter, keyed by device or connection id."""
from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self._limit = per_minute
        self._window = 60.0
        self._buckets: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            start, count = self._buckets.get(key, (now, 0))
            if now - start >= self._window:
                start, count = now, 0
            count += 1
            self._buckets[key] = (start, count)
            return count <= self._limit
