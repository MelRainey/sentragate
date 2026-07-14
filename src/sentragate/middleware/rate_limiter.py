"""
Per-identity rate limiting.

A simple in-memory sliding window keyed on the verified subject (never on
IP alone, since IP is not an identity signal we trust). This is intentionally
minimal: a single-process demo limiter. A production deployment behind more
than one gateway instance needs a shared store (Redis, etc.) instead, called
out explicitly in docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self, limit_per_minute: int) -> None:
        self.limit_per_minute = limit_per_minute
        self._hits: dict[str, deque] = defaultdict(deque)

    def allow(self, subject: str) -> bool:
        now = time.time()
        window_start = now - 60
        hits = self._hits[subject]

        while hits and hits[0] < window_start:
            hits.popleft()

        if len(hits) >= self.limit_per_minute:
            return False

        hits.append(now)
        return True
