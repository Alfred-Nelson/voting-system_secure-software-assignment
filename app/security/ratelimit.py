"""Sliding-window rate limiter (SR-14 results API, SR-21 application-layer
flood protection). Network-level DDoS protection (50 Gbps scrubbing, CDN)
is an infrastructure control - see the report."""
import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, bucket, key, limit, window=60.0, now=None):
        now = now or time.monotonic()
        with self._lock:
            q = self._hits[(bucket, key)]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True
