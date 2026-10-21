"""Sliding-window rate limiter (SR-14 results API, SR-21 application-layer
flood protection). Network-level DDoS protection (50 Gbps scrubbing, CDN)
is an infrastructure control - see the report."""
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, jsonify, request


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


def limit(bucket, config_attr, key_fn=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            svc = current_app.evote
            key = key_fn() if key_fn else (request.remote_addr or "unknown")
            if not svc.limiter.allow(bucket, key, getattr(svc.cfg, config_attr)):
                return jsonify(error="rate limit exceeded"), 429
            return fn(*args, **kwargs)
        return wrapper
    return decorator
