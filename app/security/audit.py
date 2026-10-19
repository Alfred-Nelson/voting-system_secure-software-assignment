"""Tamper-evident audit logging (SR-18, SR-19)."""
import hashlib
import threading

from ..security.crypto import canonical_json

GENESIS = "0" * 64
_lock = threading.Lock()


class AuditLog:
    def __init__(self, dbs, keys):
        self.dbs = dbs
        self.keys = keys

    @staticmethod
    def _entry_hash(prev_hash, ts, actor, role, action, details_json):
        body = canonical_json([prev_hash, ts, actor, role, action, details_json])
        return hashlib.sha256(body).hexdigest()
