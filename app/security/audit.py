"""Tamper-evident audit logging (SR-18, SR-19)."""
import hashlib
import json
import threading
from datetime import datetime, timezone

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

    def record(self, action, actor="system", role="system", details=None):
        details_json = json.dumps(details or {}, sort_keys=True, default=str)
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        with _lock, self.dbs.transaction("audit") as conn:
            row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["entry_hash"] if row else GENESIS
            entry_hash = self._entry_hash(prev, ts, actor, role, action, details_json)
            mac_version, mac = self.keys.mac(entry_hash.encode())
            conn.execute(
                "INSERT INTO audit_log (ts, actor, role, action, details, prev_hash, entry_hash,"
                " mac_version, mac) VALUES (?,?,?,?,?,?,?,?,?)",
                (ts, actor, role, action, details_json, prev, entry_hash, mac_version, mac))
        return entry_hash
