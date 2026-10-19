"""Tamper-evident audit logging (SR-18, SR-19).

Every entry records who, when, what and before/after values. Entries are
hash-chained (each entry hash covers the previous one) and each entry carries
an HMAC-SHA256 tag produced inside the KeyManager. Editing, deleting or
re-ordering any entry breaks verification. The table itself refuses UPDATE and
DELETE (SQL triggers in db.py).

Ballot contents and anything that could link a voter to a ballot are never
written to the audit log (SR-07).
"""
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

    def verify_chain(self):
        """Returns {'ok': bool, 'entries': n, 'first_bad_seq': seq|None, 'reason': str}"""
        prev = GENESIS
        count = 0
        with self.dbs.connect("audit") as conn:
            for row in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
                count += 1
                if row["prev_hash"] != prev:
                    return {"ok": False, "entries": count, "first_bad_seq": row["seq"],
                            "reason": "chain broken (entry removed or re-ordered)"}
                expected = self._entry_hash(prev, row["ts"], row["actor"], row["role"],
                                            row["action"], row["details"])
                if expected != row["entry_hash"]:
                    return {"ok": False, "entries": count, "first_bad_seq": row["seq"],
                            "reason": "entry content modified"}
                if not self.keys.mac_verify(row["entry_hash"].encode(), row["mac_version"], row["mac"]):
                    return {"ok": False, "entries": count, "first_bad_seq": row["seq"],
                            "reason": "MAC invalid (entry forged)"}
                prev = row["entry_hash"]
        return {"ok": True, "entries": count, "first_bad_seq": None, "reason": "intact"}

    def entries(self, limit=200):
        with self.dbs.connect("audit") as conn:
            rows = conn.execute("SELECT seq, ts, actor, role, action, details, entry_hash "
                                "FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]
