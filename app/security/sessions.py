"""Server-side sessions with idle timeout (SR-02).

Tokens are 256-bit random values. Only their SHA-256 hash is stored, so a
leaked database does not leak usable session tokens.
"""
import hashlib
import secrets
import time

PRIVILEGED_ROLES = {"employee", "delegate", "admin", "auditor"}


class SessionStore:
    def __init__(self, dbs, cfg):
        self.dbs = dbs
        self.cfg = cfg

    @staticmethod
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def create(self, subject_type, subject_id, username, role, state=None):
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self.dbs.connect("identity") as conn:
            # one active session per account
            conn.execute("DELETE FROM sessions WHERE subject_type = ? AND subject_id = ?",
                         (subject_type, subject_id))
            conn.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                         (self._hash(token), subject_type, subject_id, username, role, state,
                          now, now))
        return token

    def timeout_for(self, role):
        return (self.cfg.PRIVILEGED_IDLE_TIMEOUT_SEC if role in PRIVILEGED_ROLES
                else self.cfg.VOTER_IDLE_TIMEOUT_SEC)

    def validate(self, token, now=None):
        """Returns (session, None) or (None, reason)."""
        if not token:
            return None, "missing token"
        now = now or time.time()
        h = self._hash(token)
        with self.dbs.connect("identity") as conn:
            row = conn.execute("SELECT * FROM sessions WHERE token_hash = ?", (h,)).fetchone()
            if not row:
                return None, "invalid session"
            if now - row["last_active"] > self.timeout_for(row["role"]):
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (h,))
                return None, "session expired after inactivity"
            conn.execute("UPDATE sessions SET last_active = ? WHERE token_hash = ?", (now, h))
        return dict(row), None
