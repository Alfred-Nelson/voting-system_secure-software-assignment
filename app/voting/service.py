"""Election service - the voting subsystem's business logic.

Flow:
  identity side  : login (MFA) -> eligibility check -> double-vote check ->
                   blind-sign the voter's anonymous credential
"""
from datetime import date

from ..security import blind
from .ledger import ballot_hash


class VotingError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _age(dob_iso, today=None):
    today = today or date.today()
    d = date.fromisoformat(dob_iso)
    return today.year - d.year - ((today.month, today.day) < (d.month, d.day))


class ElectionService:
    def __init__(self, dbs, keys, audit, monitor, ledger, cfg):
        self.dbs, self.keys, self.audit = dbs, keys, audit
        self.monitor, self.ledger, self.cfg = monitor, ledger, cfg

    # ------------------------------------------------------------ election config
    def get(self, key, default=None):
        with self.dbs.connect("ballot") as conn:
            row = conn.execute("SELECT value FROM election WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set(self, key, value):
        with self.dbs.connect("ballot") as conn:
            conn.execute("INSERT INTO election (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def status(self):
        return self.get("status", "setup")

    def set_status(self, new_status, actor, role):
        allowed = {"setup": {"open"}, "open": {"closed"}, "closed": set()}
        old = self.status()
        if new_status not in allowed.get(old, set()):
            raise VotingError(f"cannot change election from '{old}' to '{new_status}'")
        self.set("status", new_status)
        self.audit.record("election.status_changed", actor, role,
                          {"before": old, "after": new_status})
        self.monitor.alert("info", "config.change",
                           f"Election status changed {old} -> {new_status} by {actor}")
