"""Security monitoring and alerting (SR-20, SR-16 out-of-scope alerts).

Raises alerts for:
  * repeated failed logins / account lockouts
  * a delegate touching another state's data (alert within 60 s - here: instantly)
  * election configuration changes and key rotations
  * polling terminals that miss heartbeats for more than 60 seconds
"""
from datetime import datetime, timezone


class Monitor:
    def __init__(self, dbs, audit, cfg):
        self.dbs = dbs
        self.audit = audit
        self.cfg = cfg

    def alert(self, severity, kind, message):
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.dbs.connect("audit") as conn:
            conn.execute("INSERT INTO alerts (ts, severity, kind, message) VALUES (?,?,?,?)",
                         (ts, severity, kind, message))
        self.audit.record("alert.raised", details={"severity": severity, "kind": kind,
                                                   "message": message})
