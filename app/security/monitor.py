"""Security monitoring and alerting (SR-20, SR-16 out-of-scope alerts).

Raises alerts for:
  * repeated failed logins / account lockouts
  * a delegate touching another state's data (alert within 60 s - here: instantly)
  * election configuration changes and key rotations
  * polling terminals that miss heartbeats for more than 60 seconds
"""
import time
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

    def alerts(self, include_ack=False):
        sql = ("SELECT * FROM alerts ORDER BY id DESC LIMIT 200" if include_ack else
               "SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY id DESC LIMIT 200")
        with self.dbs.connect("audit") as conn:
            return [dict(r) for r in conn.execute(sql)]

    def acknowledge(self, alert_id, actor):
        with self.dbs.connect("audit") as conn:
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        self.audit.record("alert.acknowledged", actor, "staff", {"alert_id": alert_id})

    # ---- terminals
    def heartbeat(self, terminal_id):
        with self.dbs.connect("identity") as conn:
            cur = conn.execute("UPDATE terminals SET last_heartbeat = ?, status = 'online' "
                               "WHERE id = ?", (time.time(), terminal_id))
            return cur.rowcount == 1
