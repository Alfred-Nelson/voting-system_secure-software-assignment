"""Security monitoring and alerting (SR-20, SR-16 out-of-scope alerts).

Raises alerts for:
  * repeated failed logins / account lockouts
  * a delegate touching another state's data (alert within 60 s - here: instantly)
  * election configuration changes and key rotations
  * polling terminals that miss heartbeats for more than 60 seconds
"""


class Monitor:
    def __init__(self, dbs, audit, cfg):
        self.dbs = dbs
        self.audit = audit
        self.cfg = cfg
