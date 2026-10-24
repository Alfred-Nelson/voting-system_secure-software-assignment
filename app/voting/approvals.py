"""Dual authorisation (SR-17).

A manual candidate exclusion or a recount is only a *request* until two
different Commissioner's delegates - neither of them the requester, both
logged in with MFA - approve it. Only then is it executed. Every step is
audited, so the audit log always shows two distinct approvals.
"""
import time

from .service import VotingError

ACTIONS = {"exclude_candidate", "recount"}
REQUIRED_APPROVALS = 2


class ApprovalService:
    def __init__(self, dbs, audit, election):
        self.dbs, self.audit, self.election = dbs, audit, election

    def request(self, action, target, reason, user):
        if action not in ACTIONS:
            raise VotingError(f"action must be one of {sorted(ACTIONS)}")
        if not reason or len(reason) < 5:
            raise VotingError("a reason is required")
        if action == "exclude_candidate" and not self.election.candidate_state(target):
            raise VotingError("unknown candidate", 404)
        with self.dbs.connect("identity") as conn:
            rid = conn.execute("INSERT INTO approval_requests (action, target, reason, "
                               "requested_by, created) VALUES (?,?,?,?,?)",
                               (action, target, reason, user["username"], time.time())).lastrowid
        self.audit.record("dual_auth.requested", user["username"], user["role"],
                          {"request_id": rid, "action": action, "target": target,
                           "reason": reason})
        return rid
