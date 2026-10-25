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

    def list(self):
        with self.dbs.connect("identity") as conn:
            reqs = [dict(r) for r in conn.execute(
                "SELECT * FROM approval_requests ORDER BY id DESC")]
            for r in reqs:
                r["approvals"] = [a["approver"] for a in conn.execute(
                    "SELECT approver FROM approvals WHERE request_id = ? ORDER BY ts", (r["id"],))]
        return reqs

    def approve(self, request_id, user):
        with self.dbs.transaction("identity") as conn:
            req = conn.execute("SELECT * FROM approval_requests WHERE id = ?",
                               (request_id,)).fetchone()
            if not req:
                raise VotingError("request not found", 404)
            if req["status"] != "pending":
                raise VotingError(f"request already {req['status']}", 409)
            if (req["action"] == "exclude_candidate" and user["role"] == "delegate"
                    and self.election.candidate_state(req["target"]) != user["state"]):
                raise VotingError("delegates can only approve exclusions in their own "
                                  "state/territory", 403)
            if req["requested_by"] == user["username"]:
                raise VotingError("the requester cannot approve their own request", 403)
            existing = [r["approver"] for r in conn.execute(
                "SELECT approver FROM approvals WHERE request_id = ?", (request_id,))]
            if user["username"] in existing:
                raise VotingError("you have already approved this request", 409)
            conn.execute("INSERT INTO approvals VALUES (?,?,?)",
                         (request_id, user["username"], time.time()))
            approvals = existing + [user["username"]]
            ready = len(approvals) >= REQUIRED_APPROVALS
            if ready:
                conn.execute("UPDATE approval_requests SET status = 'approved' WHERE id = ?",
                             (request_id,))
        self.audit.record("dual_auth.approved", user["username"], user["role"],
                          {"request_id": request_id, "approvals": approvals})
        if ready:
            return {"status": "executed", "approvals": approvals,
                    "outcome": self._execute(dict(req), approvals)}
        return {"status": "pending", "approvals": approvals,
                "needed": REQUIRED_APPROVALS - len(approvals)}

    def _execute(self, req, approvals):
        if req["action"] == "exclude_candidate":
            with self.dbs.connect("ballot") as conn:
                conn.execute("UPDATE candidates SET excluded = 1 WHERE id = ?", (req["target"],))
            self.audit.record("candidate.excluded", "dual-auth", "system",
                              {"candidate": req["target"], "approved_by": approvals,
                               "request_id": req["id"]})
            return f"candidate {self.election.candidate_label(req['target'])} excluded"
        result = self.election.run_tally("dual-auth:" + "+".join(approvals), "system",
                                         recount=True)
        elected = result["result"]["elected"]
        return {"recount_elected": elected,
                "recount_elected_names": [self.election.candidate_label(c) for c in elected]}
