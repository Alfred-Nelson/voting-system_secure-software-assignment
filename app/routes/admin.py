"""Staff endpoints. Every route is protected by RBAC (SR-16) and requires an
MFA session (SR-02); every state change is audited (SR-18)."""
from flask import Blueprint, g, jsonify

from ..security.rbac import enforce_state_scope, require
from ..voting.service import VotingError
from . import body, svc

bp = Blueprint("admin", __name__, url_prefix="/api")


def _err(exc):
    return jsonify(error=str(exc)), getattr(exc, "status", 400)


def _actor():
    return g.user["username"], g.user["role"]


# ---------------------------------------------------------------- election control
@bp.post("/admin/election/status")
@require("election.configure")
def set_status():
    try:
        svc().election.set_status(str(body().get("status", "")), *_actor())
        return jsonify(status=svc().election.status())
    except VotingError as exc:
        return _err(exc)


# ---------------------------------------------------------------- candidates (SR-16 scope)
@bp.put("/admin/candidates/<cid>")
@require("candidates.edit")
def edit_candidate(cid):
    state = svc().election.candidate_state(cid)
    if state is None:
        return jsonify(error="candidate not found"), 404
    denied = enforce_state_scope(state)
    if denied:
        return denied
    try:
        d = body()
        fields = {k: str(v)[:120] for k, v in d.items() if k in ("name", "party")}
        svc().election.update_candidate(cid, fields, *_actor())
        return jsonify(ok=True)
    except VotingError as exc:
        return _err(exc)


# ---------------------------------------------------------------- dual authorisation (SR-17)
@bp.post("/admin/approvals")
@require("approval.request")
def request_approval():
    d = body()
    try:
        rid = svc().approvals.request(str(d.get("action", "")), d.get("target"),
                                      str(d.get("reason", "")), g.user)
        return jsonify(request_id=rid), 201
    except VotingError as exc:
        return _err(exc)


@bp.get("/admin/approvals")
@require("approval.request")
def list_approvals():
    return jsonify(requests=svc().approvals.list())


@bp.post("/admin/approvals/<int:rid>/approve")
@require("approval.approve")
def approve(rid):
    try:
        return jsonify(svc().approvals.approve(rid, g.user))
    except VotingError as exc:
        return _err(exc)


# ---------------------------------------------------------------- polling station (SR-04)
@bp.post("/station/mark-voted")
@require("station.mark_voted")
def mark_voted():
    d = body()
    try:
        svc().election.mark_offline_vote(str(d.get("enrolment_id", "")),
                                         str(d.get("channel", "station")), g.user["username"])
        return jsonify(ok=True)
    except VotingError as exc:
            return _err(exc)

@bp.post("/admin/tally")
@require("tally.run")
def run_tally():
    try:
        return jsonify(svc().election.run_tally(*_actor()))
    except VotingError as exc:
        return _err(exc)
