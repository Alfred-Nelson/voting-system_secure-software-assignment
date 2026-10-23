"""Staff endpoints. Every route is protected by RBAC (SR-16) and requires an
MFA session (SR-02); every state change is audited (SR-18)."""
from flask import Blueprint, g, jsonify

from ..security.rbac import require
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
