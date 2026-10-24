"""Staff endpoints. Every route is protected by RBAC (SR-16) and requires an
MFA session (SR-02); every state change is audited (SR-18)."""
from flask import Blueprint, g, jsonify

from ..security.crypto import CryptoError
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


# ---------------------------------------------------------------- keys (SR-26)
@bp.get("/admin/keys")
@require("keys.view")
def key_status():
    return jsonify(keys=svc().keys.key_status(), rotation_due=svc().keys.needs_rotation())


@bp.post("/admin/keys/rotate")
@require("keys.rotate")
def rotate_key():
    d = body()
    try:
        version = svc().keys.rotate(str(d.get("purpose", "")), g.user["username"],
                                    str(d.get("reason", "manual")))
        svc().monitor.alert("info", "keys.rotated", f"{d.get('purpose')} rotated to v{version}")
        return jsonify(purpose=d.get("purpose"), version=version)
    except (CryptoError, KeyError) as exc:
        return jsonify(error=str(exc)), 400


# ---------------------------------------------------------------- monitoring (SR-20)
@bp.get("/admin/alerts")
@require("alerts.view")
def alerts():
    return jsonify(alerts=svc().monitor.alerts())


@bp.post("/admin/alerts/<int:alert_id>/ack")
@require("alerts.ack")
def ack_alert(alert_id):
    svc().monitor.acknowledge(alert_id, g.user["username"])
    return jsonify(ok=True)


@bp.get("/admin/terminals")
@require("terminal.view")
def terminals():
    svc().monitor.check_terminals()
    with svc().dbs.connect("identity") as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM terminals ORDER BY id")]
    return jsonify(terminals=rows)


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


# ---------------------------------------------------------------- tally
@bp.post("/admin/tally")
@require("tally.run")
def run_tally():
    try:
        return jsonify(svc().election.run_tally(*_actor()))
    except VotingError as exc:
        return _err(exc)


# ---------------------------------------------------------------- auditor (SR-11, SR-19)
@bp.get("/audit")
@require("audit.view")
def audit_entries():
    return jsonify(entries=svc().audit.entries())


@bp.get("/audit/verify")
@require("audit.verify")
def audit_verify():
    result = svc().audit.verify_chain()
    if not result["ok"]:
        svc().monitor.alert("critical", "audit.tamper", result["reason"])
    return jsonify(result)


@bp.get("/ledger/verify")
@require("ledger.verify")
def ledger_verify():
    result = svc().ledger.verify()
    if not result["ok"]:
        svc().monitor.alert("critical", "ledger.tamper", "; ".join(result["problems"]))
    return jsonify(result)
