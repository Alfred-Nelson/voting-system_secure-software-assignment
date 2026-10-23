"""Voter-facing endpoints.

/api/voter/*   authenticated (identity side): eligibility + blind credential
/api/ballots   ANONYMOUS (ballot side): no session token is accepted or logged,
               so the server cannot connect a ballot to a login (SR-07).
"""
import ipaddress

from flask import Blueprint, g, jsonify, request

from ..security.ratelimit import limit
from ..security.rbac import require
from ..voting.service import VotingError
from . import body, svc

bp = Blueprint("ballots", __name__)


def _err(exc: VotingError):
    return jsonify(error=str(exc)), exc.status


def mission_network_ok():
    """SR-24: requests from overseas-mission terminals must come from the
    mission's registered network."""
    tid = request.headers.get("X-Terminal-Id", "")
    if not tid.startswith("MISSION-"):
        return True
    try:
        ip = ipaddress.ip_address(request.remote_addr or "0.0.0.0")  # nosec B104
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n.strip()) for n in svc().cfg.MISSION_ALLOWED_NETWORKS)


@bp.get("/api/election")
def election_info():
    return jsonify(svc().election.public_info())


@bp.post("/api/voter/credential")
@require("credential.request")
def request_credential():
    try:
        sig = svc().election.issue_credential(g.user["subject_id"], body().get("blinded"))
        return jsonify(blind_signature=sig)
    except VotingError as exc:
        return _err(exc)


@bp.post("/api/ballots")
@limit("ballot", "BALLOT_LIMIT_PER_MIN")
def submit_ballot():
    if request.headers.get("Authorization"):
        # Refuse identified submissions outright - protects voters from a buggy client
        return jsonify(error="ballots must be submitted anonymously (no Authorization header)"), 400
    if not mission_network_ok():
        svc().audit.record("mission.network_denied", request.headers.get("X-Terminal-Id"),
                           "terminal", {"ip": request.remote_addr})
        svc().monitor.alert("high", "mission.network",
                            "Mission terminal used from an unregistered network")
        return jsonify(error="terminal not on registered mission network"), 403
    d = body()
    try:
        receipt = svc().election.submit_ballot(d.get("credential"), d.get("token"),
                                               d.get("envelope"), d.get("signature"))
        return jsonify(receipt), 201
    except VotingError as exc:
        return _err(exc)


@bp.get("/api/bulletin")
def bulletin():
    return jsonify(receipts=svc().election.bulletin())


@bp.get("/api/bulletin/<code>")
def check_receipt(code):
    if len(code) > 40:
        return jsonify(error="bad receipt code"), 400
    return jsonify(svc().election.check_receipt(code))
