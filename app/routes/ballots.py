"""Voter-facing endpoints.

/api/voter/*   authenticated (identity side): eligibility + blind credential
"""
import ipaddress

from flask import Blueprint, g, jsonify, request

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
