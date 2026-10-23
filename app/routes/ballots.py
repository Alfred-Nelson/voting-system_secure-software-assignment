"""Voter-facing endpoints.

/api/voter/*   authenticated (identity side): eligibility + blind credential
"""
from flask import Blueprint, g, jsonify

from ..security.rbac import require
from ..voting.service import VotingError
from . import body, svc

bp = Blueprint("ballots", __name__)


def _err(exc: VotingError):
    return jsonify(error=str(exc)), exc.status


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
