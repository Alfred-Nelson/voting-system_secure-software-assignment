"""Login / logout (SR-01, SR-02)."""
from flask import Blueprint, g, jsonify, request

from ..security.auth import AuthError
from ..security.ratelimit import limit
from ..security.rbac import _bearer
from . import body, svc

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@bp.post("/voter/login")
@limit("login", "LOGIN_LIMIT_PER_MIN")
def voter_login():
    d = body()
    try:
        return jsonify(svc().auth.voter_login(str(d.get("enrolment_id", "")),
                                              str(d.get("password", "")),
                                              str(d.get("totp", ""))))
    except AuthError as exc:
        return jsonify(error=str(exc)), 401


@bp.post("/staff/login")
@limit("login", "LOGIN_LIMIT_PER_MIN")
def staff_login():
    d = body()
    try:
        return jsonify(svc().auth.staff_login(str(d.get("username", "")),
                                              str(d.get("password", "")),
                                              str(d.get("totp", ""))))
    except AuthError as exc:
        return jsonify(error=str(exc)), 401


@bp.post("/logout")
def logout():
    token = _bearer()
    if token:
        session, _ = svc().sessions.validate(token)
        svc().sessions.destroy(token)
        if session:
            svc().audit.record("auth.logout", session["username"], session["role"], {})
    return jsonify(ok=True)


@bp.get("/me")
def me():
    session, reason = svc().sessions.validate(_bearer())
    if not session:
        return jsonify(error=reason), 401
    return jsonify(username=session["username"], role=session["role"], state=session["state"],
                   idle_timeout_sec=svc().sessions.timeout_for(session["role"]))
