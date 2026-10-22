"""Role-based access control with least privilege (SR-16)."""
from functools import wraps

from flask import current_app, g, jsonify, request

ROLE_PERMISSIONS = {
    "voter": {"ballot.view", "credential.request"},
    "employee": {"station.mark_voted", "approval.request", "terminal.view", "alerts.view"},
    "delegate": {"candidates.edit", "approval.request", "approval.approve", "alerts.view"},
    "admin": {"election.configure", "tally.run", "results.publish", "keys.rotate",
              "keys.view", "alerts.view", "alerts.ack", "terminal.view", "backup.run"},
    "auditor": {"audit.view", "audit.verify", "ledger.verify", "alerts.view", "keys.view"},
}


def has_permission(role, permission):
    return permission in ROLE_PERMISSIONS.get(role, set())


def _bearer():
    header = request.headers.get("Authorization", "")
    return header[7:] if header.startswith("Bearer ") else None


def require(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            svc = current_app.evote
            session, reason = svc.sessions.validate(_bearer())
            if not session:
                return jsonify(error=reason), 401
            g.user = session
            if not has_permission(session["role"], permission):
                svc.audit.record("access.denied", session["username"], session["role"],
                                 {"permission": permission, "path": request.path})
                return jsonify(error="forbidden"), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def enforce_state_scope(target_state):
    """Call inside a handler after @require. Returns an error response or None."""
    user = g.user
    if user["role"] == "delegate" and user["state"] != target_state:
        svc = current_app.evote
        svc.audit.record("access.out_of_scope", user["username"], user["role"],
                         {"own_state": user["state"], "target_state": target_state,
                          "path": request.path})
        svc.monitor.alert("high", "rbac.out_of_scope",
                          f"Delegate {user['username']} ({user['state']}) tried to modify "
                          f"{target_state} data")
        return jsonify(error="forbidden: outside your state/territory"), 403
    return None
