"""Role-based access control with least privilege (SR-16)."""
from flask import request

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
