"""SR-16 role-based access control and least privilege."""
from app.security.rbac import ROLE_PERMISSIONS, has_permission


def test_permission_matrix_separation_of_duties():
    assert not has_permission("admin", "audit.view")         # admins can't read/alter audit
    assert not has_permission("auditor", "tally.run")        # auditors can't change the election
    assert not has_permission("voter", "station.mark_voted")
    assert not has_permission("employee", "approval.approve")
    assert not has_permission("delegate", "keys.rotate")
    assert all(p for p in ROLE_PERMISSIONS.values())
