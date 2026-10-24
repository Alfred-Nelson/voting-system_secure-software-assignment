"""SR-16 role-based access control and least privilege."""
import pytest

from app.security.rbac import ROLE_PERMISSIONS, has_permission


def test_permission_matrix_separation_of_duties():
    assert not has_permission("admin", "audit.view")         # admins can't read/alter audit
    assert not has_permission("auditor", "tally.run")        # auditors can't change the election
    assert not has_permission("voter", "station.mark_voted")
    assert not has_permission("employee", "approval.approve")
    assert not has_permission("delegate", "keys.rotate")
    assert all(p for p in ROLE_PERMISSIONS.values())


def test_unauthenticated_requests_rejected(http):
    assert http.get("/api/audit").status_code == 401
    assert http.post("/api/admin/tally").status_code == 401


@pytest.mark.parametrize("user,method,path", [
    ("admin1", "get", "/api/audit"),
    ("auditor1", "post", "/api/admin/tally"),
    ("officer1", "post", "/api/admin/keys/rotate"),
    ("delegate_nsw1", "post", "/api/admin/election/status"),
])
def test_forbidden_actions_denied_and_audited(h, http, svc, user, method, path):
    r = getattr(http, method)(path, headers=h.staff(user), json={})
    assert r.status_code == 403
    assert any(e["action"] == "access.denied" and e["actor"] == user for e in svc.audit.entries())


def test_voter_cannot_use_staff_endpoints(h, http):
    v = h.voter("NSW1000001")
    r = http.get("/api/admin/alerts", headers={"Authorization": "Bearer " + v.token})
    assert r.status_code == 403


def test_delegate_limited_to_own_state_with_alert(h, http, svc):
    hdr = h.staff("delegate_nsw1")
    assert http.put("/api/admin/candidates/A1", json={"name": "Mia T."}, headers=hdr).status_code == 200
    r = http.put("/api/admin/candidates/V1", json={"name": "Hacked"}, headers=hdr)
    assert r.status_code == 403
    assert any(a["kind"] == "rbac.out_of_scope" for a in svc.monitor.alerts())


def test_candidate_edit_records_before_and_after(h, http, svc):
    http.put("/api/admin/candidates/A2", json={"party": "New Party"}, headers=h.staff("delegate_nsw1"))
    entry = next(e for e in svc.audit.entries() if e["action"] == "candidate.updated")
    assert '"before"' in entry["details"] and '"New Party"' in entry["details"]
