"""SR-17 dual authorisation for candidate exclusion and recounts."""


def _request(http, h, action="exclude_candidate", target="U1", user="officer1"):
    r = http.post("/api/admin/approvals", json={"action": action, "target": target,
                                                "reason": "s.44 ineligibility"}, headers=h.staff(user))
    assert r.status_code == 201, r.get_json()
    return r.get_json()["request_id"]


def _excluded(svc, cid):
    with svc.dbs.connect("ballot") as c:
        return c.execute("SELECT excluded FROM candidates WHERE id = ?", (cid,)).fetchone()[0] == 1


def test_two_distinct_delegates_required(h, http, svc):
    rid = _request(http, h)
    r = http.post(f"/api/admin/approvals/{rid}/approve", headers=h.staff("delegate_nsw1")).get_json()
    assert r["status"] == "pending" and not _excluded(svc, "U1")
    r = http.post(f"/api/admin/approvals/{rid}/approve", headers=h.staff("delegate_nsw2")).get_json()
    assert r["status"] == "executed" and _excluded(svc, "U1")
    actions = [e for e in svc.audit.entries() if e["action"] == "candidate.excluded"]
    assert '"delegate_nsw1"' in actions[0]["details"] and '"delegate_nsw2"' in actions[0]["details"]


def test_same_delegate_cannot_approve_twice(h, http):
    rid = _request(http, h)
    hdr = h.staff("delegate_nsw1")
    http.post(f"/api/admin/approvals/{rid}/approve", headers=hdr)
    r = http.post(f"/api/admin/approvals/{rid}/approve", headers=hdr)
    assert r.status_code == 409


def test_requester_cannot_approve_own_request(h, http):
    rid = _request(http, h, user="delegate_nsw1")
    r = http.post(f"/api/admin/approvals/{rid}/approve", headers=h.staff("delegate_nsw1"))
    assert r.status_code == 403


def test_employee_cannot_approve(h, http):
    rid = _request(http, h)
    assert http.post(f"/api/admin/approvals/{rid}/approve",
                     headers=h.staff("officer1")).status_code == 403
