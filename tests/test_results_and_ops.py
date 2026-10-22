"""Election status rules and general hardening (results, backup and monitoring tests are added in later issues)."""


def test_election_status_transitions_enforced(h, http):
    adm = h.staff("admin1")
    r = http.post("/api/admin/election/status", json={"status": "closed"}, headers=adm)
    assert r.status_code == 400                       # can't close before opening
    r = http.post("/api/admin/election/status", json={"status": "tallied"}, headers=adm)
    assert r.status_code == 400                       # only the count may set 'tallied'
