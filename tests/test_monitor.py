"""SR-20 alert handling endpoints."""


# ---------------------------------------------------------------- GET /api/admin/alerts, POST .../ack
def test_alerts_list_and_acknowledge(h, http, svc):
    svc.monitor.alert("critical", "test.alert", "something happened")
    adm = h.staff("admin1")

    r = http.get("/api/admin/alerts", headers=adm)
    assert r.status_code == 200
    found = [a for a in r.get_json()["alerts"] if a["kind"] == "test.alert"]
    assert len(found) == 1 and found[0]["severity"] == "critical"

    r = http.post(f"/api/admin/alerts/{found[0]['id']}/ack", headers=adm)
    assert r.status_code == 200 and r.get_json() == {"ok": True}
    assert not any(a["kind"] == "test.alert" for a in
                   http.get("/api/admin/alerts", headers=adm).get_json()["alerts"])
    assert any(e["action"] == "alert.acknowledged" and e["actor"] == "admin1"
               for e in svc.audit.entries())


def test_alerts_permissions(h, http, svc):
    svc.monitor.alert("medium", "test.alert", "x")
    alert_id = svc.monitor.alerts()[0]["id"]
    assert http.get("/api/admin/alerts").status_code == 401
    assert http.post(f"/api/admin/alerts/{alert_id}/ack").status_code == 401
    for user in ("officer1", "delegate_nsw1", "auditor1"):          # may view
        assert http.get("/api/admin/alerts", headers=h.staff(user)).status_code == 200
        r = http.post(f"/api/admin/alerts/{alert_id}/ack", headers=h.staff(user))
        assert r.status_code == 403                                 # but only admins acknowledge
    assert any(a["id"] == alert_id for a in svc.monitor.alerts())   # still unacknowledged
    assert any(e["action"] == "access.denied" and e["actor"] == "auditor1"
               for e in svc.audit.entries())
