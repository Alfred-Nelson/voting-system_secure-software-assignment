"""SR-20 alert handling endpoints."""
import time


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


# ---------------------------------------------------------------- GET /api/admin/terminals
def _set_heartbeat(svc, terminal_id, age_sec):
    with svc.dbs.connect("identity") as conn:
        conn.execute("UPDATE terminals SET status = 'online', last_heartbeat = ? WHERE id = ?",
                     (time.time() - age_sec, terminal_id))


def test_terminals_endpoint_runs_offline_check_first(h, http, svc):
    _set_heartbeat(svc, "PS-SYD-001", 30)            # recent heartbeat: stays online
    _set_heartbeat(svc, "MISSION-LON-01", 120)       # missed heartbeats: must go offline
    r = http.get("/api/admin/terminals", headers=h.staff("admin1"))
    assert r.status_code == 200
    status = {t["id"]: t["status"] for t in r.get_json()["terminals"]}
    assert status == {"PS-SYD-001": "online", "MISSION-LON-01": "offline"}
    alert = next(a for a in svc.monitor.alerts() if a["kind"] == "terminal.offline")
    assert alert["severity"] == "critical" and "MISSION-LON-01" in alert["message"]


def test_terminals_permissions(h, http, svc):
    assert http.get("/api/admin/terminals").status_code == 401
    assert http.get("/api/admin/terminals", headers=h.staff("officer1")).status_code == 200
    for user in ("auditor1", "delegate_nsw1"):
        assert http.get("/api/admin/terminals", headers=h.staff(user)).status_code == 403
    assert any(e["action"] == "access.denied" and e["actor"] == "auditor1"
               for e in svc.audit.entries())
