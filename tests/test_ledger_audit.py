"""SR-11 ballot ledger, SR-18/SR-19 tamper-evident audit log."""
import json
import sqlite3

import pytest


def _vote_and_close(h, http, n=4):
    h.open_polls()
    for i in range(1, n + 1):
        h.voter(f"NSW100000{i}").cast({"atl": {"A": 1, "B": 2}})
    adm = h.staff("admin1")
    http.post("/api/admin/election/status", json={"status": "closed"}, headers=adm)
    return adm


def test_ledger_verifies_and_has_batch_checksums(h, http, svc):
    _vote_and_close(h, http, 4)
    res = svc.ledger.verify()
    assert res["ok"] and res["ledger_entries"] == 4
    with svc.dbs.connect("ballot") as c:
        kinds = [r[0] for r in c.execute("SELECT kind FROM ledger ORDER BY seq")]
    assert kinds.count("batch") == 1          # batch size 3 in tests


def test_ledger_is_append_only(h, http, svc):
    _vote_and_close(h, http, 1)
    with sqlite3.connect(svc.dbs.paths["ballot"]) as c:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            c.execute("DELETE FROM ledger")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            c.execute("UPDATE ledger SET item_hash = 'x'")


def test_modified_ballot_blocks_the_count(h, http, svc):
    adm = _vote_and_close(h, http, 3)
    with sqlite3.connect(svc.dbs.paths["ballot"]) as c:
        bid, env = c.execute("SELECT id, envelope FROM ballots LIMIT 1").fetchone()
        e = json.loads(env)
        e["iv"] = "AAAAAAAAAAAAAAAA"
        c.execute("UPDATE ballots SET envelope = ? WHERE id = ?", (json.dumps(e), bid))
    assert not svc.ledger.verify()["ok"]
    r = http.post("/api/admin/tally", headers=adm)
    assert r.status_code == 409 and "integrity" in r.get_json()["error"]
    assert any(a["kind"] == "ledger.tamper" for a in svc.monitor.alerts())


def test_deleted_ballot_detected(h, http, svc):
    _vote_and_close(h, http, 2)
    with sqlite3.connect(svc.dbs.paths["ballot"]) as c:
        c.execute("DELETE FROM ballots WHERE rowid = (SELECT MIN(rowid) FROM ballots)")
    res = svc.ledger.verify()
    assert not res["ok"] and any("missing" in p for p in res["problems"])


def test_injected_ballot_detected(h, http, svc):
    _vote_and_close(h, http, 1)
    with sqlite3.connect(svc.dbs.paths["ballot"]) as c:
        c.execute("INSERT INTO ballots VALUES ('x', 'c', '{}', 's', 'h', 0)")
    assert not svc.ledger.verify()["ok"]


def test_audit_log_append_only(svc, creds):
    with sqlite3.connect(svc.dbs.paths["audit"]) as c:
        with pytest.raises(sqlite3.DatabaseError):
            c.execute("UPDATE audit_log SET actor = 'x'")
        with pytest.raises(sqlite3.DatabaseError):
            c.execute("DELETE FROM audit_log")


def test_audit_chain_detects_edit_delete_and_forgery(svc, creds):
    for i in range(5):
        svc.audit.record("test.event", "tester", "admin", {"i": i})
    assert svc.audit.verify_chain()["ok"]
    path = svc.dbs.paths["audit"]
    with sqlite3.connect(path) as c:
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("DROP TRIGGER audit_no_delete")
        c.execute("UPDATE audit_log SET details = '{\"i\": 99}' WHERE seq = 3")
    res = svc.audit.verify_chain()
    assert not res["ok"] and res["first_bad_seq"] == 3


def test_audit_detects_deleted_entry(svc, creds):
    for i in range(4):
        svc.audit.record("test.event", "tester", "admin", {"i": i})
    with sqlite3.connect(svc.dbs.paths["audit"]) as c:
        c.execute("DROP TRIGGER audit_no_delete")
        c.execute("DELETE FROM audit_log WHERE seq = 2")
    assert "chain broken" in svc.audit.verify_chain()["reason"]


def test_audit_detects_recomputed_hash_without_mac_key(svc, creds):
    """An attacker who recomputes the SHA-256 chain still can't produce valid MACs."""
    from app.security.audit import AuditLog
    svc.audit.record("test.event", "tester", "admin", {})
    with sqlite3.connect(svc.dbs.paths["audit"]) as c:
        c.row_factory = sqlite3.Row
        c.execute("DROP TRIGGER audit_no_update")
        last = c.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        forged = AuditLog._entry_hash(last["prev_hash"], last["ts"], "evil", last["role"],
                                      last["action"], last["details"])
        c.execute("UPDATE audit_log SET actor = 'evil', entry_hash = ? WHERE seq = ?",
                  (forged, last["seq"]))
    res = svc.audit.verify_chain()
    assert not res["ok"] and "MAC" in res["reason"]


def test_admin_actions_are_audited_with_identity(h, http, svc):
    h.open_polls()
    entry = next(e for e in svc.audit.entries() if e["action"] == "election.status_changed")
    assert entry["actor"] == "admin1" and '"before": "setup"' in entry["details"]


# ---------------------------------------------------------------- GET /api/audit
def test_audit_endpoint_returns_latest_200_entries(h, http, svc):
    hdr = h.staff("auditor1")                  # log in first so its audit entry isn't the newest
    for i in range(205):
        svc.audit.record("test.event", "tester", "admin", {"i": i})
    r = http.get("/api/audit", headers=hdr)
    assert r.status_code == 200
    entries = r.get_json()["entries"]
    assert len(entries) == 200
    seqs = [e["seq"] for e in entries]
    assert seqs == sorted(seqs, reverse=True)                  # newest first
    assert entries[0]["action"] == "test.event" and '"i": 204' in entries[0]["details"]
    assert {"seq", "ts", "actor", "role", "action", "details", "entry_hash"} <= set(entries[0])


def test_audit_endpoint_is_auditor_only(h, http, svc):
    assert http.get("/api/audit").status_code == 401
    for user in ("admin1", "officer1", "delegate_nsw1"):
        assert http.get("/api/audit", headers=h.staff(user)).status_code == 403
    assert any(e["action"] == "access.denied" and e["actor"] == "admin1"
               for e in svc.audit.entries())


# ---------------------------------------------------------------- GET /api/audit/verify
def test_audit_verify_endpoint_intact_chain(h, http, svc):
    r = http.get("/api/audit/verify", headers=h.staff("auditor1"))
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] and data["first_bad_seq"] is None and data["entries"] > 0
    assert not any(a["kind"] == "audit.tamper" for a in svc.monitor.alerts())


def test_audit_verify_endpoint_names_first_bad_entry_and_alerts(h, http, svc):
    for i in range(5):
        svc.audit.record("test.event", "tester", "admin", {"i": i})
    hdr = h.staff("auditor1")
    with sqlite3.connect(svc.dbs.paths["audit"]) as c:
        c.execute("DROP TRIGGER audit_no_update")                 # attacker with database access
        c.execute("UPDATE audit_log SET details = '{\"i\": 99}' WHERE seq = 3")
    r = http.get("/api/audit/verify", headers=hdr)
    assert r.status_code == 200
    data = r.get_json()
    assert not data["ok"] and data["first_bad_seq"] == 3 and data["reason"]
    alert = next(a for a in svc.monitor.alerts() if a["kind"] == "audit.tamper")
    assert alert["severity"] == "critical" and alert["message"] == data["reason"]


def test_audit_verify_endpoint_is_auditor_only(h, http, svc):
    assert http.get("/api/audit/verify").status_code == 401
    for user in ("admin1", "officer1", "delegate_nsw1"):
        assert http.get("/api/audit/verify", headers=h.staff(user)).status_code == 403
