"""SR-18/SR-19 tamper-evident audit log."""
import sqlite3


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
