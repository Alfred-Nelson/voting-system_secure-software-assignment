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
