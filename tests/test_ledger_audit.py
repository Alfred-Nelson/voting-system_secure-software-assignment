"""SR-11 ballot ledger, SR-18/SR-19 tamper-evident audit log."""
import sqlite3

import pytest


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
