"""SR-11 ballot ledger, SR-18/SR-19 tamper-evident audit log."""
import sqlite3

import pytest


def test_audit_log_append_only(svc, creds):
    with sqlite3.connect(svc.dbs.paths["audit"]) as c:
        with pytest.raises(sqlite3.DatabaseError):
            c.execute("UPDATE audit_log SET actor = 'x'")
        with pytest.raises(sqlite3.DatabaseError):
            c.execute("DELETE FROM audit_log")
