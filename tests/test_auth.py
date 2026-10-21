"""SR-01, SR-02 authentication and session control."""
from app.config import TestConfig
from app.db import Databases
from app.security.sessions import SessionStore


def make_store(tmp_path):
    dbs = Databases(tmp_path / "data", TestConfig)
    return SessionStore(dbs, TestConfig), dbs


def test_session_tokens_stored_hashed(tmp_path):
    store, dbs = make_store(tmp_path)
    token = store.create("staff", 1, "admin1", "admin")
    with dbs.connect("identity") as c:
        stored = [r[0] for r in c.execute("SELECT token_hash FROM sessions")]
    assert token not in stored and len(stored[0]) == 64
