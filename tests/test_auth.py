"""SR-01, SR-02 authentication and session control."""
from app.config import TestConfig
from app.db import Databases
from app.security.sessions import SessionStore


def make_store(tmp_path):
    dbs = Databases(tmp_path / "data", TestConfig)
    return SessionStore(dbs, TestConfig), dbs


def login(http, enrol, password, code):
    return http.post("/api/auth/voter/login",
                     json={"enrolment_id": enrol, "password": password, "totp": code})


def test_voter_login_with_both_factors(h, http, creds):
    r = login(http, "NSW1000001", creds["voter_password"], h.code("NSW1000001"))
    assert r.status_code == 200 and r.get_json()["role"] == "voter"


def test_session_tokens_stored_hashed(tmp_path):
    store, dbs = make_store(tmp_path)
    token = store.create("staff", 1, "admin1", "admin")
    with dbs.connect("identity") as c:
        stored = [r[0] for r in c.execute("SELECT token_hash FROM sessions")]
    assert token not in stored and len(stored[0]) == 64


def test_voter_idle_timeout_is_longer(tmp_path):
    store, _ = make_store(tmp_path)
    assert store.timeout_for("voter") == 600
    assert store.timeout_for("voter") > store.timeout_for("admin")
