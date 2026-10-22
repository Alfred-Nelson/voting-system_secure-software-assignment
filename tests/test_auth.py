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


def test_single_factor_rejected_and_audited(h, http, creds, svc):
    r = http.post("/api/auth/voter/login", json={"enrolment_id": "NSW1000001",
                                                  "password": creds["voter_password"]})
    assert r.status_code == 401
    assert any(e["action"] == "auth.rejected_single_factor" for e in svc.audit.entries())


def test_wrong_code_and_unknown_user_give_same_error(h, http, creds):
    a = login(http, "NSW1000001", creds["voter_password"], "000000").get_json()["error"]
    b = login(http, "NOPE0000", creds["voter_password"], "000000").get_json()["error"]
    c = login(http, "NSW1000001", "wrong-password", h.code("NSW1000001")).get_json()["error"]
    assert a == b == c == "invalid credentials"      # no account enumeration


def test_totp_code_cannot_be_replayed(h, http, creds):
    code = h.code("NSW1000001")
    assert login(http, "NSW1000001", creds["voter_password"], code).status_code == 200
    assert login(http, "NSW1000001", creds["voter_password"], code).status_code == 401


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
