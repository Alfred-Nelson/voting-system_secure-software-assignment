"""Election status rules and general hardening (results, backup and monitoring tests are added in later issues)."""
import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.security.integrity import build_manifest, manifest_bytes, verify_release


# ---------------------------------------------------------------- SR-14
def _publish(h, http):
    h.open_polls()
    h.voter("NSW1000001").cast({"atl": {"B": 1}})
    adm = h.staff("admin1")
    http.post("/api/admin/election/status", json={"status": "closed"}, headers=adm)
    http.post("/api/admin/tally", headers=adm)


def test_results_require_client_key(h, http, creds):
    _publish(h, http)
    assert http.get("/api/results").status_code == 401
    assert http.get("/api/results", headers={"X-API-Key": "wrong"}).status_code == 401


def test_results_signature_verifies_and_detects_change(h, http, creds):
    _publish(h, http)
    data = http.get("/api/results", headers={"X-API-Key": creds["results_api_key"]}).get_json()
    pub = serialization.load_pem_public_key(data["public_key_pem"].encode())
    payload = json.dumps(data["result"], sort_keys=True, separators=(",", ":")).encode()
    pub.verify(base64.b64decode(data["signature"]), payload)
    data["result"]["elected"] = ["A1"]
    tampered = json.dumps(data["result"], sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(Exception):
        pub.verify(base64.b64decode(data["signature"]), tampered)


def test_results_rate_limited_100_per_minute(h, http, creds):
    _publish(h, http)
    hdr = {"X-API-Key": creds["results_api_key"]}
    codes = [http.get("/api/results", headers=hdr).status_code for _ in range(101)]
    assert codes[:100] == [200] * 100 and codes[100] == 429


def test_cannot_count_while_polls_open(h, http):
    h.open_polls()
    r = http.post("/api/admin/tally", headers=h.staff("admin1"))
    assert r.status_code == 409


# ---------------------------------------------------------------- hardening
def test_security_headers(http):
    r = http.get("/api/election")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "max-age" in r.headers["Strict-Transport-Security"]
    assert r.headers["Cache-Control"] == "no-store"


def test_oversized_request_rejected(http):
    r = http.post("/api/ballots", data="x" * 70000, content_type="application/json")
    assert r.status_code == 413


def test_election_status_transitions_enforced(h, http):
    adm = h.staff("admin1")
    r = http.post("/api/admin/election/status", json={"status": "closed"}, headers=adm)
    assert r.status_code == 400                       # can't close before opening
    r = http.post("/api/admin/election/status", json={"status": "tallied"}, headers=adm)
    assert r.status_code == 400                       # only the count may set 'tallied'


# ---------------------------------------------------------------- SR-25
def _signed_release(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.py").write_text("print('vote')")
    key = ed25519.Ed25519PrivateKey.generate()
    manifest = build_manifest(app_dir)
    (tmp_path / "manifest.json").write_text(json.dumps({
        "manifest": manifest, "signature": base64.b64encode(key.sign(manifest_bytes(manifest))).decode()}))
    (tmp_path / "pub.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return app_dir


def test_signed_build_verifies(tmp_path):
    app_dir = _signed_release(tmp_path)
    assert verify_release(app_dir, tmp_path / "manifest.json", tmp_path / "pub.pem")[0]


def test_modified_code_refuses_to_run(tmp_path):
    app_dir = _signed_release(tmp_path)
    (app_dir / "main.py").write_text("print('rigged')")
    ok, reason = verify_release(app_dir, tmp_path / "manifest.json", tmp_path / "pub.pem")
    assert not ok and "main.py" in reason
    (app_dir / "main.py").write_text("print('vote')")
    (app_dir / "backdoor.py").write_text("x = 1")
    assert not verify_release(app_dir, tmp_path / "manifest.json", tmp_path / "pub.pem")[0]


def test_forged_manifest_rejected(tmp_path):
    app_dir = _signed_release(tmp_path)
    m = json.loads((tmp_path / "manifest.json").read_text())
    m["manifest"]["files"]["main.py"] = "0" * 64
    (tmp_path / "manifest.json").write_text(json.dumps(m))
    ok, reason = verify_release(app_dir, tmp_path / "manifest.json", tmp_path / "pub.pem")
    assert not ok and "signature" in reason
