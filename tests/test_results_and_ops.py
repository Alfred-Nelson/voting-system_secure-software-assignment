"""Election status rules and general hardening (results, backup and monitoring tests are added in later issues)."""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization

from app.security.backup import create_backup, restore_backup
from app.security.crypto import CryptoError
from client.voter_client import FlaskTransport, VoterClient


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


# ---------------------------------------------------------------- SR-23
def test_backup_restore_roundtrip(svc, creds, tmp_path):
    path = create_backup(svc.dbs, svc.keys, tmp_path / "bk")
    assert b"SQLite" not in path.read_bytes()                     # encrypted
    files = restore_backup(svc.keys, path, tmp_path / "restore")
    assert sorted(files) == ["audit.db", "ballot.db", "identity.db"]
    assert (tmp_path / "restore" / "identity.db").stat().st_size > 0


def test_tampered_backup_rejected(svc, creds, tmp_path):
    path = create_backup(svc.dbs, svc.keys, tmp_path / "bk")
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(CryptoError):
        restore_backup(svc.keys, path, tmp_path / "restore")


# ---------------------------------------------------------------- SR-20 / SR-22
def test_offline_terminal_raises_alert(svc, creds, http):
    assert http.post("/api/terminals/heartbeat", json={"terminal_id": "PS-SYD-001"}).status_code == 200
    assert svc.monitor.check_terminals(now=time.time() + 30) == []
    assert svc.monitor.check_terminals(now=time.time() + 61) == ["PS-SYD-001"]
    alert = svc.monitor.alerts()[0]
    assert alert["severity"] == "critical" and "paper-ballot" in alert["message"]


def test_unknown_terminal_rejected(http, creds):
    assert http.post("/api/terminals/heartbeat", json={"terminal_id": "FAKE"}).status_code == 404


# ---------------------------------------------------------------- SR-24
def test_mission_terminal_network_restriction(http, creds):
    hdr = {"X-Terminal-Id": "MISSION-LON-01"}
    inside = http.post("/api/terminals/heartbeat", json={"terminal_id": "MISSION-LON-01"},
                       headers=hdr, environ_base={"REMOTE_ADDR": "10.20.1.5"})
    outside = http.post("/api/terminals/heartbeat", json={"terminal_id": "MISSION-LON-01"},
                        headers=hdr, environ_base={"REMOTE_ADDR": "203.0.113.9"})
    assert inside.status_code == 200 and outside.status_code == 403


class FlakyTransport(FlaskTransport):
    """Simulates the mission's link dropping for ballot submissions."""
    offline = True

    def request(self, method, path, json_body=None, headers=None):
        if self.offline and path == "/api/ballots":
            raise ConnectionError("link down")
        return super().request(method, path, json_body, headers)


def test_mission_offline_queue_delivers_intact(h, http, tmp_path, svc):
    h.open_polls()
    t = FlakyTransport(http, remote_addr="10.20.1.5")
    v = VoterClient(t, queue_path=tmp_path / "queue.json", terminal_id="MISSION-LON-01")
    v.login("NSW1000005", h.creds["voter_password"], h.code("NSW1000005"))
    assert v.cast({"atl": {"C": 1}}) == {"queued": True}
    assert "atl" not in (tmp_path / "queue.json").read_text()      # queued ballot is encrypted
    t.offline = False                                              # link restored (e.g. after 4 h)
    receipts = v.flush_queue()
    assert len(receipts) == 1 and receipts[0]["receipt"]
    assert svc.ledger.verify()["ok"]


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
