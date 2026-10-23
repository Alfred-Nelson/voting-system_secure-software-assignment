"""SR-06 - personal data encrypted at rest (the voting-flow tests are added in later issues)."""
import base64
import json

import pytest

from client.voter_client import ClientError

BALLOT = {"atl": {"A": 1, "B": 2, "C": 3}}


def test_full_vote_produces_verifiable_receipt(h, http):
    h.open_polls()
    v = h.voter("NSW1000001")
    receipt = v.cast(BALLOT)
    assert receipt["receipt"].count("-") == 4
    check = v.verify_receipt(receipt["receipt"])
    assert check == {"found": True, "issued_hour": receipt["issued_hour"], "signature_valid": True}
    codes = [r["code"] for r in http.get("/api/bulletin").get_json()["receipts"]]
    assert receipt["receipt"] in codes


def test_voting_closed_before_polls_open(h):
    v = h.voter("NSW1000001")
    with pytest.raises(ClientError, match="not open"):
        v.cast(BALLOT)


@pytest.mark.parametrize("enrol,reason", [("NSW1000009", "under 18"),
                                          ("NSW1000010", "not on the electoral roll"),
                                          ("VIC2000001", "enrolled in VIC")])
def test_ineligible_voters_refused(h, enrol, reason):                        # SR-03
    h.open_polls()
    with pytest.raises(ClientError, match=reason):
        h.voter(enrol).cast(BALLOT)


def test_pii_encrypted_in_identity_db(svc, creds):                          # SR-06
    raw = (svc.dbs.paths["identity"]).read_bytes()
    assert b"Aisha Rahman" not in raw and b"George St" not in raw and b"NSW1000001" not in raw


def test_concurrent_credential_requests_only_one_succeeds(h, svc):        # SR-04 race condition
    import threading
    from app.voting.service import VotingError
    h.open_polls()
    with svc.dbs.connect("identity") as c:
        vid = c.execute("SELECT id FROM voters WHERE division = 'Sydney' LIMIT 1").fetchone()[0]
    results = []

    def attempt():
        try:
            svc.election.issue_credential(vid, format(12345, "x"))
            results.append("ok")
        except VotingError:
            results.append("refused")

    threads = [threading.Thread(target=attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 1 and results.count("refused") == 9


def test_bulletin_does_not_reveal_superseded_status(h, http, tmp_path):     # SR-30 coercion
    h.open_polls()
    v = h.voter("NSW1000001", wallet_path=tmp_path / "w.json")
    v.cast(BALLOT)
    v.cast({"atl": {"B": 1}})
    rows = http.get("/api/bulletin").get_json()["receipts"]
    assert len(rows) == 2 and all(set(r) == {"code", "issued_hour"} for r in rows)


def _submission(h):
    h.open_polls()
    v = h.voter("NSW1000001")
    v.obtain_credential()
    return v, v.build_submission(BALLOT)


def test_forged_credential_rejected(h, http):                               # SR-07
    _, sub = _submission(h)
    sub["token"] = format(int(sub["token"], 16) ^ 0xFF, "x")
    r = http.post("/api/ballots", json=sub)
    assert r.status_code == 403


def test_modified_ciphertext_rejected(h, http):                             # SR-10
    _, sub = _submission(h)
    ct = bytearray(base64.b64decode(sub["envelope"]["ciphertext"]))
    ct[10] ^= 1
    sub["envelope"]["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    r = http.post("/api/ballots", json=sub)
    assert r.status_code == 400 and "signature" in r.get_json()["error"]


def test_wrong_size_envelope_rejected(h, http):                              # SR-09
    v, sub = _submission(h)
    sub["envelope"]["ciphertext"] = base64.b64encode(b"x" * 100).decode()
    r = http.post("/api/ballots", json=sub)
    assert r.status_code == 400


def test_replayed_ballot_rejected(h, http):
    _, sub = _submission(h)
    assert http.post("/api/ballots", json=sub).status_code == 201
    assert http.post("/api/ballots", json=sub).status_code == 409


def test_identified_submission_refused(h, http):                            # SR-07
    v, sub = _submission(h)
    r = http.post("/api/ballots", json=sub, headers={"Authorization": "Bearer abc"})
    assert r.status_code == 400


def test_no_link_between_voter_and_ballot(h, svc):                          # SR-07 / SR-08
    h.open_polls()
    v = h.voter("NSW1000001")
    v.cast(BALLOT)
    with svc.dbs.connect("ballot") as c:
        cols = [r[1] for r in c.execute("PRAGMA table_info(ballots)")]
        ballot_row = dict(c.execute("SELECT * FROM ballots").fetchone())
    assert not {"voter_id", "ts", "timestamp", "created"} & set(cols)
    audit_text = json.dumps(svc.audit.entries(1000))
    assert ballot_row["credential_hash"] not in audit_text
    assert ballot_row["ballot_hash"] not in audit_text
    assert "NSW1000001" not in audit_text                # enrolment id never logged in clear


def test_ballot_stored_encrypted(h, svc):                                   # SR-05
    h.open_polls()
    h.voter("NSW1000001").cast({"atl": {"A": 1}})
    with svc.dbs.connect("ballot") as c:
        env = c.execute("SELECT envelope FROM ballots").fetchone()[0]
    assert '"atl"' not in env and "wrapped_key" in env


def test_ballots_mixed_in_batches_before_ledger(tmp_path, creds):            # SR-09
    """With a mixing batch of 3, nothing reaches the ledger until 3 ballots are
    pooled; the batch is then shuffled, so ledger order != submission order."""
    import secrets as _s
    from app import create_app
    from app.config import TestConfig
    from app.seed import seed
    from tests.conftest import Helper

    class MixCfg(TestConfig):
        MASTER_KEY_HEX = _s.token_hex(32)
        MIX_BATCH_SIZE = 3

    app = create_app(MixCfg, tmp_path / "mix")
    svc = app.evote
    helper = Helper(app, app.test_client(), seed(svc))
    helper.open_polls()
    receipts = []
    for i in (1, 2):
        receipts.append(helper.voter(f"NSW100000{i}").cast({"atl": {"A": 1}})["receipt"])
    assert svc.ledger.verify()["ledger_entries"] == 0          # still in the mixing pool
    receipts.append(helper.voter("NSW1000003").cast({"atl": {"B": 1}})["receipt"])
    assert svc.ledger.verify() == {"ok": True, "ledger_entries": 3, "stored_ballots": 3,
                                   "problems": []}
    actions = [e["action"] for e in svc.audit.entries()]
    assert "ballots.batch_mixed" in actions and "ballot.accepted" not in actions
    helper.voter("NSW1000004").cast({"atl": {"C": 1}})
    adm = helper.staff("admin1")
    helper.http.post("/api/admin/election/status", json={"status": "closed"}, headers=adm)
    assert svc.ledger.verify()["ledger_entries"] == 4          # closing flushes the last batch
