"""SR-06 - personal data encrypted at rest (the voting-flow tests are added in later issues)."""
import base64

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
