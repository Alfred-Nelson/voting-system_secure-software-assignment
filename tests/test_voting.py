"""SR-06 - personal data encrypted at rest (the voting-flow tests are added in later issues)."""
import pytest

from client.voter_client import ClientError

BALLOT = {"atl": {"A": 1, "B": 2, "C": 3}}


def test_voting_closed_before_polls_open(h):
    v = h.voter("NSW1000001")
    with pytest.raises(ClientError, match="not open"):
        v.cast(BALLOT)


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
