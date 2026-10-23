"""SR-09 / SR-30 - anonymous ballot submission (ElectionService.submit_ballot).

Tests are added one checklist item at a time; each section names the item it covers.
"""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.security import blind
from app.security.crypto import b64e
from app.voting.service import VotingError


def make_credential(svc, issued=True):
    """Build an anonymous credential the way the voter's device does.

    Returns (credential_b64, token_hex). With issued=False the token is not a
    signature from the AEC blind key (a forged credential).
    """
    spki = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    n, e = svc.keys.blind_public()
    m = blind.message_int(spki, n)
    blinded, r = blind.blind(m, n, e)
    token = blind.unblind(svc.keys.blind_sign(blinded), r, n)
    if not issued:
        token = (token + 1) % n
    return b64e(spki), format(token, "x")


@pytest.fixture
def open_election(svc):
    svc.election.set_status("open", "admin1", "admin")
    return svc.election


# ---- Task 1: polls open, load_spki, blind.verify of the credential ----------------------
def test_submit_refused_while_polls_not_open(svc):
    cred, token = make_credential(svc)
    with pytest.raises(VotingError, match="not open") as exc:
        svc.election.submit_ballot(cred, token, {}, "")
    assert exc.value.status == 409


def test_submit_refused_after_polls_closed(svc, open_election):
    cred, token = make_credential(svc)
    open_election.set_status("closed", "admin1", "admin")
    with pytest.raises(VotingError, match="not open"):
        open_election.submit_ballot(cred, token, {}, "")


def test_credential_without_valid_blind_signature_rejected(svc, open_election):    # SR-07
    cred, token = make_credential(svc, issued=False)
    with pytest.raises(VotingError, match="not issued by the AEC") as exc:
        open_election.submit_ballot(cred, token, {}, "")
    assert exc.value.status == 403


def test_blind_signature_for_a_different_credential_rejected(svc, open_election):
    cred, _ = make_credential(svc)
    _, other_token = make_credential(svc)             # valid token, but for another key
    with pytest.raises(VotingError, match="not issued by the AEC"):
        open_election.submit_ballot(cred, other_token, {}, "")


def test_garbage_credential_rejected_as_malformed(svc, open_election):
    _, token = make_credential(svc)
    with pytest.raises(VotingError, match="malformed") as exc:
        open_election.submit_ballot(b64e(b"not a DER public key"), token, {}, "")
    assert exc.value.status == 400


def test_non_hex_token_rejected_as_malformed(svc, open_election):
    cred, _ = make_credential(svc)
    with pytest.raises(VotingError, match="malformed"):
        open_election.submit_ballot(cred, "zz-not-hex", {}, "")


def test_valid_credential_passes_the_credential_check(svc, open_election):
    # Later checklist items extend submit_ballot; for now a genuine credential must get
    # past the credential check without raising "not issued by the AEC".
    cred, token = make_credential(svc)
    open_election.submit_ballot(cred, token, {}, "")
