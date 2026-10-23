"""SR-09 / SR-30 - anonymous ballot submission (ElectionService.submit_ballot).

Tests are added one checklist item at a time; each section names the item it covers.
"""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.security import blind
from app.security.crypto import b64d, b64e, hybrid_encrypt, pad_fixed
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


def make_envelope(svc, plaintext=b'{"atl":{"A":1}}'):
    """A real encrypted ballot: padded to BALLOT_PAD_BYTES, then hybrid-encrypted."""
    padded = pad_fixed(plaintext, svc.cfg.BALLOT_PAD_BYTES)
    return hybrid_encrypt(svc.keys.ballot_public_key(), padded)


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
    # Later checklist items extend submit_ballot; for now a genuine credential with a
    # well-formed envelope must get through without raising.
    cred, token = make_credential(svc)
    open_election.submit_ballot(cred, token, make_envelope(svc), "")


# ---- Task 2: envelope has exactly wrapped_key/iv/ciphertext, fixed ciphertext size ------
@pytest.mark.parametrize("bad", [None, "envelope", ["wrapped_key", "iv", "ciphertext"], {}])
def test_envelope_must_be_a_dict_with_the_three_fields(svc, open_election, bad):
    cred, token = make_credential(svc)
    with pytest.raises(VotingError, match="malformed ballot envelope") as exc:
        open_election.submit_ballot(cred, token, bad, "")
    assert exc.value.status == 400


@pytest.mark.parametrize("missing", ["wrapped_key", "iv", "ciphertext"])
def test_envelope_missing_a_field_rejected(svc, open_election, missing):
    cred, token = make_credential(svc)
    env = make_envelope(svc)
    del env[missing]
    with pytest.raises(VotingError, match="malformed ballot envelope"):
        open_election.submit_ballot(cred, token, env, "")


def test_envelope_with_an_extra_field_rejected(svc, open_election):
    # An extra field could smuggle identifying data past the size check.
    cred, token = make_credential(svc)
    env = make_envelope(svc)
    env["note"] = "hello"
    with pytest.raises(VotingError, match="malformed ballot envelope"):
        open_election.submit_ballot(cred, token, env, "")


@pytest.mark.parametrize("size", [0, 100, 2048, 2048 + 15, 2048 + 17, 4096 + 16])    # SR-09
def test_ciphertext_of_any_other_size_rejected(svc, open_election, size):
    cred, token = make_credential(svc)
    env = make_envelope(svc)
    env["ciphertext"] = b64e(b"x" * size)
    with pytest.raises(VotingError, match="wrong size") as exc:
        open_election.submit_ballot(cred, token, env, "")
    assert exc.value.status == 400


def test_ciphertext_of_exactly_pad_bytes_plus_tag_accepted(svc, open_election):   # SR-09
    assert len(b64d(make_envelope(svc)["ciphertext"])) == svc.cfg.BALLOT_PAD_BYTES + 16
    cred, token = make_credential(svc)
    open_election.submit_ballot(cred, token, make_envelope(svc), "")
