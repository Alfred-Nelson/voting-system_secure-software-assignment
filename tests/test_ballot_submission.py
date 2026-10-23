"""SR-09 / SR-30 - anonymous ballot submission (ElectionService.submit_ballot).

Tests are added one checklist item at a time; each section names the item it covers.
"""
import json
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.security import blind
from app.security.crypto import (b64d, b64e, ecdsa_sign_raw, envelope_signing_bytes,
                                 hybrid_encrypt, pad_fixed, sha256_hex)
from app.voting.ledger import ballot_hash
from app.voting.service import VotingError


def make_credential(svc, issued=True, curve=None, with_key=False):
    """Build an anonymous credential the way the voter's device does.

    Returns (credential_b64, token_hex), or (private_key, credential_b64, token_hex) with
    with_key=True. With issued=False the token is not a signature from the AEC blind key
    (a forged credential). `curve` lets a test build a credential on the wrong curve.
    """
    key = ec.generate_private_key(curve or ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    n, e = svc.keys.blind_public()
    m = blind.message_int(spki, n)
    blinded, r = blind.blind(m, n, e)
    token = blind.unblind(svc.keys.blind_sign(blinded), r, n)
    if not issued:
        token = (token + 1) % n
    out = (b64e(spki), format(token, "x"))
    return (key, *out) if with_key else out


def make_envelope(svc, plaintext=b'{"atl":{"A":1}}'):
    """A real encrypted ballot: padded to BALLOT_PAD_BYTES, then hybrid-encrypted."""
    padded = pad_fixed(plaintext, svc.cfg.BALLOT_PAD_BYTES)
    return hybrid_encrypt(svc.keys.ballot_public_key(), padded)


def sign_envelope(key, envelope):
    return b64e(ecdsa_sign_raw(key, envelope_signing_bytes(envelope)))


def make_submission(svc, plaintext=b'{"atl":{"A":1}}'):
    """A complete, valid anonymous submission: (credential_b64, token_hex, envelope, signature)."""
    key, cred, token = make_credential(svc, with_key=True)
    env = make_envelope(svc, plaintext)
    return cred, token, env, sign_envelope(key, env)


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
    # Later checklist items extend submit_ballot; for now a fully valid submission
    # must get through without raising.
    open_election.submit_ballot(*make_submission(svc))


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
    cred, token, env, sig = make_submission(svc)
    assert len(b64d(env["ciphertext"])) == svc.cfg.BALLOT_PAD_BYTES + 16
    open_election.submit_ballot(cred, token, env, sig)


# ---- Task 3: ecdsa_verify_raw over envelope_signing_bytes; audit ballot.rejected --------
def _rejections(svc):
    return [e for e in svc.audit.entries() if e["action"] == "ballot.rejected"]


def test_modified_ciphertext_fails_signature_check(svc, open_election):            # SR-10
    cred, token, env, sig = make_submission(svc)
    ct = bytearray(b64d(env["ciphertext"]))
    ct[10] ^= 1                                       # same size, one flipped bit
    env["ciphertext"] = b64e(bytes(ct))
    with pytest.raises(VotingError, match="signature invalid") as exc:
        open_election.submit_ballot(cred, token, env, sig)
    assert exc.value.status == 400


@pytest.mark.parametrize("field", ["wrapped_key", "iv"])
def test_modified_wrapped_key_or_iv_fails_signature_check(svc, open_election, field):
    cred, token, env, sig = make_submission(svc)
    raw = bytearray(b64d(env[field]))
    raw[0] ^= 1
    env[field] = b64e(bytes(raw))
    with pytest.raises(VotingError, match="signature invalid"):
        open_election.submit_ballot(cred, token, env, sig)


def test_signature_from_a_different_key_rejected(svc, open_election):
    cred, token, env, _ = make_submission(svc)
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(VotingError, match="signature invalid"):
        open_election.submit_ballot(cred, token, env, sign_envelope(other, env))


@pytest.mark.parametrize("sig", ["", b64e(b"short"), b64e(b"x" * 65)])
def test_signature_of_wrong_length_rejected(svc, open_election, sig):
    cred, token, env, _ = make_submission(svc)
    with pytest.raises(VotingError, match="64 bytes"):
        open_election.submit_ballot(cred, token, env, sig)


def test_signature_that_is_not_base64_rejected(svc, open_election):
    cred, token, env, _ = make_submission(svc)
    with pytest.raises(VotingError, match="invalid base64") as exc:
        open_election.submit_ballot(cred, token, env, "***not base64***")
    assert exc.value.status == 400


def test_credential_on_the_wrong_curve_rejected(svc, open_election):
    _, cred, token = make_credential(svc, curve=ec.SECP384R1(), with_key=True)
    with pytest.raises(VotingError, match="P-256"):
        open_election.submit_ballot(cred, token, make_envelope(svc), b64e(b"\x01" * 64))


def test_rejection_is_audited_anonymously(svc, open_election):                      # SR-07
    cred, token, env, sig = make_submission(svc)
    env["iv"] = b64e(b"\x00" * 12)
    with pytest.raises(VotingError):
        open_election.submit_ballot(cred, token, env, sig)
    (entry,) = _rejections(svc)
    assert entry["actor"] == "anonymous" and entry["role"] == "voter"
    assert "signature invalid" in entry["details"]
    # nothing that could identify the credential or ballot goes into the log
    for secret in (cred, token, sig, env["ciphertext"], env["wrapped_key"]):
        assert secret not in entry["details"]
    assert svc.audit.verify_chain()["ok"]


def test_valid_ballot_is_not_audited_as_rejected(svc, open_election):
    open_election.submit_ballot(*make_submission(svc))
    assert _rejections(svc) == []


# ---- Task 4: refuse a ballot_hash already in ballots or ballot_pool (replay) ------------
def _hash_of(cred, env, sig):
    envelope_json = json.dumps(env, sort_keys=True, separators=(",", ":"))
    return ballot_hash(sha256_hex(b64d(cred)), envelope_json, sig)


def _store(svc, table, cred, env, sig):
    """Put a ballot straight into `table`, as an earlier accepted submission would be."""
    envelope_json = json.dumps(env, sort_keys=True, separators=(",", ":"))
    with svc.dbs.transaction("ballot") as conn:
        conn.execute(f"INSERT INTO {table} (id, credential_hash, envelope, signature, "  # nosec B608
                     "ballot_hash) VALUES (?,?,?,?,?)",
                     (str(uuid.uuid4()), sha256_hex(b64d(cred)), envelope_json, sig,
                      _hash_of(cred, env, sig)))


@pytest.mark.parametrize("table", ["ballot_pool", "ballots"])
def test_replayed_ballot_refused(svc, open_election, table):
    cred, token, env, sig = make_submission(svc)
    _store(svc, table, cred, env, sig)
    with pytest.raises(VotingError, match="duplicate ballot") as exc:
        open_election.submit_ballot(cred, token, env, sig)
    assert exc.value.status == 409


def test_ballot_hash_ignores_envelope_key_order(svc, open_election):
    # The hash is taken over canonical JSON, so re-ordering the fields is still a replay.
    cred, token, env, sig = make_submission(svc)
    _store(svc, "ballot_pool", cred, env, sig)
    reordered = {k: env[k] for k in reversed(list(env))}
    with pytest.raises(VotingError, match="duplicate ballot"):
        open_election.submit_ballot(cred, token, reordered, sig)


def test_other_stored_ballots_do_not_block_a_new_one(svc, open_election):
    cred, _, env, sig = make_submission(svc)
    _store(svc, "ballot_pool", cred, env, sig)
    open_election.submit_ballot(*make_submission(svc))


def test_same_credential_with_a_new_envelope_is_not_a_replay(svc, open_election):  # SR-30
    key, cred, token = make_credential(svc, with_key=True)
    first = make_envelope(svc, b'{"atl":{"A":1}}')
    _store(svc, "ballots", cred, first, sign_envelope(key, first))
    second = make_envelope(svc, b'{"atl":{"B":1}}')      # a re-vote: new ciphertext, new hash
    open_election.submit_ballot(cred, token, second, sign_envelope(key, second))

