"""SR-09 / SR-30 - anonymous ballot submission (ElectionService.submit_ballot).

Tests are added one checklist item at a time; each section names the item it covers.
"""
import json
import re
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app import create_app
from app.security import blind
from app.security.crypto import (b64d, b64e, ecdsa_sign_raw, envelope_signing_bytes,
                                 hybrid_encrypt, pad_fixed, sha256_hex)
from app.voting.ledger import ballot_hash
from app.voting.service import VotingError
from tests.conftest import _Cfg


class _PoolCfg(_Cfg):
    MIX_BATCH_SIZE = 100          # keep ballots in ballot_pool; a flush would empty it


@pytest.fixture
def app(tmp_path):
    return create_app(_PoolCfg, tmp_path / "data")


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


# ---- Task 5: older ballots from the same credential_hash are marked superseded ----------
def _flag(svc, table, cred, env, sig):
    with svc.dbs.connect("ballot") as conn:
        row = conn.execute(f"SELECT superseded FROM {table} WHERE ballot_hash = ?",  # nosec B608
                           (_hash_of(cred, env, sig),)).fetchone()
    return row["superseded"]


def _revote(svc, table, key, cred, text=b'{"atl":{"A":1}}'):
    """An earlier ballot from this credential, already stored in `table`."""
    env = make_envelope(svc, text)
    sig = sign_envelope(key, env)
    _store(svc, table, cred, env, sig)
    return env, sig


@pytest.mark.parametrize("table", ["ballots", "ballot_pool"])                       # SR-30
def test_older_ballot_from_same_credential_marked_superseded(svc, open_election, table):
    key, cred, token = make_credential(svc, with_key=True)
    env, sig = _revote(svc, table, key, cred)
    assert _flag(svc, table, cred, env, sig) == 0
    new_env = make_envelope(svc, b'{"atl":{"B":1}}')
    open_election.submit_ballot(cred, token, new_env, sign_envelope(key, new_env))
    assert _flag(svc, table, cred, env, sig) == 1


def test_every_older_ballot_in_both_tables_superseded(svc, open_election):
    key, cred, token = make_credential(svc, with_key=True)
    stored = [(t, *_revote(svc, t, key, cred, text))
              for t, text in [("ballots", b"1"), ("ballots", b"2"), ("ballot_pool", b"3")]]
    new_env = make_envelope(svc, b"4")
    open_election.submit_ballot(cred, token, new_env, sign_envelope(key, new_env))
    assert [_flag(svc, t, cred, env, sig) for t, env, sig in stored] == [1, 1, 1]


def test_ballots_from_other_credentials_untouched(svc, open_election):
    other_key, other_cred, _ = make_credential(svc, with_key=True)
    env, sig = _revote(svc, "ballots", other_key, other_cred)
    open_election.submit_ballot(*make_submission(svc))
    assert _flag(svc, "ballots", other_cred, env, sig) == 0


def test_replay_does_not_supersede_the_newer_ballot(svc, open_election):
    # Replaying an old ballot must be refused without touching the voter's latest one.
    key, cred, token = make_credential(svc, with_key=True)
    old_env, old_sig = _revote(svc, "ballots", key, cred, b"old")
    new_env, new_sig = _revote(svc, "ballot_pool", key, cred, b"new")
    with pytest.raises(VotingError, match="duplicate ballot"):
        open_election.submit_ballot(cred, token, old_env, old_sig)
    assert _flag(svc, "ballot_pool", cred, new_env, new_sig) == 0


def test_rejected_ballot_does_not_supersede_anything(svc, open_election):
    key, cred, token = make_credential(svc, with_key=True)
    env, sig = _revote(svc, "ballots", key, cred)
    bad_env = make_envelope(svc)
    with pytest.raises(VotingError):                      # signed by someone else
        open_election.submit_ballot(cred, token, bad_env,
                                    sign_envelope(ec.generate_private_key(ec.SECP256R1()), bad_env))
    assert _flag(svc, "ballots", cred, env, sig) == 0


# ---- Task 6: insert into ballot_pool with a random UUID id ------------------------------
def _pool(svc):
    with svc.dbs.connect("ballot") as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM ballot_pool")]


def test_accepted_ballot_is_stored_in_the_pool(svc, open_election):
    cred, token, env, sig = make_submission(svc)
    open_election.submit_ballot(cred, token, env, sig)
    (row,) = _pool(svc)
    assert row["credential_hash"] == sha256_hex(b64d(cred))
    assert json.loads(row["envelope"]) == env
    assert row["signature"] == sig
    assert row["ballot_hash"] == _hash_of(cred, env, sig)
    assert row["superseded"] == 0


def test_pool_row_id_is_a_random_uuid(svc, open_election):                         # SR-09
    open_election.submit_ballot(*make_submission(svc))
    open_election.submit_ballot(*make_submission(svc))
    ids = [r["id"] for r in _pool(svc)]
    assert len(set(ids)) == 2
    assert all(uuid.UUID(i).version == 4 and str(uuid.UUID(i)) == i for i in ids)


def test_pool_ids_do_not_follow_submission_order(svc, open_election):             # SR-09
    order = []
    for _ in range(12):
        sub = make_submission(svc)
        open_election.submit_ballot(*sub)
        order.append(_hash_of(sub[0], sub[2], sub[3]))
    by_id = [r["ballot_hash"] for r in sorted(_pool(svc), key=lambda r: r["id"])]
    assert len(by_id) == 12 and by_id != order      # a sequential id would make these equal


def test_pool_has_no_voter_or_time_column(svc):                                    # SR-07 / SR-09
    with svc.dbs.connect("ballot") as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(ballot_pool)")}
    assert cols == {"id", "credential_hash", "envelope", "signature", "ballot_hash",
                    "superseded"}


def test_revote_stores_new_ballot_and_supersedes_the_old(svc, open_election):     # SR-30
    key, cred, token = make_credential(svc, with_key=True)
    for text in (b"first", b"second"):
        env = make_envelope(svc, text)
        open_election.submit_ballot(cred, token, env, sign_envelope(key, env))
    rows = sorted(_pool(svc), key=lambda r: r["superseded"])
    assert [r["superseded"] for r in rows] == [0, 1]       # only the latest stays live
    assert rows[0]["envelope"] != rows[1]["envelope"]


def test_resubmitting_a_stored_ballot_is_a_replay(svc, open_election):
    sub = make_submission(svc)
    open_election.submit_ballot(*sub)
    with pytest.raises(VotingError, match="duplicate ballot") as exc:
        open_election.submit_ballot(*sub)
    assert exc.value.status == 409
    assert len(_pool(svc)) == 1


def test_rejected_ballot_is_not_stored(svc, open_election):
    cred, token, env, _ = make_submission(svc)
    with pytest.raises(VotingError):
        open_election.submit_ballot(cred, token, env, b64e(b"\x00" * 64))
    assert _pool(svc) == []


# ---- Task 7: _issue_receipt - code from ballot hash, hour-only time, signed -------------
def _receipts(svc):
    with svc.dbs.connect("ballot") as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM receipts")]


def _utc_hour():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00Z")


def test_submit_returns_a_receipt(svc, open_election):
    receipt = open_election.submit_ballot(*make_submission(svc))
    assert set(receipt) == {"receipt", "issued_hour", "key_version", "signature"}


def test_receipt_code_is_derived_from_the_ballot_hash(svc, open_election):
    cred, token, env, sig = make_submission(svc)
    receipt = open_election.submit_ballot(cred, token, env, sig)
    bh = _hash_of(cred, env, sig)
    assert re.fullmatch(r"([0-9A-F]{4}-){4}[0-9A-F]{4}", receipt["receipt"])
    assert receipt["receipt"].replace("-", "") == bh[:20].upper()


def test_receipt_time_is_the_hour_only(svc, open_election):                         # SR-09
    before = _utc_hour()
    receipt = open_election.submit_ballot(*make_submission(svc))
    after = _utc_hour()
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:00Z", receipt["issued_hour"])
    assert receipt["issued_hour"] in (before, after)         # no minutes, seconds or millis


def test_receipt_signature_verifies(svc, open_election):
    receipt = open_election.submit_ballot(*make_submission(svc))
    msg = f"{receipt['receipt']}|{receipt['issued_hour']}".encode()
    assert svc.keys.verify("receipt_sign", receipt["key_version"], receipt["signature"], msg)


def test_receipt_signature_fails_if_code_or_hour_changed(svc, open_election):
    receipt = open_election.submit_ballot(*make_submission(svc))
    ver, sig = receipt["key_version"], receipt["signature"]
    assert not svc.keys.verify("receipt_sign", ver, sig,
                               f"AAAA-AAAA-AAAA-AAAA-AAAA|{receipt['issued_hour']}".encode())
    assert not svc.keys.verify("receipt_sign", ver, sig,
                               f"{receipt['receipt']}|2000-01-01T00:00Z".encode())


def test_receipt_is_recorded_for_the_bulletin_board(svc, open_election):
    receipt = open_election.submit_ballot(*make_submission(svc))
    (row,) = _receipts(svc)
    assert (row["code"], row["issued_hour"], row["key_version"], row["signature"]) == (
        receipt["receipt"], receipt["issued_hour"], receipt["key_version"], receipt["signature"])


def test_receipt_table_has_no_exact_time_or_link_to_voter(svc):                    # SR-07 / SR-09
    with svc.dbs.connect("ballot") as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(receipts)")}
    assert cols == {"code", "issued_hour", "key_version", "signature"}


def test_each_submission_gets_its_own_receipt(svc, open_election):
    key, cred, token = make_credential(svc, with_key=True)
    codes = []
    for text in (b"first", b"second"):                     # a re-vote gets a fresh receipt
        env = make_envelope(svc, text)
        codes.append(open_election.submit_ballot(cred, token, env,
                                                 sign_envelope(key, env))["receipt"])
    assert codes[0] != codes[1]
    assert sorted(r["code"] for r in _receipts(svc)) == sorted(codes)


def test_no_receipt_for_rejected_or_replayed_ballots(svc, open_election):
    cred, token, env, sig = make_submission(svc)
    with pytest.raises(VotingError):
        open_election.submit_ballot(cred, token, env, b64e(b"\x00" * 64))
    assert _receipts(svc) == []
    open_election.submit_ballot(cred, token, env, sig)
    with pytest.raises(VotingError, match="duplicate"):
        open_election.submit_ballot(cred, token, env, sig)
    assert len(_receipts(svc)) == 1


def test_receipt_reveals_nothing_about_the_vote(svc, open_election):
    receipt = open_election.submit_ballot(*make_submission(svc, b'{"atl":{"A":1}}'))
    assert "atl" not in json.dumps(receipt)

