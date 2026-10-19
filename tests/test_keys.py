"""SR-26 key management."""
from datetime import datetime, timedelta, timezone

import pytest

from app.security.crypto import CryptoError
from app.security.keys import KeyManager


def make(tmp_path, master=None):
    return KeyManager(tmp_path / "ks.enc", master or b"\x01" * 32)


def test_keystore_encrypted_at_rest(tmp_path):
    km = make(tmp_path)
    raw = (tmp_path / "ks.enc").read_bytes()
    assert b"material" not in raw and b"PRIVATE" not in raw
    # none of the real (base64) key material may appear in the file either
    for entry in km._store.values():
        for version in entry["versions"]:
            assert version["material"].encode() not in raw


def test_wrong_master_key_cannot_open_keystore(tmp_path):
    make(tmp_path)
    with pytest.raises(CryptoError):
        make(tmp_path, b"\x02" * 32)


def test_keys_persist_across_restart(tmp_path):
    n1 = make(tmp_path).blind_public()[0]
    assert make(tmp_path).blind_public()[0] == n1


def test_rotation_keeps_old_versions_verifiable(tmp_path):
    events = []
    km = KeyManager(tmp_path / "ks.enc", b"\x01" * 32, on_event=lambda *a: events.append(a))
    v1, sig1 = km.sign("receipt_sign", b"receipt")
    v2 = km.rotate("receipt_sign", "admin1")
    assert v2 == v1 + 1
    v, sig2 = km.sign("receipt_sign", b"receipt")
    assert v == v2
    assert km.verify("receipt_sign", v1, sig1, b"receipt")      # old signature still verifies
    assert km.verify("receipt_sign", v2, sig2, b"receipt")
    assert not km.verify("receipt_sign", v2, sig1, b"receipt")  # but with the right key only
    assert events and events[0][0] == "key.rotated"             # rotation is audited


def test_rotation_due_after_90_days(tmp_path):
    km = make(tmp_path)
    assert km.needs_rotation() == []
    later = datetime.now(timezone.utc) + timedelta(days=91)
    assert set(km.needs_rotation(later)) == {"results_sign", "receipt_sign", "audit_hmac", "backup"}


def test_election_scoped_keys_cannot_rotate_mid_election(tmp_path):
    km = make(tmp_path)
    for purpose in ("blind", "ballot_enc", "pii_enc"):
        with pytest.raises(CryptoError):
            km.rotate(purpose)
