"""SR-26 key management."""
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
