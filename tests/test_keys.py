"""SR-26 key management."""
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
