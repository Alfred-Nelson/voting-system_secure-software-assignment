"""SR-05, SR-06, SR-07, SR-09, SR-10, SR-01 primitives."""
import os

import pytest

from app.security.crypto import CryptoError, aes_decrypt, aes_encrypt


def test_aes_gcm_roundtrip_and_tamper_detection():               # SR-05
    key = os.urandom(32)
    blob = aes_encrypt(key, b"ballot", b"aad")
    assert aes_decrypt(key, blob, b"aad") == b"ballot"
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(CryptoError):
        aes_decrypt(key, tampered, b"aad")
    with pytest.raises(CryptoError):
        aes_decrypt(key, blob, b"other-aad")
