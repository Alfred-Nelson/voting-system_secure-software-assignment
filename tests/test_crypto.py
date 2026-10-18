"""SR-05, SR-06, SR-07, SR-09, SR-10, SR-01 primitives."""
import os

import pytest

from app.security.crypto import CryptoError, aes_decrypt, aes_encrypt, pad_fixed, unpad_fixed


def test_aes_gcm_roundtrip_and_tamper_detection():               # SR-05
    key = os.urandom(32)
    blob = aes_encrypt(key, b"ballot", b"aad")
    assert aes_decrypt(key, blob, b"aad") == b"ballot"
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(CryptoError):
        aes_decrypt(key, tampered, b"aad")
    with pytest.raises(CryptoError):
        aes_decrypt(key, blob, b"other-aad")


def test_aes_rejects_short_keys():
    with pytest.raises(CryptoError):
        aes_encrypt(os.urandom(16), b"x")


def test_fixed_size_padding_hides_length():                       # SR-09
    a, b = pad_fixed(b"{}", 2048), pad_fixed(b"x" * 1500, 2048)
    assert len(a) == len(b) == 2048
    assert unpad_fixed(a) == b"{}" and unpad_fixed(b) == b"x" * 1500
    with pytest.raises(CryptoError):
        pad_fixed(b"x" * 2045, 2048)
