"""SR-05, SR-06, SR-07, SR-09, SR-10, SR-01 primitives."""
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.security.crypto import (CryptoError, FieldCipher, aes_decrypt, aes_encrypt,
                                 hybrid_decrypt, hybrid_encrypt, pad_fixed, unpad_fixed)


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


def test_hybrid_encryption_roundtrip():                            # SR-05
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    env = hybrid_encrypt(priv.public_key(), b"secret ballot")
    unwrap = lambda w: priv.decrypt(w, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))
    assert hybrid_decrypt(unwrap, env) == b"secret ballot"
    assert b"secret" not in env["ciphertext"].encode()


def test_field_cipher_and_blind_index():                           # SR-06
    fc = FieldCipher(os.urandom(32), os.urandom(32))
    token = fc.encrypt("Aisha Rahman", "name")
    assert "Aisha" not in token
    assert fc.decrypt(token, "name") == "Aisha Rahman"
    with pytest.raises(CryptoError):        # context binding: can't move a value to another column
        fc.decrypt(token, "address")
    assert fc.blind_index("nsw1000001") == fc.blind_index("NSW1000001 ")
    assert fc.encrypt("x", "c") != fc.encrypt("x", "c")   # random nonce each time
