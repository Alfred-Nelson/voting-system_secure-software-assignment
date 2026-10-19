import pytest

from app.security.crypto import (
    CryptoError,
    aes_decrypt,
    aes_encrypt,
    envelope_signing_bytes,
)


def test_aes_encrypt_decrypt_round_trip_and_rejects_modified_data():
    key = b"k" * 32
    plaintext = b"ballot"
    aad = b"election-1"

    ciphertext = aes_encrypt(key, plaintext, aad)

    assert aes_decrypt(key, ciphertext, aad) == plaintext
    with pytest.raises(CryptoError):
        aes_decrypt(key, ciphertext, b"election-2")


def test_envelope_signing_bytes_use_versioned_field_order():
    envelope = {
        "wrapped_key": "wrapped",
        "iv": "nonce",
        "ciphertext": "encrypted",
    }

    assert envelope_signing_bytes(envelope) == b"v1|wrapped|nonce|encrypted"
