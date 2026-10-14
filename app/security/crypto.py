"""Cryptographic primitives used across the platform.

SR-05  Ballot encryption: AES-256-GCM (authenticated) with the AES key wrapped
       by RSA-OAEP-SHA256 under the election public key (hybrid encryption).
SR-06  Personal data at rest: AES-256-GCM field encryption + HMAC blind index.
SR-09  Fixed-size padding so ciphertext length never reveals ballot content.
SR-10  Ballot signatures: ECDSA P-256 (the voter's anonymous credential key).
"""
import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Raised for any failed decryption or verification."""


# ---------------------------------------------------------------- helpers
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # binascii.Error or TypeError
        raise CryptoError("invalid base64") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding - required before hashing or signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------- AES-256-GCM
def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Returns nonce(12) || ciphertext+tag."""
    if len(key) != 32:
        raise CryptoError("AES-256 requires a 32-byte key")
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
