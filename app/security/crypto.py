"""Cryptographic primitives used across the platform.

SR-05  Ballot encryption: AES-256-GCM (authenticated) with the AES key wrapped
       by RSA-OAEP-SHA256 under the election public key (hybrid encryption).
SR-06  Personal data at rest: AES-256-GCM field encryption + HMAC blind index.
SR-09  Fixed-size padding so ciphertext length never reveals ballot content.
SR-10  Ballot signatures: ECDSA P-256 (the voter's anonymous credential key).
"""
import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidTag
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


def aes_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    if len(blob) < 28:
        raise CryptoError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as exc:
        raise CryptoError("authentication tag mismatch - data was modified") from exc


# ---------------------------------------------------------------- PII at rest (SR-06)
class FieldCipher:
    """Encrypts individual database fields. A separate HMAC key produces a
    deterministic 'blind index' so records can be looked up without
    decrypting the whole table."""

    def __init__(self, enc_key: bytes, index_key: bytes):
        self._enc_key = enc_key
        self._index_key = index_key

    def encrypt(self, value: str, context: str) -> str:
        return b64e(aes_encrypt(self._enc_key, value.encode(), context.encode()))

    def decrypt(self, token: str, context: str) -> str:
        return aes_decrypt(self._enc_key, b64d(token), context.encode()).decode()

    def blind_index(self, value: str) -> str:
        return hmac.new(self._index_key, value.strip().upper().encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- padding (SR-09)
def pad_fixed(data: bytes, size: int) -> bytes:
    """Length-prefixed padding to a fixed block size."""
    if len(data) + 4 > size:
        raise CryptoError("ballot too large for fixed-size envelope")
    return len(data).to_bytes(4, "big") + data + os.urandom(size - 4 - len(data))


def unpad_fixed(data: bytes) -> bytes:
    n = int.from_bytes(data[:4], "big")
    if n > len(data) - 4:
        raise CryptoError("corrupt padding")
    return data[4:4 + n]
