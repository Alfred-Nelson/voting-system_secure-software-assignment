"""Key management (SR-26) - a software stand-in for a Hardware Security Module.

Design rules copied from how an HSM behaves:
  * Private keys are generated inside the KeyManager and are never returned to
    callers. Callers ask the KeyManager to *perform* an operation (sign,
    decrypt, blind-sign, MAC) instead.
  * The keystore is encrypted at rest with AES-256-GCM under a master key that
    is supplied from outside the application (environment variable / HSM).
  * Every key has versions. Rotation creates a new version; old public keys
    are kept so earlier signatures can still be verified.
  * Rotatable keys older than 90 days are reported by needs_rotation().

Election-scoped keys (the blind-signing key and the ballot decryption key) are
deliberately NOT rotated during an election because every issued credential
and every encrypted ballot depends on them.
"""
import json
import os
import threading
from pathlib import Path

from .crypto import CryptoError, aes_decrypt, aes_encrypt

ROTATABLE = {"results_sign", "receipt_sign", "audit_hmac", "backup"}
PURPOSES = {
    "blind": "rsa",          # SR-07 blind signatures
    "ballot_enc": "rsa",     # SR-05 ballot decryption (RSA-OAEP unwrap)
    "results_sign": "ed25519",  # SR-14
    "receipt_sign": "ed25519",  # SR-15
    "audit_hmac": "secret",  # SR-18/19 audit entry MAC
    "pii_enc": "secret",     # SR-06
    "pii_index": "secret",   # SR-06 blind index
    "backup": "secret",      # SR-23
}


class KeyManager:
    def __init__(self, keystore_path: Path, master_key: bytes, rotation_days: int = 90,
                 on_event=None):
        if len(master_key) != 32:
            raise CryptoError("master key must be 256 bits")
        self._path = Path(keystore_path)
        self._master = master_key
        self._rotation_days = rotation_days
        self._lock = threading.Lock()
        self._on_event = on_event or (lambda *a, **k: None)
        self._store = self._load() if self._path.exists() else {}
        changed = False
        for purpose in PURPOSES:
            if purpose not in self._store:
                self._store[purpose] = {"current": 0, "versions": []}
                self._new_version(purpose)
                changed = True
        if changed:
            self._save()
        self._cache = {}

    # ------------------------------------------------------------ persistence
    def _load(self):
        blob = self._path.read_bytes()
        return json.loads(aes_decrypt(self._master, blob, b"evote-keystore"))

    def _save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_bytes(aes_encrypt(self._master, json.dumps(self._store).encode(), b"evote-keystore"))
        os.replace(tmp, self._path)

