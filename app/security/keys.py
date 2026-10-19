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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from .crypto import CryptoError, aes_decrypt, aes_encrypt, b64d, b64e

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


def _now():
    return datetime.now(timezone.utc)


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

    def _new_version(self, purpose):
        kind = PURPOSES[purpose]
        if kind == "rsa":
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            material = priv.private_bytes(serialization.Encoding.DER,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
        elif kind == "ed25519":
            material = ed25519.Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
        else:
            material = os.urandom(32)
        entry = self._store[purpose]
        version = len(entry["versions"]) + 1
        entry["versions"].append({"version": version, "created": _now().isoformat(),
                                  "material": b64e(material)})
        entry["current"] = version
        return version

    def _material(self, purpose, version=None):
        entry = self._store[purpose]
        version = version or entry["current"]
        for v in entry["versions"]:
            if v["version"] == version:
                return b64d(v["material"]), version
        raise CryptoError(f"unknown key version {purpose} v{version}")

    def _private(self, purpose, version=None):
        material, version = self._material(purpose, version)
        cache_key = (purpose, version)
        if cache_key not in self._cache:
            if PURPOSES[purpose] == "rsa":
                self._cache[cache_key] = serialization.load_der_private_key(material, None)
            else:
                self._cache[cache_key] = ed25519.Ed25519PrivateKey.from_private_bytes(material)
        return self._cache[cache_key], version

    # ------------------------------------------------------------ rotation
    def rotate(self, purpose, actor="system", reason="scheduled"):
        if purpose not in ROTATABLE:
            raise CryptoError(f"{purpose} is election-scoped and cannot be rotated mid-election")
        with self._lock:
            version = self._new_version(purpose)
            self._save()
        self._on_event("key.rotated", actor, {"purpose": purpose, "version": version,
                                               "reason": reason})
        return version

    def needs_rotation(self, now=None):
        now = now or _now()
        due = []
        for purpose in ROTATABLE:
            entry = self._store[purpose]
            created = datetime.fromisoformat(entry["versions"][entry["current"] - 1]["created"])
            if now - created > timedelta(days=self._rotation_days):
                due.append(purpose)
        return sorted(due)

    def key_status(self):
        out = []
        for purpose, entry in self._store.items():
            cur = entry["versions"][entry["current"] - 1]
            out.append({"purpose": purpose, "algorithm": PURPOSES[purpose],
                        "current_version": entry["current"], "created": cur["created"],
                        "rotatable": purpose in ROTATABLE})
        return out

