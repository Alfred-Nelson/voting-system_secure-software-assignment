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
