"""Database layer.

SR-08: voter identity, ballots and audit records live in three physically
separate SQLite databases. There is no shared key between the identity and
ballot databases: ballots are stored against an anonymous credential hash,
never a voter id, so no join between them is possible.

SR-11 / SR-19: the ledger and audit tables are append-only - SQL triggers
abort any UPDATE or DELETE, and both are hash-chained so tampering that
bypasses the triggers (e.g. editing the file directly) is still detected.
"""

IDENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS voters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrol_index TEXT UNIQUE NOT NULL,      -- HMAC blind index of enrolment id (SR-06)
    enrol_enc TEXT NOT NULL,               -- AES-256-GCM encrypted PII (SR-06)
    name_enc TEXT NOT NULL,
    address_enc TEXT NOT NULL,
    dob_enc TEXT NOT NULL,
    division TEXT NOT NULL,
    state TEXT NOT NULL,
    enrolled INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT NOT NULL,
    totp_secret_enc TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    last_totp_counter INTEGER NOT NULL DEFAULT 0,
    token_issued INTEGER NOT NULL DEFAULT 0,   -- online credential issued (SR-04)
    voted_channel TEXT                          -- 'station' / 'postal' (SR-04)
);
"""
