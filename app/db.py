"""Database layer.

SR-08: voter identity, ballots and audit records live in three physically
separate SQLite databases. There is no shared key between the identity and
ballot databases: ballots are stored against an anonymous credential hash,
never a voter id, so no join between them is possible.

SR-11 / SR-19: the ledger and audit tables are append-only - SQL triggers
abort any UPDATE or DELETE, and both are hash-chained so tampering that
bypasses the triggers (e.g. editing the file directly) is still detected.
"""
import sqlite3
from contextlib import contextmanager
from pathlib import Path

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
CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    state TEXT,
    password_hash TEXT NOT NULL,
    totp_secret_enc TEXT NOT NULL,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    last_totp_counter INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    state TEXT,
    created REAL NOT NULL,
    last_active REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS terminals (
    id TEXT PRIMARY KEY,
    location TEXT NOT NULL,
    last_heartbeat REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unknown'
);
CREATE TABLE IF NOT EXISTS api_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    key_hash TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,              -- 'exclude_candidate' | 'recount'
    target TEXT,
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    request_id INTEGER NOT NULL,
    approver TEXT NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY (request_id, approver)
);
"""

BALLOT_SCHEMA = """
CREATE TABLE IF NOT EXISTS election (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS groups (
    code TEXT PRIMARY KEY, name TEXT NOT NULL, position INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    party TEXT NOT NULL,
    group_code TEXT,
    position INTEGER NOT NULL,
    state TEXT NOT NULL,
    excluded INTEGER NOT NULL DEFAULT 0
);
-- No voter id, no timestamp, random primary key (SR-07, SR-09)
CREATE TABLE IF NOT EXISTS ballots (
    id TEXT PRIMARY KEY,
    credential_hash TEXT NOT NULL,
    envelope TEXT NOT NULL,
    signature TEXT NOT NULL,
    ballot_hash TEXT NOT NULL,
    superseded INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_ballots_cred ON ballots(credential_hash);
-- SR-09 mixing pool: accepted ballots wait here until a batch is full, then the
-- batch is shuffled before it enters the ballot store and ledger, so storage
-- and ledger order no longer follow submission order.
CREATE TABLE IF NOT EXISTS ballot_pool (
    id TEXT PRIMARY KEY,
    credential_hash TEXT NOT NULL,
    envelope TEXT NOT NULL,
    signature TEXT NOT NULL,
    ballot_hash TEXT NOT NULL,
    superseded INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ledger (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,              -- 'ballot' | 'batch'
    item_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TABLE IF NOT EXISTS receipts (
    code TEXT PRIMARY KEY,
    issued_hour TEXT NOT NULL,       -- coarse timestamp only (SR-09 vs SR-15)
    key_version INTEGER NOT NULL,
    signature TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload TEXT NOT NULL,
    key_version INTEGER NOT NULL,
    signature TEXT NOT NULL
);
"""

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    mac_version INTEGER NOT NULL,
    mac TEXT NOT NULL
);
-- SR-19: the audit log is append-only; the database itself rejects UPDATE and DELETE
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    severity TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);
"""


class Databases:
    def __init__(self, data_dir: Path, cfg):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.paths = {
            "identity": self.data_dir / cfg.IDENTITY_DB,
            "ballot": self.data_dir / cfg.BALLOT_DB,
            "audit": self.data_dir / cfg.AUDIT_DB,
        }
        for name, schema in (("identity", IDENTITY_SCHEMA), ("ballot", BALLOT_SCHEMA),
                             ("audit", AUDIT_SCHEMA)):
            with self.connect(name) as conn:
                conn.executescript(schema)

    @contextmanager
    def connect(self, name):
        conn = sqlite3.connect(self.paths[name], timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self, name):
        """BEGIN IMMEDIATE takes the write lock up front, which makes
        check-then-update sequences (e.g. double-vote checks) atomic."""
        with self.connect(name) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
