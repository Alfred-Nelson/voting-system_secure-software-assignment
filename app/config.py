"""Central configuration for the Secure E-Voting prototype.

Every security-relevant number from the Part One requirements lives here so it
can be reviewed in one place (and changed without touching code).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Settings are added section by section (storage, keys, authentication, ballots)."""

    # --- Storage (SR-08: identity, ballot and audit data are separate databases) ---
    DATA_DIR = Path(os.environ.get("EVOTE_DATA_DIR", BASE_DIR / "data"))
    IDENTITY_DB = "identity.db"
    BALLOT_DB = "ballot.db"
    AUDIT_DB = "audit.db"
    KEYSTORE_FILE = "keystore.json.enc"

    # --- Key management (SR-26) ---
    # In production the master key lives inside an HSM. Here it comes from the
    # environment so it is never written to the repository.
    MASTER_KEY_HEX = os.environ.get("EVOTE_MASTER_KEY")  # 64 hex chars = 256 bits
    KEY_ROTATION_DAYS = 90

    # --- Authentication (SR-01, SR-02) ---
    MAX_FAILED_LOGINS = 5            # account locked after this many failures
    LOCKOUT_MINUTES = 15
    PRIVILEGED_IDLE_TIMEOUT_SEC = 180   # SR-02: 3 minutes for staff accounts
    VOTER_IDLE_TIMEOUT_SEC = 600        # voters get 10 minutes to fill in a ballot
    TOTP_STEP_SEC = 30
    TOTP_DIGITS = 6

    # --- Ballot handling (SR-05, SR-09) ---
    BALLOT_PAD_BYTES = 2048          # every plaintext ballot padded to this size
    LEDGER_BATCH_SIZE = 1000         # SR-11 batch checksum interval
    MIX_BATCH_SIZE = 10              # SR-09 ballots shuffled in batches of this size

    # --- Rate limiting (SR-14, SR-21) ---
    RESULTS_API_LIMIT_PER_MIN = 100
    LOGIN_LIMIT_PER_MIN = 20
    BALLOT_LIMIT_PER_MIN = 60

    # --- Monitoring (SR-20) ---
    TERMINAL_OFFLINE_SEC = 60
    FAILED_LOGIN_ALERT_THRESHOLD = 3

    # --- Overseas missions (SR-24) ---
    MISSION_ALLOWED_NETWORKS = os.environ.get(
        "EVOTE_MISSION_NETWORKS", "127.0.0.0/8,10.20.0.0/16"
    ).split(",")

    # --- Software integrity (SR-25) ---
    REQUIRE_SIGNED_BUILD = os.environ.get("EVOTE_REQUIRE_SIGNED_BUILD", "0") == "1"

    # --- Election ---
    ELECTION_STATE = "NSW"
    VACANCIES = 2

    TESTING = False


class TestConfig(Config):
    TESTING = True
    MIX_BATCH_SIZE = 1
    LOGIN_LIMIT_PER_MIN = 1000
    BALLOT_LIMIT_PER_MIN = 1000
