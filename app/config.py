"""Central security configuration - every security-relevant number lives here
so it can be reviewed in one place. Secrets come only from the environment;
there are no default secret values in source code."""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_list(name: str) -> tuple:
    return tuple(item.strip() for item in os.environ.get(name, "").split(",") if item.strip())


class Config:
    # ---- Storage
    DATA_DIR = os.path.abspath(os.environ.get("EVOTE_DATA_DIR") or os.path.join(BASE_DIR, "data"))
    IDENTITY_DB = os.path.join(DATA_DIR, "identity.db")
    BALLOT_DB = os.path.join(DATA_DIR, "ballots.db")
    AUDIT_DB = os.path.join(DATA_DIR, "audit.db")
    KEYSTORE_FILE = os.path.join(DATA_DIR, "keystore.json")

    # ---- Keys (secret supplied via environment only; empty means "not configured")
    MASTER_KEY_HEX = os.environ.get("EVOTE_MASTER_KEY", "")
    KEY_ROTATION_DAYS = 90

    # ---- Authentication and sessions (SR-02)
    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 15
    PRIVILEGED_IDLE_TIMEOUT_SEC = 180
    VOTER_IDLE_TIMEOUT_SEC = 600
    TOTP_STEP_SEC = 30
    TOTP_DIGITS = 6

    # ---- Ballots
    BALLOT_PAD_BYTES = 2048
    LEDGER_BATCH_SIZE = 1000
    MIX_BATCH_SIZE = 10

    # ---- Rate limits (requests per minute)
    RESULTS_API_LIMIT_PER_MIN = 100
    LOGIN_LIMIT_PER_MIN = 20
    BALLOT_LIMIT_PER_MIN = 60

    # ---- Monitoring
    TERMINAL_OFFLINE_SEC = 60
    FAILED_LOGIN_ALERT_THRESHOLD = 3

    # ---- Missions and build. Networks are comma-separated CIDRs; empty allows none.
    MISSION_ALLOWED_NETWORKS = _env_list("EVOTE_MISSION_NETWORKS")
    REQUIRE_SIGNED_BUILD = _env_bool("EVOTE_REQUIRE_SIGNED_BUILD", True)

    # ---- Election
    ELECTION_STATE = "NSW"
    VACANCIES = 2
    TESTING = False

    @classmethod
    def ensure_data_dir(cls) -> str:
        """Create the data directory (owner-only on POSIX) if it does not exist."""
        os.makedirs(cls.DATA_DIR, mode=0o700, exist_ok=True)
        return cls.DATA_DIR


class TestConfig(Config):
    """Used by the automated tests only."""
    TESTING = True
    MIX_BATCH_SIZE = 1
    LOGIN_LIMIT_PER_MIN = 10_000
    BALLOT_LIMIT_PER_MIN = 10_000


Config.ensure_data_dir()
