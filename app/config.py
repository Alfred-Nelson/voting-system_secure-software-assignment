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
