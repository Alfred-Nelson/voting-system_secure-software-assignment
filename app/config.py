"""Central configuration for the Secure E-Voting prototype.

Every security-relevant number from the Part One requirements lives here so it
can be reviewed in one place (and changed without touching code).
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    """Settings are added section by section (storage, keys, authentication, ballots)."""
