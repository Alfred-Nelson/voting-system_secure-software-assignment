"""Election service - the voting subsystem's business logic.

Flow:
  identity side  : login (MFA) -> eligibility check -> double-vote check ->
                   blind-sign the voter's anonymous credential
"""
from datetime import date

from ..security import blind
from .ledger import ballot_hash


class VotingError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _age(dob_iso, today=None):
    today = today or date.today()
    d = date.fromisoformat(dob_iso)
    return today.year - d.year - ((today.month, today.day) < (d.month, d.day))


class ElectionService:
    def __init__(self, dbs, keys, audit, monitor, ledger, cfg):
        self.dbs, self.keys, self.audit = dbs, keys, audit
        self.monitor, self.ledger, self.cfg = monitor, ledger, cfg
