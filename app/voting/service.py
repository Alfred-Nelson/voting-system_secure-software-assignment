"""Election service - the voting subsystem's business logic.

Flow:
  identity side  : login (MFA) -> eligibility check -> double-vote check ->
                   blind-sign the voter's anonymous credential
"""
from datetime import date

from ..security import blind
from ..security.crypto import CryptoError
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

    # ------------------------------------------------------------ election config
    def get(self, key, default=None):
        with self.dbs.connect("ballot") as conn:
            row = conn.execute("SELECT value FROM election WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set(self, key, value):
        with self.dbs.connect("ballot") as conn:
            conn.execute("INSERT INTO election (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))

    def status(self):
        return self.get("status", "setup")

    def set_status(self, new_status, actor, role):
        allowed = {"setup": {"open"}, "open": {"closed"}, "closed": set()}
        old = self.status()
        if new_status not in allowed.get(old, set()):
            raise VotingError(f"cannot change election from '{old}' to '{new_status}'")
        self.set("status", new_status)
        self.audit.record("election.status_changed", actor, role,
                          {"before": old, "after": new_status})
        self.monitor.alert("info", "config.change",
                           f"Election status changed {old} -> {new_status} by {actor}")

    def ballot_paper(self):
        with self.dbs.connect("ballot") as conn:
            groups = [dict(r) for r in conn.execute("SELECT * FROM groups ORDER BY position")]
            cands = [dict(r) for r in conn.execute(
                "SELECT id, name, party, group_code, position, state, excluded FROM candidates "
                "WHERE state = ? ORDER BY CASE WHEN group_code IS NULL THEN 1 ELSE 0 END, "
                "group_code, position", (self.cfg.ELECTION_STATE,))]
        for g in groups:
            g["candidates"] = [c["id"] for c in cands if c["group_code"] == g["code"]]
        return groups, cands

    def public_info(self):
        groups, cands = self.ballot_paper()
        n, e = self.keys.blind_public()
        return {
            "status": self.status(),
            "state": self.cfg.ELECTION_STATE,
            "vacancies": self.cfg.VACANCIES,
            "groups": groups,
            "candidates": cands,
            "pad_bytes": self.cfg.BALLOT_PAD_BYTES,
            "keys": {
                "blind_n": format(n, "x"),
                "blind_e": format(e, "x"),
                "ballot_encryption_pem": self.keys.ballot_public_pem(),
                "receipt_verify_pem": self.keys.public_key_pem("receipt_sign"),
            },
        }

    # ------------------------------------------------------------ identity side
    def _check_eligible(self, voter):
        """SR-03: enrolled, 18+, enrolled in the state holding this election."""
        fc = self.keys.field_cipher()
        dob = fc.decrypt(voter["dob_enc"], "dob")
        if not voter["enrolled"]:
            return "not on the electoral roll"
        if _age(dob) < 18:
            return "under 18"
        if voter["state"] != self.cfg.ELECTION_STATE:
            return f"enrolled in {voter['state']}, not {self.cfg.ELECTION_STATE}"
        return None

    def issue_credential(self, voter_id, blinded_hex):
        """SR-03 + SR-04 + SR-07. Atomic: the voter row is locked while checking
        and the status flag is set in the same transaction."""
        if self.status() != "open":
            raise VotingError("voting is not open", 409)
        try:
            blinded = int(blinded_hex, 16)
        except (TypeError, ValueError):
            raise VotingError("blinded value must be hex")
        with self.dbs.transaction("identity") as conn:
            voter = conn.execute("SELECT * FROM voters WHERE id = ?", (voter_id,)).fetchone()
            if voter is None:
                raise VotingError("unknown voter", 404)
            reason = self._check_eligible(voter)
            if reason:
                self.audit.record("eligibility.denied", f"voter:{voter_id}", "voter",
                                  {"reason": reason})
                raise VotingError(f"not eligible: {reason}", 403)
            if voter["token_issued"] or voter["voted_channel"]:
                channel = voter["voted_channel"] or "online"
                self.audit.record("double_vote.blocked", f"voter:{voter_id}", "voter",
                                  {"existing_channel": channel, "attempted": "online"})
                raise VotingError(f"already voted ({channel}). To change an online vote, "
                                  "re-submit using the credential stored on your device.", 409)
            try:
                signature = self.keys.blind_sign(blinded)
            except CryptoError as exc:
                raise VotingError(str(exc))
            conn.execute("UPDATE voters SET token_issued = 1 WHERE id = ?", (voter_id,))
        return format(signature, "x")
