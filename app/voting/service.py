"""Election service - the voting subsystem's business logic.

Flow:
  identity side  : login (MFA) -> eligibility check -> double-vote check ->
                   blind-sign the voter's anonymous credential
"""
import json
import uuid
from datetime import date, datetime, timezone

from ..security import blind
from ..security.crypto import (CryptoError, b64d, ecdsa_verify_raw, envelope_signing_bytes,
                               load_spki, sha256_hex)
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
        # No blinded value or signature is logged - nothing that could link later.
        self.audit.record("credential.issued", f"voter:{voter_id}", "voter", {})
        return format(signature, "x")

    def mark_offline_vote(self, enrolment_id, channel, staff_user):
        """SR-04 cross-channel: polling station / postal votes."""
        if channel not in ("station", "postal"):
            raise VotingError("channel must be 'station' or 'postal'")
        fc = self.keys.field_cipher()
        with self.dbs.transaction("identity") as conn:
            voter = conn.execute("SELECT * FROM voters WHERE enrol_index = ?",
                                 (fc.blind_index(enrolment_id),)).fetchone()
            if voter is None:
                raise VotingError("voter not found on roll", 404)
            reason = self._check_eligible(voter)
            if reason:
                raise VotingError(f"not eligible: {reason}", 403)
            if voter["token_issued"] or voter["voted_channel"]:
                existing = voter["voted_channel"] or "online"
                self.audit.record("double_vote.blocked", staff_user, "employee",
                                  {"voter": voter["id"], "existing_channel": existing,
                                   "attempted": channel})
                self.monitor.alert("medium", "double_vote",
                                   f"Second-channel vote attempt ({channel}) for a voter who "
                                   f"already voted ({existing})")
                raise VotingError(f"voter has already voted ({existing})", 409)
            conn.execute("UPDATE voters SET voted_channel = ? WHERE id = ?", (channel, voter["id"]))
        self.audit.record("vote.marked_offline", staff_user, "employee",
                          {"voter": voter["id"], "channel": channel})

    # ------------------------------------------------------------ ballot side (anonymous)
    def submit_ballot(self, credential_b64, token_hex, envelope, signature_b64):
        if self.status() != "open":
            raise VotingError("voting is not open", 409)
        try:
            spki = b64d(credential_b64)
            cred_key = load_spki(spki)
            n, e = self.keys.blind_public()
            token = int(token_hex, 16)
            if not blind.verify(blind.message_int(spki, n), token, n, e):
                raise VotingError("credential was not issued by the AEC", 403)
            if not isinstance(envelope, dict) or set(envelope) != {"wrapped_key", "iv",
                                                                   "ciphertext"}:
                raise VotingError("malformed ballot envelope")
            # SR-09: every ballot must use the fixed-size envelope
            if len(b64d(envelope["ciphertext"])) != self.cfg.BALLOT_PAD_BYTES + 16:
                raise VotingError("ballot envelope has the wrong size")
            ecdsa_verify_raw(cred_key, b64d(signature_b64), envelope_signing_bytes(envelope))
        except CryptoError as exc:
            self.audit.record("ballot.rejected", "anonymous", "voter", {"reason": str(exc)})
            raise VotingError(f"ballot rejected: {exc}", 400)
        except (TypeError, ValueError):
            raise VotingError("malformed ballot submission")

        credential_hash = sha256_hex(spki)
        envelope_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        bh = ballot_hash(credential_hash, envelope_json, signature_b64)
        with self.dbs.transaction("ballot") as conn:
            for table in ("ballots", "ballot_pool"):
                if conn.execute(f"SELECT 1 FROM {table} WHERE ballot_hash = ?",  # nosec B608
                                (bh,)).fetchone():
                    raise VotingError("duplicate ballot (replay)", 409)
            # SR-30: a newer ballot from the same anonymous credential replaces the older one
            for table in ("ballots", "ballot_pool"):
                conn.execute(f"UPDATE {table} SET superseded = 1 WHERE credential_hash = ? "  # nosec B608
                             "AND superseded = 0", (credential_hash,))
            # SR-09: random id, no timestamp - storage order reveals nothing about arrival order
            conn.execute("INSERT INTO ballot_pool (id, credential_hash, envelope, signature, "
                         "ballot_hash) VALUES (?,?,?,?,?)",
                         (str(uuid.uuid4()), credential_hash, envelope_json, signature_b64, bh))
            receipt = self._issue_receipt(conn, bh)
        # Nothing is audited per ballot: a per-ballot audit entry would put a timestamp
        # next to each submission and let someone line it up with logins (SR-07, SR-09).
        return receipt

    def _issue_receipt(self, conn, bh):
        """SR-15: receipt code derived from the ballot hash; reveals nothing about
        the vote. Coarse (hourly) timestamp only, to respect SR-09."""
        code = "-".join(bh[i:i + 4].upper() for i in range(0, 20, 4))
        hour = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00Z")
        version, sig = self.keys.sign("receipt_sign", f"{code}|{hour}".encode())
        conn.execute("INSERT INTO receipts VALUES (?,?,?,?)", (code, hour, version, sig))
        return {"receipt": code, "issued_hour": hour, "key_version": version, "signature": sig}
