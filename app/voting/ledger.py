"""Tamper-evident ballot ledger and pre-tally integrity check (SR-11).

* Every accepted ballot's SHA-256 hash is appended to a hash-chained,
  append-only ledger.
* Every `batch_size` ballots a batch checksum entry is added, so a monitoring
  job can check recent batches quickly.
* verify() re-hashes every stored ballot and checks (a) the chain is unbroken,
  (b) every stored ballot is in the ledger with an identical hash and
  (c) the ledger contains no ballot that has disappeared from the store.
  The tally refuses to run unless verify() passes.
"""
import hashlib

from ..security.crypto import canonical_json

GENESIS = "0" * 64


def ballot_hash(credential_hash, envelope_json, signature):
    return hashlib.sha256(canonical_json([credential_hash, envelope_json, signature])).hexdigest()


def _entry_hash(prev, kind, item):
    return hashlib.sha256(f"{prev}|{kind}|{item}".encode()).hexdigest()


class Ledger:
    def __init__(self, dbs, batch_size=1000):
        self.dbs = dbs
        self.batch_size = batch_size

    def append_in(self, conn, item_hash):
        """Append inside the caller's transaction (so ballot + ledger commit together)."""
        row = conn.execute("SELECT entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["entry_hash"] if row else GENESIS
        entry = _entry_hash(prev, "ballot", item_hash)
        conn.execute("INSERT INTO ledger (kind, item_hash, prev_hash, entry_hash) VALUES (?,?,?,?)",
                     ("ballot", item_hash, prev, entry))
        count = conn.execute("SELECT COUNT(*) FROM ledger WHERE kind='ballot'").fetchone()[0]
        if count % self.batch_size == 0:
            hashes = [r[0] for r in conn.execute(
                "SELECT item_hash FROM ledger WHERE kind='ballot' ORDER BY seq DESC LIMIT ?",
                (self.batch_size,))]
            checksum = hashlib.sha256("".join(reversed(hashes)).encode()).hexdigest()
            batch_entry = _entry_hash(entry, "batch", checksum)
            conn.execute("INSERT INTO ledger (kind, item_hash, prev_hash, entry_hash) "
                         "VALUES (?,?,?,?)", ("batch", checksum, entry, batch_entry))
        return entry
