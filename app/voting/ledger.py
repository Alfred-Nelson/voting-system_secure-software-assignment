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
