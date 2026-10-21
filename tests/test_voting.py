"""SR-06 - personal data encrypted at rest (the voting-flow tests are added in later issues)."""


def test_pii_encrypted_in_identity_db(svc, creds):                          # SR-06
    raw = (svc.dbs.paths["identity"]).read_bytes()
    assert b"Aisha Rahman" not in raw and b"George St" not in raw and b"NSW1000001" not in raw
