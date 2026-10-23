"""Reference voter client - what runs on the voter's device / polling terminal.

The browser UI does exactly the same steps with WebCrypto. This Python version
is used by the unit tests, the CLI demo and overseas mission terminals.
"""
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.security import blind
from app.security.crypto import (ecdsa_sign_raw, envelope_signing_bytes, hybrid_encrypt,
                                 pad_fixed)
from app.voting import formality


class ClientError(Exception):
    pass


# ------------------------------------------------------------------ transports
class FlaskTransport:
    """Wraps a Flask test client (unit tests)."""

    def __init__(self, client, remote_addr="127.0.0.1"):
        self.client = client
        self.remote_addr = remote_addr

    def request(self, method, path, json_body=None, headers=None):
        resp = self.client.open(path, method=method, json=json_body, headers=headers or {},
                                environ_base={"REMOTE_ADDR": self.remote_addr})
        return resp.status_code, resp.get_json(silent=True) or {}


class HttpTransport:
    """Talks to a running server over HTTPS (demo / terminals)."""

    def __init__(self, base_url, verify=True, timeout=10):
        import requests
        self.requests = requests
        self.base, self.verify, self.timeout = base_url.rstrip("/"), verify, timeout

    def request(self, method, path, json_body=None, headers=None):
        try:
            r = self.requests.request(method, self.base + path, json=json_body,
                                      headers=headers or {}, verify=self.verify,
                                      timeout=self.timeout)
        except self.requests.RequestException as exc:
            raise ConnectionError(str(exc)) from exc
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}


# ------------------------------------------------------------------ client
class VoterClient:
    def __init__(self, transport, wallet_path=None, queue_path=None, terminal_id=None):
        self.t = transport
        self.token = None
        self.election = None
        self.wallet_path = Path(wallet_path) if wallet_path else None
        self.queue_path = Path(queue_path) if queue_path else None
        self.terminal_id = terminal_id
        self.credential = self._load_wallet()

    # ---- helpers
    def _auth(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _check(self, status, data, ok=(200, 201)):
        if status not in ok:
            raise ClientError(f"{status}: {data.get('error', data)}")
        return data

    # ---- steps
    def login(self, enrolment_id, password, code):
        s, d = self.t.request("POST", "/api/auth/voter/login",
                              {"enrolment_id": enrolment_id, "password": password, "totp": code})
        self.token = self._check(s, d)["token"]
        return d

    def load_election(self):
        s, d = self.t.request("GET", "/api/election")
        self.election = self._check(s, d)
        return self.election

    def check_formality(self, ballot):
        e = self.election or self.load_election()
        groups = {g["code"]: g["candidates"] for g in e["groups"]}
        return formality.validate(ballot, groups, [c["id"] for c in e["candidates"]])

    def obtain_credential(self):
        """SR-07: blind-signature credential issuance."""
        e = self.election or self.load_election()
        n, ex = int(e["keys"]["blind_n"], 16), int(e["keys"]["blind_e"], 16)
        key = ec.generate_private_key(ec.SECP256R1())
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        m = blind.message_int(spki, n)
        blinded, r = blind.blind(m, n, ex)
        s, d = self.t.request("POST", "/api/voter/credential", {"blinded": format(blinded, "x")},
                              self._auth())
        sig = blind.unblind(int(self._check(s, d)["blind_signature"], 16), r, n)
        if not blind.verify(m, sig, n, ex):
            raise ClientError("authority returned an invalid blind signature")
        self.credential = {"key": key, "spki": spki, "token": format(sig, "x")}
        self._save_wallet()
        # Log out before voting - the ballot is sent with no session at all.
        self.t.request("POST", "/api/auth/logout", None, self._auth())
        self.token = None
        return self.credential

    def build_submission(self, ballot):
        e = self.election or self.load_election()
        result = self.check_formality(ballot)
        if not result.formal:
            raise ClientError("informal ballot: " + "; ".join(result.errors))
        pub = serialization.load_pem_public_key(e["keys"]["ballot_encryption_pem"].encode())
        plain = pad_fixed(json.dumps(ballot, sort_keys=True).encode(), e["pad_bytes"])
        envelope = hybrid_encrypt(pub, plain)
        sig = ecdsa_sign_raw(self.credential["key"], envelope_signing_bytes(envelope))
        return {"credential": base64.b64encode(self.credential["spki"]).decode(),
                "token": self.credential["token"], "envelope": envelope,
                "signature": base64.b64encode(sig).decode()}

    def cast(self, ballot):
        """Returns the receipt."""
        if not self.credential:
            self.obtain_credential()
        return self._submit(self.build_submission(ballot))

    def _submit(self, submission):
        headers = {"X-Terminal-Id": self.terminal_id} if self.terminal_id else {}
        s, d = self.t.request("POST", "/api/ballots", submission, headers)  # NO auth header
        return self._check(s, d)

    # ---- wallet: keeps the credential so the voter can re-vote (SR-30)
    def _save_wallet(self):
        if not self.wallet_path:
            return
        pem = self.credential["key"].private_bytes(serialization.Encoding.PEM,
                                                   serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption())
        self.wallet_path.write_text(json.dumps({"key": pem.decode(),
                                                "spki": base64.b64encode(self.credential["spki"]).decode(),
                                                "token": self.credential["token"]}))
        os.chmod(self.wallet_path, 0o600)
    def _load_wallet(self):
        if not self.wallet_path or not self.wallet_path.exists():
            return None
        w = json.loads(self.wallet_path.read_text())
        return {"key": serialization.load_pem_private_key(w["key"].encode(), None),
                "spki": base64.b64decode(w["spki"]), "token": w["token"]}
