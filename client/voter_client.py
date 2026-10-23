"""Reference voter client - what runs on the voter's device / polling terminal.

The browser UI does exactly the same steps with WebCrypto. This Python version
is used by the unit tests, the CLI demo and overseas mission terminals.
"""
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization


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

    # ---- wallet: keeps the credential so the voter can re-vote (SR-30)
    def _load_wallet(self):
        if not self.wallet_path or not self.wallet_path.exists():
            return None
        w = json.loads(self.wallet_path.read_text())
        return {"key": serialization.load_pem_private_key(w["key"].encode(), None),
                "spki": base64.b64decode(w["spki"]), "token": w["token"]}
