"""Reference voter client - what runs on the voter's device / polling terminal.

The browser UI does exactly the same steps with WebCrypto. This Python version
is used by the unit tests, the CLI demo and overseas mission terminals.
"""


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
