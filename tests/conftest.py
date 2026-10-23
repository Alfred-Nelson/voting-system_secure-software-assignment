import secrets
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app                    # noqa: E402
from app.config import TestConfig             # noqa: E402
from app.security import totp                 # noqa: E402
from app.seed import seed                     # noqa: E402
from client.voter_client import FlaskTransport, VoterClient  # noqa: E402


class _Cfg(TestConfig):
    MASTER_KEY_HEX = secrets.token_hex(32)
    LEDGER_BATCH_SIZE = 3


@pytest.fixture
def app(tmp_path):
    return create_app(_Cfg, tmp_path / "data")


@pytest.fixture
def svc(app):
    return app.evote


@pytest.fixture
def creds(svc):
    return seed(svc)


@pytest.fixture
def http(app):
    return app.test_client()


class Helper:
    """Login helpers. TOTP codes can't be replayed, so each login by the same
    account uses the next time-step (the server accepts +/-1 step of drift)."""

    def __init__(self, app, http, creds):
        self.app, self.http, self.creds = app, http, creds
        self._last = {}
        self._headers = {}

    def code(self, who):
        e = self.creds["voters"].get(who) or self.creds["staff"].get(who)
        now_step = int(time.time() // 30)
        step = max(now_step, self._last.get(who, -1) + 1)
        assert step <= now_step + 1, "test logs in the same account too often"
        self._last[who] = step
        return totp.now_code(e["totp_secret"], at=step * 30 + 1)

    def staff(self, user, fresh=False):
        if not fresh and user in self._headers:
            return self._headers[user]
        r = self.http.post("/api/auth/staff/login", json={
            "username": user, "password": self.creds["staff_password"], "totp": self.code(user)})
        assert r.status_code == 200, r.get_json()
        self._headers[user] = {"Authorization": "Bearer " + r.get_json()["token"]}
        return self._headers[user]

    def voter(self, enrol, **kw):
        v = VoterClient(FlaskTransport(self.http), **kw)
        v.login(enrol, self.creds["voter_password"], self.code(enrol))
        return v

    def open_polls(self):
        r = self.http.post("/api/admin/election/status", json={"status": "open"},
                           headers=self.staff("admin1"))
        assert r.status_code == 200


@pytest.fixture
def h(app, http, creds):
    return Helper(app, http, creds)
