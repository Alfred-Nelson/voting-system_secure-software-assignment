"""Multi-factor authentication (SR-01 voters, SR-02 privileged users).

* Password (scrypt) AND a 6-digit TOTP code are both required - a request
  with only one factor is rejected and audited.
* TOTP codes cannot be replayed (the last used time-step is stored).
* After MAX_FAILED_LOGINS failures the account is locked for LOCKOUT_MINUTES
  and the security team is alerted (SR-20).
* Error messages never reveal which factor was wrong or whether the account
  exists (prevents enumeration).
"""


class AuthError(Exception):
    pass


GENERIC = "invalid credentials"


class Authenticator:
    def __init__(self, dbs, keys, audit, monitor, sessions, cfg):
        self.dbs, self.keys, self.audit = dbs, keys, audit
        self.monitor, self.sessions, self.cfg = monitor, sessions, cfg

    def _login(self, table, lookup_col, lookup_val, actor, password, code, role_of):
        if not password or not code:
            self.audit.record("auth.rejected_single_factor", actor, "unknown",
                              {"has_password": bool(password), "has_totp": bool(code)})
            raise AuthError("password and one-time code are both required")
