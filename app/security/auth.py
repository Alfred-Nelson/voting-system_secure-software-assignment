"""Multi-factor authentication (SR-01 voters, SR-02 privileged users).

* Password (scrypt) AND a 6-digit TOTP code are both required - a request
  with only one factor is rejected and audited.
* TOTP codes cannot be replayed (the last used time-step is stored).
* After MAX_FAILED_LOGINS failures the account is locked for LOCKOUT_MINUTES
  and the security team is alerted (SR-20).
* Error messages never reveal which factor was wrong or whether the account
  exists (prevents enumeration).
"""
import time

from . import passwords


class AuthError(Exception):
    pass


GENERIC = "invalid credentials"


class Authenticator:
    def __init__(self, dbs, keys, audit, monitor, sessions, cfg):
        self.dbs, self.keys, self.audit = dbs, keys, audit
        self.monitor, self.sessions, self.cfg = monitor, sessions, cfg

    def _fail(self, conn, table, row, actor, role, reason):
        failures = row["failed_logins"] + 1
        locked_until = 0
        if failures >= self.cfg.MAX_FAILED_LOGINS:
            locked_until = time.time() + self.cfg.LOCKOUT_MINUTES * 60
        conn.execute(f"UPDATE {table} SET failed_logins = ?, locked_until = ? WHERE id = ?",  # nosec B608
                     (failures, locked_until, row["id"]))
        self.audit.record("auth.failed", actor, role, {"reason": reason, "failures": failures})
        if failures == self.cfg.FAILED_LOGIN_ALERT_THRESHOLD:
            self.monitor.alert("medium", "auth.repeated_failures",
                               f"{failures} failed logins for {actor}")
        if locked_until:
            self.monitor.alert("high", "auth.lockout", f"Account {actor} locked after "
                                                       f"{failures} failed logins")

    def _login(self, table, lookup_col, lookup_val, actor, password, code, role_of):
        if not password or not code:
            self.audit.record("auth.rejected_single_factor", actor, "unknown",
                              {"has_password": bool(password), "has_totp": bool(code)})
            raise AuthError("password and one-time code are both required")
        error = None   # raised only after the transaction commits, so failure counters persist
        with self.dbs.transaction("identity") as conn:
            row = conn.execute(f"SELECT * FROM {table} WHERE {lookup_col} = ?",  # nosec B608
                               (lookup_val,)).fetchone()
            if row is None:
                passwords.verify_password(password, passwords.DUMMY_HASH)  # equal timing
                self.audit.record("auth.failed", actor, "unknown", {"reason": "unknown account"})
                error = GENERIC
            else:
                role, state = role_of(row)
                if row["locked_until"] > time.time():
                    self.audit.record("auth.locked", actor, role, {})
                    error = "account temporarily locked - try again later"
                elif not passwords.verify_password(password, row["password_hash"]):
                    self._fail(conn, table, row, actor, role, "bad password")
                    error = GENERIC
        if error:
            raise AuthError(error)
