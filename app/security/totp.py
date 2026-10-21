"""Time-based one-time passwords, RFC 6238 (SR-01, SR-02 second factor).

Compatible with Google Authenticator / Microsoft Authenticator via the
otpauth:// provisioning URI.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret_b32: str, counter: int, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def now_code(secret_b32: str, at: float = None, step: int = 30) -> str:
    return _code(secret_b32, int((at or time.time()) // step))


def verify(secret_b32: str, code: str, at: float = None, step: int = 30, window: int = 1):
    """Accepts the current code and +/- `window` steps for clock drift.
    Returns the matching time-step counter (so callers can block replay) or None."""
    if not code or not code.isdigit() or len(code) != 6:
        return None
    counter = int((at or time.time()) // step)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(_code(secret_b32, counter + drift), code):
            return counter + drift
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str = "AEC-eVote-Prototype") -> str:
    return (f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&digits=6&period=30")
