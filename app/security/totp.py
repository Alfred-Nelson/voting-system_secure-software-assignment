"""Time-based one-time passwords, RFC 6238 (SR-01, SR-02 second factor)."""
import base64
import secrets


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
