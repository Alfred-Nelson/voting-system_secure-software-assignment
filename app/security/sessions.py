"""Server-side sessions with idle timeout (SR-02).

Tokens are 256-bit random values. Only their SHA-256 hash is stored, so a
leaked database does not leak usable session tokens.
"""

PRIVILEGED_ROLES = {"employee", "delegate", "admin", "auditor"}
