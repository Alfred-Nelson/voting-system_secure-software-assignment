"""Chaum RSA blind signatures (SR-07: cryptographic separation of voter and vote).

Protocol
  1. Voter device creates an anonymous credential (ECDSA key pair) and computes
     m = SHA-256(credential public key) mod n.
  2. Device picks random r and sends the *blinded* value  m' = m * r^e mod n.
  3. The authority checks eligibility / double voting, then signs blindly:
     s' = (m')^d mod n. It never sees m.
  4. Device unblinds: s = s' * r^-1 mod n, which is a valid signature on m.
  5. The ballot is submitted with (credential, s). The server can verify that an
     eligible voter was issued this credential but cannot tell which one.
"""
import hashlib
import secrets
from math import gcd
