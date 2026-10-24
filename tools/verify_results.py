"""Independent results verifier - what a media outlet runs (SR-14).

    python tools/verify_results.py http://127.0.0.1:5000 <API_KEY> [--insecure]

Fetches the signed results and verifies the Ed25519 signature locally.
"""
import base64
import json
import sys

import requests
from cryptography.hazmat.primitives import serialization


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    base, key = sys.argv[1].rstrip("/"), sys.argv[2]
    verify_tls = "--insecure" not in sys.argv
    r = requests.get(base + "/api/results", headers={"X-API-Key": key}, verify=verify_tls, timeout=10)
    r.raise_for_status()
    data = r.json()
    pub = serialization.load_pem_public_key(data["public_key_pem"].encode())
    payload = json.dumps(data["result"], sort_keys=True, separators=(",", ":")).encode()
    try:
        pub.verify(base64.b64decode(data["signature"]), payload)
    except Exception:
        raise SystemExit("SIGNATURE INVALID - results may have been altered")
    res = data["result"]
    print("Signature VALID (results_sign key v%s)" % data["key_version"])
    print("Elected:", ", ".join(res["elected"]), "| formal:", res["formal_ballots"],
          "| informal:", res["informal_ballots"], "| quota:", res["quota"])
    print("Input digest:", res["input_digest"])


if __name__ == "__main__":
    main()
