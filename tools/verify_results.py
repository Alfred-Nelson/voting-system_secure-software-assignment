"""Independent results verifier - what a media outlet runs (SR-14).

    python tools/verify_results.py http://127.0.0.1:3776 <API_KEY> [--insecure] [--rounds]

Fetches the signed results and verifies the Ed25519 signature locally.
"""
import base64
import json
import re
import sys

import requests
from cryptography.hazmat.primitives import serialization


def make_labeller(res):
    """Return a function turning candidate ids into 'Name (Party)' using the signed lookup."""
    cands = res.get("candidates", {})   # older results have no lookup: ids are shown as-is

    def label(cid):
        c = cands.get(cid)
        return f"{c['name']} ({c['party']})" if c else cid

    pattern = re.compile(r"\b(" + "|".join(map(re.escape, cands)) + r")\b") if cands else None
    return label, (lambda text: pattern.sub(lambda m: label(m.group(1)), text) if pattern else text)


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
    label, label_text = make_labeller(res)
    print("Elected:", ", ".join(label(c) for c in res["elected"]), "| formal:", res["formal_ballots"],
          "| informal:", res["informal_ballots"], "| quota:", res["quota"])
    print("Input digest:", res["input_digest"])
    if "--rounds" in sys.argv:
        for rd in res["rounds"]:
            print(f"Round {rd['round']}: {label_text(rd['action'])}")
            for cid, total in rd["totals"].items():
                print(f"    {label(cid)}: {total}")


if __name__ == "__main__":
    main()
