"""Print the current one-time code for a demo voter or staff member
(stands in for the authenticator app during the demo).

    python tools/totp_code.py NSW1000001
    python tools/totp_code.py admin1
    python tools/totp_code.py admin1 --uri     # otpauth:// link to add to a real authenticator app
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.config import Config               # noqa: E402
from app.security import totp               # noqa: E402


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    who = sys.argv[1]
    creds = json.loads((Path(Config.DATA_DIR) / "demo_credentials.json").read_text())
    entry = creds["voters"].get(who.upper()) or creds["staff"].get(who)
    if not entry:
        raise SystemExit(f"unknown demo account {who}")
    if "--uri" in sys.argv:
        print(totp.provisioning_uri(entry["totp_secret"], who))
        return
    remaining = 30 - int(time.time()) % 30
    print(f"{totp.now_code(entry['totp_secret'])}   (valid for {remaining}s)")


if __name__ == "__main__":
    main()
