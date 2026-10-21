"""Reset the data folder and load the fictional demo election.

    python tools/setup_demo.py

Writes data/demo_credentials.json (demo passwords + TOTP secrets). That file
is for the demo only and is git-ignored.
"""
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app          # noqa: E402
from app.config import Config      # noqa: E402
from app.seed import seed           # noqa: E402


def main():
    data = Path(Config.DATA_DIR)
    if data.exists():
        keep = data / "DEV_ONLY_master.key"
        master = keep.read_text() if keep.exists() else None
        shutil.rmtree(data)
        if master:
            data.mkdir(parents=True)
            keep.write_text(master)
    app = create_app()
    creds = seed(app.evote)
    out = data / "demo_credentials.json"
    out.write_text(json.dumps(creds, indent=2))
    print(f"Demo election created. Credentials written to {out}\n")
    print(f"Voter password : {creds['voter_password']}   (all demo voters)")
    print(f"Staff password : {creds['staff_password']}   (all demo staff)")
    print("Voters         :", ", ".join(k + (" [" + v["note"] + "]" if v["note"] else "")
                                       for k, v in creds["voters"].items()))
    print("Staff          :", ", ".join(f"{k} ({v['role']}{'/' + v['state'] if v['state'] else ''})"
                                       for k, v in creds["staff"].items()))
    print(f"Results API key: {creds['results_api_key']}")
    print("\nGet a one-time code with:  python tools/totp_code.py <enrolment-id or username>")


if __name__ == "__main__":
    main()
