"""Software integrity / signed builds (SR-25).

The release pipeline (tools/sign_release.py, run in CI) hashes every file of
the application and signs the manifest with the release key (Ed25519). On
start-up the server re-hashes its own code and refuses to run if any file was
added, removed or changed, or if the manifest signature is invalid.
"""
import hashlib
from pathlib import Path

TRACKED_SUFFIXES = {".py", ".js", ".html", ".css"}


def build_manifest(app_dir: Path) -> dict:
    files = {}
    for path in sorted(Path(app_dir).rglob("*")):
        if path.is_file() and path.suffix in TRACKED_SUFFIXES and "__pycache__" not in path.parts:
            rel = path.relative_to(app_dir).as_posix()
            files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"version": 1, "files": files}
