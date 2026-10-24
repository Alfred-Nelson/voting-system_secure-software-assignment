"""Software integrity / signed builds (SR-25).

The release pipeline (tools/sign_release.py, run in CI) hashes every file of
the application and signs the manifest with the release key (Ed25519). On
start-up the server re-hashes its own code and refuses to run if any file was
added, removed or changed, or if the manifest signature is invalid.
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .crypto import b64d

TRACKED_SUFFIXES = {".py", ".js", ".html", ".css"}


def build_manifest(app_dir: Path) -> dict:
    files = {}
    for path in sorted(Path(app_dir).rglob("*")):
        if path.is_file() and path.suffix in TRACKED_SUFFIXES and "__pycache__" not in path.parts:
            rel = path.relative_to(app_dir).as_posix()
            files[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"version": 1, "files": files}


def manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def verify_release(app_dir: Path, manifest_path: Path, public_key_path: Path):
    """Returns (ok: bool, reason: str)."""
    if not manifest_path.exists() or not public_key_path.exists():
        return False, "release manifest or public key missing"
    signed = json.loads(manifest_path.read_text())
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    try:
        public_key.verify(b64d(signed["signature"]), manifest_bytes(signed["manifest"]))
    except Exception:
        return False, "manifest signature invalid"
    current = build_manifest(app_dir)["files"]
    expected = signed["manifest"]["files"]
    changed = sorted(k for k in set(current) | set(expected) if current.get(k) != expected.get(k))
    if changed:
        return False, f"code differs from signed release: {', '.join(changed[:5])}"
    return True, "signed build verified"
