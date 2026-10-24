"""Create a signed release manifest (SR-25).

    python tools/sign_release.py            # uses RELEASE_SIGNING_KEY (base64 raw Ed25519) or creates a key
    EVOTE_REQUIRE_SIGNED_BUILD=1 python run.py    # server now refuses to start if code was changed

In CI the private key comes from a GitHub Actions secret; the public key is
committed at release/release_public.pem.
"""
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
from app.security.integrity import build_manifest, manifest_bytes  # noqa: E402


def main():
    rel = BASE / "release"
    rel.mkdir(exist_ok=True)
    env_key = os.environ.get("RELEASE_SIGNING_KEY")
    key_file = rel / "DEV_ONLY_release_private.key"
    if env_key:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(base64.b64decode(env_key))
    elif key_file.exists():
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(key_file.read_bytes())
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        key_file.write_bytes(priv.private_bytes(serialization.Encoding.Raw,
                                                serialization.PrivateFormat.Raw,
                                                serialization.NoEncryption()))
        os.chmod(key_file, 0o600)
        print(f"Created development release key {key_file} (git-ignored)")
    manifest = build_manifest(BASE / "app")
    sig = priv.sign(manifest_bytes(manifest))
    (rel / "manifest.json").write_text(json.dumps(
        {"manifest": manifest, "signature": base64.b64encode(sig).decode()}, indent=1))
    (rel / "release_public.pem").write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Signed manifest of {len(manifest['files'])} files -> release/manifest.json")


if __name__ == "__main__":
    main()
