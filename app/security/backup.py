"""Encrypted backup and restore of election data (SR-23).

Uses SQLite's online backup API (consistent snapshot while running), packs the
three databases into a tar archive and encrypts it with AES-256-GCM using the
'backup' key from the KeyManager. The keystore itself is NOT included - it is
escrowed separately (in production: HSM backup), so a stolen backup is useless.
"""
import io
import json
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"EVBK1"


def create_backup(dbs, keys, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, path in dbs.paths.items():
            snap = Path(tmp) / path.name
            src, dst = sqlite3.connect(path), sqlite3.connect(snap)
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
            tar.add(snap, arcname=path.name)
    version, blob = keys.backup_encrypt(buf.getvalue())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = out_dir / f"evote-backup-{stamp}.bin"
    header = json.dumps({"key_version": version}).encode()
    out.write_bytes(MAGIC + len(header).to_bytes(2, "big") + header + blob)
    return out


def restore_backup(keys, backup_file: Path, target_dir: Path) -> list:
    raw = Path(backup_file).read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError("not an e-vote backup file")
    hlen = int.from_bytes(raw[5:7], "big")
    header = json.loads(raw[7:7 + hlen])
    plain = keys.backup_decrypt(header["key_version"], raw[7 + hlen:])  # raises if tampered
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    restored = []
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        for member in tar.getmembers():
            # guard against path traversal in archive names
            if not member.isfile() or "/" in member.name or member.name.startswith("."):
                raise ValueError(f"unsafe archive member {member.name}")
            data = tar.extractfile(member).read()
            (target_dir / member.name).write_bytes(data)
            restored.append(member.name)
    return restored
