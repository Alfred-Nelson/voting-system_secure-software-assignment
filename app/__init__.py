"""Application factory for the Secure E-Voting prototype."""
import logging
import os
import secrets
from pathlib import Path

log = logging.getLogger("evote")


def _master_key(cfg, data_dir: Path) -> bytes:
    if cfg.MASTER_KEY_HEX:
        return bytes.fromhex(cfg.MASTER_KEY_HEX)
    # Development fallback only - production must inject the key from an HSM / secret store.
    path = data_dir / "DEV_ONLY_master.key"
    if not path.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(32))
        os.chmod(path, 0o600)
        log.warning("Generated a development master key at %s - never do this in production", path)
    return bytes.fromhex(path.read_text().strip())
