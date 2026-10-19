"""Application factory for the Secure E-Voting prototype."""
import logging
import os
import secrets
from pathlib import Path
from types import SimpleNamespace

from flask import Flask

from .config import Config
from .db import Databases
from .security.audit import AuditLog
from .security.keys import KeyManager
from .security.monitor import Monitor

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


def create_app(config_object=Config, data_dir=None):
    cfg = config_object
    data_dir = Path(data_dir or cfg.DATA_DIR)
    app = Flask(__name__)
    app.config.from_object(cfg)

    dbs = Databases(data_dir, cfg)
    svc = SimpleNamespace(cfg=cfg, dbs=dbs)
    # Audit log needs the key manager and vice versa (key rotation is audited).
    holder = {}
    svc.keys = KeyManager(data_dir / cfg.KEYSTORE_FILE, _master_key(cfg, data_dir),
                          cfg.KEY_ROTATION_DAYS,
                          on_event=lambda action, actor, details: holder["audit"].record(
                              action, actor, "admin", details))
    svc.audit = holder["audit"] = AuditLog(dbs, svc.keys)
    svc.monitor = Monitor(dbs, svc.audit, cfg)
    app.evote = svc

    return app
