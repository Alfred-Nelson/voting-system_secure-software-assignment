"""Application factory for the Secure E-Voting prototype."""
import logging
import os
import secrets
from pathlib import Path
from types import SimpleNamespace

from flask import Flask, jsonify, request

from .config import Config
from .db import Databases
from .security.audit import AuditLog
from .security.auth import Authenticator
from .security.keys import KeyManager
from .security.monitor import Monitor
from .security.ratelimit import RateLimiter
from .security.sessions import SessionStore
from .voting.ledger import Ledger
from .voting.service import ElectionService
from .routes import admin, auth, ballots, public

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
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024   # reject oversized requests early

    dbs = Databases(data_dir, cfg)
    svc = SimpleNamespace(cfg=cfg, dbs=dbs, limiter=RateLimiter())
    # Audit log needs the key manager and vice versa (key rotation is audited).
    holder = {}
    svc.keys = KeyManager(data_dir / cfg.KEYSTORE_FILE, _master_key(cfg, data_dir),
                          cfg.KEY_ROTATION_DAYS,
                          on_event=lambda action, actor, details: holder["audit"].record(
                              action, actor, "admin", details))
    svc.audit = holder["audit"] = AuditLog(dbs, svc.keys)
    svc.monitor = Monitor(dbs, svc.audit, cfg)
    svc.sessions = SessionStore(dbs, cfg)
    svc.auth = Authenticator(dbs, svc.keys, svc.audit, svc.monitor, svc.sessions, cfg)
    svc.ledger = Ledger(dbs, cfg.LEDGER_BATCH_SIZE)
    svc.election = ElectionService(dbs, svc.keys, svc.audit, svc.monitor, svc.ledger, cfg)
    app.evote = svc

    due = svc.keys.needs_rotation()
    if due:
        svc.monitor.alert("medium", "keys.rotation_due", f"Keys due for 90-day rotation: {due}")

    for bp in (admin.bp, auth.bp, ballots.bp, public.bp):
        app.register_blueprint(bp)

    @app.after_request
    def security_headers(resp):
        # SR-05 / general hardening
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def bad_method(_):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def too_large(_):
        return jsonify(error="request too large"), 413

    @app.errorhandler(500)
    def server_error(_):
        # never leak stack traces to clients
        return jsonify(error="internal error"), 500

    return app
