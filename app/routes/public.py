"""Public pages, results API (SR-14) and terminal heartbeats (SR-20/22)."""
import hashlib

from flask import Blueprint, current_app, jsonify, request, send_from_directory

from ..security.ratelimit import limit
from .ballots import mission_network_ok
from . import body, svc

bp = Blueprint("public", __name__)


def _api_client():
    """Results consumers authenticate with an API key issued by the AEC.
    (Production: mutual TLS client certificates - see report.)"""
    key = request.headers.get("X-API-Key", "")
    if not key:
        return None
    with svc().dbs.connect("identity") as conn:
        row = conn.execute("SELECT name FROM api_clients WHERE key_hash = ?",
                           (hashlib.sha256(key.encode()).hexdigest(),)).fetchone()
    return row["name"] if row else None


def _client_key():
    return _api_client() or request.remote_addr or "anon"


@bp.get("/api/results")
@limit("results", "RESULTS_API_LIMIT_PER_MIN", key_fn=_client_key)
def results():
    client = _api_client()
    if not client:
        svc().audit.record("results.unauthenticated", request.remote_addr or "?", "anonymous", {})
        return jsonify(error="results API requires a registered client key"), 401
    latest = svc().election.latest_result()
    if not latest:
        return jsonify(error="no results published yet"), 404
    svc().audit.record("results.served", client, "api_client", {})
    return jsonify(latest)


@bp.post("/api/terminals/heartbeat")
def heartbeat():
    if not mission_network_ok():
        return jsonify(error="terminal not on registered mission network"), 403
    tid = str(body().get("terminal_id", ""))
    if not svc().monitor.heartbeat(tid):
        return jsonify(error="unknown terminal"), 404
    return jsonify(ok=True)


@bp.get("/health")
def health():
    return jsonify(status="ok", election=svc().election.status())


@bp.get("/")
def index():
    return send_from_directory(current_app.static_folder, "index.html")


@bp.get("/admin")
def admin_page():
    return send_from_directory(current_app.static_folder, "admin.html")


@bp.get("/board")
def board_page():
    return send_from_directory(current_app.static_folder, "board.html")
