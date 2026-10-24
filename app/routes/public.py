"""Results API (SR-14)."""
import hashlib

from flask import Blueprint, jsonify, request

from ..security.ratelimit import limit
from . import svc

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
