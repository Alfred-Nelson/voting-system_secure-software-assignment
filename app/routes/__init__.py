from flask import current_app, request


def body() -> dict:
    """Parse a JSON object body; anything else becomes an empty dict."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def svc():
    return current_app.evote
