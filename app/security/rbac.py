"""Role-based access control with least privilege (SR-16)."""
from flask import request


def _bearer():
    header = request.headers.get("Authorization", "")
    return header[7:] if header.startswith("Bearer ") else None
