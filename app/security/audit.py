"""Tamper-evident audit logging (SR-18, SR-19)."""
import threading

GENESIS = "0" * 64
_lock = threading.Lock()
