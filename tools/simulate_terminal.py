"""Simulate a polling terminal sending heartbeats (SR-20 / SR-22 demo).

    python tools/simulate_terminal.py PS-SYD-001 http://127.0.0.1:3776
Stop it with Ctrl+C - after 60 s the console shows the terminal offline and a
critical alert to start the paper-ballot procedure.
"""
import sys
import time

import requests

tid = sys.argv[1] if len(sys.argv) > 1 else "PS-SYD-001"
base = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3776").rstrip("/")
print(f"Terminal {tid} sending heartbeats to {base} every 10s (Ctrl+C to simulate an outage)")
while True:
    r = requests.post(base + "/api/terminals/heartbeat", json={"terminal_id": tid},
                      headers={"X-Terminal-Id": tid}, timeout=5, verify=False)  # nosec B501
    print(time.strftime("%H:%M:%S"), r.status_code, r.json())
    time.sleep(10)
