"""Start the prototype server.

    python run.py            # http://127.0.0.1:3776  (development)
    python run.py --tls      # https://127.0.0.1:3775 TLS 1.3 ONLY (SR-05)
"""
import argparse
import logging
import ssl
import threading
import time
from pathlib import Path

from app import create_app

BASE = Path(__file__).resolve().parent


class DropBallotAccessLogs(logging.Filter):
    """SR-07 / SR-09: the web server's access log would otherwise record the client
    IP and exact time of every ballot submission. Those lines are never written."""

    def filter(self, record):
        return "/api/ballots" not in record.getMessage()


def monitor_loop(app):
    """Background job: mark silent terminals offline (SR-20)."""
    while True:
        time.sleep(15)
        with app.app_context():
            app.evote.monitor.check_terminals()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tls", action="store_true", help="serve HTTPS with TLS 1.3 only")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int)
    args = ap.parse_args()

    logging.getLogger("werkzeug").addFilter(DropBallotAccessLogs())
    app = create_app()
    threading.Thread(target=monitor_loop, args=(app,), daemon=True).start()

    ssl_ctx = None
    if args.tls:
        cert, key = BASE / "certs" / "server.crt", BASE / "certs" / "server.key"
        if not cert.exists():
            raise SystemExit("No certificate found - run: python tools/gen_cert.py")
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # refuse TLS 1.2 and below
        ssl_ctx.load_cert_chain(cert, key)
    port = args.port or (3775 if args.tls else 3776)
    print(f"Serving on {'https' if ssl_ctx else 'http'}://{args.host}:{port}")
    app.run(host=args.host, port=port, ssl_context=ssl_ctx, debug=False, threaded=True)


if __name__ == "__main__":
    main()
