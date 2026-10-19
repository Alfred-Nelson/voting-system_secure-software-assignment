"""Start the prototype server.

    python run.py            # http://127.0.0.1:5000  (development)
"""
from app import create_app


def main():
    app = create_app()
    print("Serving on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
