"""Flask application factory. Run:  python backend/app.py   (from the project root)"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, jsonify, request, send_from_directory  # noqa: E402

from backend.config import Config  # noqa: E402
from backend.models.database import get_connection  # noqa: E402
from backend.routes.api import api  # noqa: E402
from backend.services.ingestion import load_dataset  # noqa: E402
from backend.utils.security import rate_limit_check  # noqa: E402


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)
    app.config.update(overrides or {})
    app.register_blueprint(api)

    # Auto-build the DB the first time if it does not exist yet.
    if not Path(app.config["DATABASE_PATH"]).exists() and Path(app.config["THREATS_CSV"]).exists():
        load_dataset(get_connection(app.config["DATABASE_PATH"]), _ConfigView(app.config), reset=True)

    @app.before_request
    def _limit():
        if request.path.startswith("/api/"):
            return rate_limit_check()

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                                   "script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        origin = request.headers.get("Origin")
        if origin and origin in app.config["CORS_ORIGINS"]:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, OPTIONS"
        return resp

    @app.route("/api/<path:_p>", methods=["OPTIONS"])
    def _preflight(_p):
        return ("", 204)

    @app.errorhandler(404)
    def _404(_e):
        return jsonify(error="Not found."), 404

    @app.errorhandler(413)
    def _413(_e):
        return jsonify(error="Request body too large."), 413

    @app.errorhandler(500)
    def _500(_e):  # never leak stack traces to clients
        return jsonify(error="Internal server error."), 500

    @app.get("/")
    def home():
        return send_from_directory(app.config["FRONTEND_DIR"], "index.html")

    @app.get("/<path:filename>")
    def static_files(filename):
        return send_from_directory(app.config["FRONTEND_DIR"], filename)

    return app


class _ConfigView:
    """Adapter so ingestion can read Flask config values with attribute access."""
    def __init__(self, cfg):
        self.__dict__.update({k: cfg[k] for k in ("THREATS_CSV", "VULNS_CSV", "AWARENESS_DIR")})


if __name__ == "__main__":
    # debug=False on purpose: the Werkzeug debugger must never be exposed.
    create_app().run(host="127.0.0.1", port=5000, debug=False)
