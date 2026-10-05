"""
CyberRegis Threat Intelligence Platform
========================================
Industry-grade security analysis & threat intelligence server.
This is the application entry point — all route logic lives in api/ blueprints.
"""

# ── Pre-import patches ────────────────────────────────────────
import matplotlib
matplotlib.use("Agg")

# Fix Windows cp1252 encoding for Unicode box characters in console output
import sys as _sys, io as _io
if _sys.stdout.encoding and _sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    try:
        _sys.stdout = _io.TextIOWrapper(_sys.stdout.buffer, encoding='utf-8', errors='replace')
        _sys.stderr = _io.TextIOWrapper(_sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

import hmac
import ipaddress
import os
import sys
import logging
import urllib3
import requests

# Corporate-proxy SSL bypass (set SSL_VERIFY=true in .env when not behind a proxy)
from config import get_config
cfg = get_config()

if not cfg.SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    os.environ["PYTHONHTTPSVERIFY"] = "0"

    _original_session_request = requests.Session.request
    def _patched_session_request(self, *args, **kwargs):
        kwargs.setdefault("verify", False)
        return _original_session_request(self, *args, **kwargs)
    requests.Session.request = _patched_session_request

    _orig_get, _orig_post = requests.get, requests.post
    def _patched_get(*a, **kw):
        kw.setdefault("verify", False)
        return _orig_get(*a, **kw)
    def _patched_post(*a, **kw):
        kw.setdefault("verify", False)
        return _orig_post(*a, **kw)
    requests.get = _patched_get
    requests.post = _patched_post

# ── Flask Application Factory ─────────────────────────────────
from flask import Flask, request as flask_request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Ensure database tables exist
import database
database.init_db()  # Initialize database tables on startup

PUBLIC_PATHS = {"/api/health"}


def create_app() -> Flask:
    if cfg.FLASK_ENV == "production" and not cfg.API_TOKEN:
        raise RuntimeError("API_TOKEN must be set when FLASK_ENV=production")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = cfg.MAX_CONTENT_LENGTH

    # ── CORS ──────────────────────────────────────────
    CORS(
        app,
        resources={r"/api/*": {"origins": cfg.cors_origins()}},
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    )

    # ── API authentication ────────────────────────────
    # Every /api/* route except the health probe requires the shared API token.
    @app.before_request
    def require_api_token():
        if flask_request.method == "OPTIONS" or not flask_request.path.startswith("/api/"):
            return None
        if flask_request.path in PUBLIC_PATHS or not cfg.API_TOKEN:
            return None
        supplied = flask_request.headers.get("X-API-Key", "")
        auth = flask_request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
        if not supplied or not hmac.compare_digest(supplied, cfg.API_TOKEN):
            return {"status": "error", "error": {"message": "Unauthorized", "code": "ERR_401"}}, 401
        return None

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    # ── Rate Limiting ─────────────────────────────────
    Limiter(
        get_remote_address,
        app=app,
        default_limits=[cfg.DEFAULT_RATE_LIMIT, cfg.SCAN_RATE_LIMIT],
        storage_uri="memory://",
    )

    # ── Logging ───────────────────────────────────────
    logging.basicConfig(
        filename=cfg.LOG_FILE,
        level=getattr(logging, cfg.LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
    logging.getLogger().addHandler(console)

    # ── Register Blueprints ───────────────────────────
    from api.domain_routes import domain_bp
    from api.ip_routes import ip_bp
    from api.url_routes import url_bp
    from api.network_routes import network_bp
    from api.scanner_routes import scanner_bp
    from api.security_routes import security_bp
    from api.chat_routes import chat_bp
    from api.threat_intel_routes import threat_intel_bp
    from api.reports_routes import reports_bp
    from api.monitoring_routes import monitoring_bp
    from api.shodan_routes import shodan_bp

    for bp in [domain_bp, ip_bp, url_bp, network_bp, scanner_bp,
               security_bp, chat_bp, threat_intel_bp, reports_bp, monitoring_bp, shodan_bp]:
        app.register_blueprint(bp)

    # ── Global error handlers ─────────────────────────
    @app.errorhandler(404)
    def not_found(_e):
        return {"status": "error", "error": {"message": "Endpoint not found", "code": "ERR_404"}}, 404

    @app.errorhandler(429)
    def rate_limited(_e):
        return {"status": "error", "error": {"message": "Rate limit exceeded", "code": "ERR_429"}}, 429

    @app.errorhandler(500)
    def internal_error(_e):
        return {"status": "error", "error": {"message": "Internal server error", "code": "ERR_500"}}, 500

    return app


# ── Main ──────────────────────────────────────────────────────
app = create_app()

def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", cfg.FLASK_PORT))
    host = cfg.FLASK_HOST

    if not cfg.API_TOKEN and not _is_loopback(host):
        sys.exit("Refusing to listen on a non-loopback address without API_TOKEN set. "
                 "Set API_TOKEN in .env or bind FLASK_HOST=127.0.0.1.")

    # Start Telegram bot polling
    try:
        from services.notification_service import start_telegram_bot
        start_telegram_bot()
    except Exception as e:
        logging.getLogger(__name__).warning(f"Telegram bot failed to start: {e}")
    _sep = "+" + "=" * 62 + "+"
    print(_sep)
    print("| {:^60} |".format("CyberRegis Threat Intelligence Platform"))
    print(_sep)
    print("| {:<60} |".format(f"  API Server:  http://{host}:{port}"))
    print("| {:<60} |".format(f"  Health:      http://{host}:{port}/api/health"))
    print("| {:<60} |".format(f"  Auth:        {'API token required' if cfg.API_TOKEN else 'OPEN (loopback only)'}"))
    print("| {:<60} |".format(f"  Environment: {cfg.FLASK_ENV}"))
    print("| {:<60} |".format(f"  SSL Verify:  {cfg.SSL_VERIFY}"))
    print(_sep)
    app.run(host=host, port=port, debug=cfg.FLASK_DEBUG, threaded=True)
