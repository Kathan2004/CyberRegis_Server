"""
CyberRegis Server Configuration
Loads settings from environment variables / .env file
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-to-a-random-secret-key")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    FLASK_PORT = int(os.getenv("FLASK_PORT", 5000))
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    # ── API Keys ──────────────────────────────────────────────
    SAFE_BROWSING_KEY = os.getenv("SAFE_BROWSING_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

    # ── Telegram ──────────────────────────────────────────────
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

    # ── Threat Intel Feeds ────────────────────────────────────
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")

    # ── Database ──────────────────────────────────────────────
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///cyberregis.db")
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberregis.db")

    # ── CORS ──────────────────────────────────────────────────
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001")

    # ── SSL Verification ──────────────────────────────────────
    SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() == "true"

    # ── Rate Limits ───────────────────────────────────────────
    DEFAULT_RATE_LIMIT = "100 per day"
    SCAN_RATE_LIMIT = "20 per minute"
    HEAVY_RATE_LIMIT = "5 per minute"

    # ── Upload ────────────────────────────────────────────────
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB

    # ── Logging ───────────────────────────────────────────────
    LOG_FILE = "cyberregis.log"
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # ── Cache ─────────────────────────────────────────────────
    CACHE_TTL = 3600  # 1 hour
    CACHE_MAX_SIZE = 2000


class ProductionConfig(Config):
    FLASK_DEBUG = False
    FLASK_ENV = "production"


class DevelopmentConfig(Config):
    FLASK_DEBUG = True
    FLASK_ENV = "development"


def get_config():
    env = os.getenv("FLASK_ENV", "development")
    if env == "production":
        return ProductionConfig()
    return DevelopmentConfig()
