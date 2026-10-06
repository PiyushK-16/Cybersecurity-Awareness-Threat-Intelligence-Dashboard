"""Central configuration. Values come from environment variables (.env) with safe defaults."""
import os
from datetime import date
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

try:  # python-dotenv is optional; the project also works with plain environment variables
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:  # pragma: no cover
    pass

# The "demo clock". All synthetic data is generated relative to this date so
# recency scores are reproducible no matter when you run the project.
REFERENCE_DATE = date.fromisoformat(os.getenv("REFERENCE_DATE", "2026-10-01"))


class Config:
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "threat_dashboard.db"))
    THREATS_CSV = str(BASE_DIR / "data" / "threat_intelligence_dataset.csv")
    VULNS_CSV = str(BASE_DIR / "data" / "vulnerabilities.csv")
    AWARENESS_DIR = str(BASE_DIR / "awareness")
    FRONTEND_DIR = str(BASE_DIR / "frontend")
    # Demo keys - CHANGE THEM in your own .env. Never commit real secrets.
    ANALYST_API_KEY = os.getenv("ANALYST_API_KEY", "demo-analyst-key-change-me")
    ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "demo-admin-key-change-me")
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "300"))
    CORS_ORIGINS = [o for o in os.getenv("CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if o]
    MAX_CONTENT_LENGTH = 64 * 1024  # reject huge request bodies
    JSON_SORT_KEYS = False
    TESTING = False
