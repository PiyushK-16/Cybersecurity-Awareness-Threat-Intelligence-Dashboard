"""Initialise (or rebuild) the SQLite database from the synthetic CSV files.
Run from the project root:  python backend/init_db.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import Config  # noqa: E402
from backend.models.database import get_connection  # noqa: E402
from backend.services.ingestion import load_dataset  # noqa: E402


def main():
    conn = get_connection(Config.DATABASE_PATH)
    s = load_dataset(conn, Config, reset=True)
    print(f"Rows read: {s['rows_read']} | loaded: {s['rows_loaded']} | rejected: {s['rows_rejected']}")
    print(f"Correlated clusters: {s['clusters']}")
    print(f"Alerts: {s['raw_alerts']} raw -> {s['correlated_alerts']} after correlation (alert-fatigue reduction)")
    print(f"Database ready: {Config.DATABASE_PATH}")


if __name__ == "__main__":
    main()
