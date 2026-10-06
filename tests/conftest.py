"""Shared fixtures. Tests use a SMALL synthetic dataset in a temp folder - your real DB is never touched."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "data"))

from backend.app import create_app  # noqa: E402
from backend.config import Config  # noqa: E402
from backend.utils.security import reset_rate_limiter  # noqa: E402
import generate_threat_data as gen  # noqa: E402

ANALYST, ADMIN = "test-analyst", "test-admin"


@pytest.fixture(scope="session")
def csv_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    rows, vulns = gen.generate_dataset(400, seed=7)
    gen.write_csv(d / "threats.csv", rows)
    gen.write_csv(d / "vulns.csv", vulns)
    return d


def make_app(csv_dir, db_path, **extra):
    cfg = dict(TESTING=True, DATABASE_PATH=str(db_path), THREATS_CSV=str(csv_dir / "threats.csv"),
               VULNS_CSV=str(csv_dir / "vulns.csv"), ANALYST_API_KEY=ANALYST, ADMIN_API_KEY=ADMIN,
               RATE_LIMIT_PER_MINUTE=100000)
    cfg.update(extra)
    return create_app(cfg)


@pytest.fixture()
def app(csv_dir, tmp_path):
    reset_rate_limiter()
    return make_app(csv_dir, tmp_path / "t.db")


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def conn(app):
    from backend.models.database import get_connection
    c = get_connection(app.config["DATABASE_PATH"])
    yield c
    c.close()


def hdr(key):
    return {"X-API-Key": key}
