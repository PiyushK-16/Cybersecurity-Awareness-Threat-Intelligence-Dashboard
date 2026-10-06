"""Small date helpers."""
from datetime import date, datetime, timezone


def parse_date(value) -> date:
    """Accept date, datetime or ISO string ('2026-09-12' or '2026-09-12T10:00:00')."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None).isoformat()
