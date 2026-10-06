"""Input sanitisation helpers (defence in depth - the frontend ALSO escapes everything)."""
import re

_TAG = re.compile(r"<[^>]*>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value, max_len: int = 1000) -> str:
    """Remove control characters and HTML tags, then truncate."""
    if value is None:
        return ""
    text = _CTRL.sub("", str(value))
    text = _TAG.sub("", text)
    text = text.replace("<", "").replace(">", "")
    return text.strip()[:max_len]
