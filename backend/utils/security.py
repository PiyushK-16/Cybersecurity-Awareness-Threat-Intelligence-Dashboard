"""Authentication (API keys), role-based access control and a tiny rate limiter."""
import hmac
import time
from collections import defaultdict, deque
from functools import wraps

from flask import current_app, jsonify, request

ROLE_ORDER = {"viewer": 0, "analyst": 1, "admin": 2}
_hits: dict[str, deque] = defaultdict(deque)


def current_role() -> tuple[str, str]:
    """Return (role, actor) based on the X-API-Key header. No key = read-only viewer."""
    key = request.headers.get("X-API-Key", "")
    cfg = current_app.config
    if key and hmac.compare_digest(key, cfg["ADMIN_API_KEY"]):
        return "admin", "admin"
    if key and hmac.compare_digest(key, cfg["ANALYST_API_KEY"]):
        return "analyst", "analyst"
    return "viewer", "anonymous"


def require_role(minimum: str):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            role, actor = current_role()
            if role == "viewer":
                return jsonify(error="Authentication required: send a valid X-API-Key header."), 401
            if ROLE_ORDER[role] < ROLE_ORDER[minimum]:
                return jsonify(error=f"Forbidden: requires {minimum} role."), 403
            request.actor = actor
            return fn(*a, **kw)
        return wrapper
    return deco


def rate_limit_check():
    """Sliding-window limiter per client IP (in-memory; use Redis for multi-process deployments)."""
    limit = current_app.config["RATE_LIMIT_PER_MINUTE"]
    now, q = time.time(), _hits[request.remote_addr or "?"]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        return jsonify(error="Rate limit exceeded. Try again shortly."), 429
    q.append(now)
    return None


def reset_rate_limiter():
    _hits.clear()
