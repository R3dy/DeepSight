"""
API v2 Blueprint — versioned, auth-required routes for enterprise features.

All routes under /api/v2/ are behind the auth → RBAC → audit middleware stack.
"""

import time
import threading
from functools import wraps

from flask import Blueprint, jsonify, request, g

import auth

# ── Create the v2 blueprint ──
v2_bp = Blueprint("v2", __name__, url_prefix="/api/v2")

# ── In-memory audit buffer (flushed to SQLite periodically) ──
_audit_buffer: list[dict] = []
_audit_lock = threading.Lock()
_AUDIT_FLUSH_INTERVAL = 5  # seconds
_AUDIT_FLUSH_MAX_BATCH = 100
_audit_last_flush = time.time()


def _ensure_api_audit_table():
    """Create the api_audit table if it doesn't exist."""
    conn = auth._get_db()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS api_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                user_id INTEGER,
                username TEXT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status_code INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                duration_ms REAL,
                details TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_api_audit_ts ON api_audit(timestamp);
            CREATE INDEX IF NOT EXISTS idx_api_audit_path ON api_audit(path);
            CREATE INDEX IF NOT EXISTS idx_api_audit_user ON api_audit(user_id);
        """)
        conn.commit()
    finally:
        conn.close()


def _flush_audit_buffer():
    """Flush in-memory audit buffer to SQLite."""
    global _audit_buffer, _audit_last_flush
    _ensure_audit_table_lazy()
    with _audit_lock:
        if not _audit_buffer:
            _audit_last_flush = time.time()
            return
        batch = _audit_buffer[:_AUDIT_FLUSH_MAX_BATCH]
        _audit_buffer = _audit_buffer[_AUDIT_FLUSH_MAX_BATCH:]

    conn = auth._get_db()
    try:
        conn.executemany(
            """INSERT INTO api_audit
               (timestamp, user_id, username, method, path, status_code,
                ip_address, user_agent, duration_ms, details)
               VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(e.get("user_id"), e.get("username"), e.get("method"),
              e.get("path"), e.get("status_code"), e.get("ip_address"),
              e.get("user_agent"), e.get("duration_ms"), e.get("details"))
             for e in batch],
        )
        conn.commit()
    finally:
        conn.close()

    _audit_last_flush = time.time()


def log_api_audit(method: str, path: str, status_code: int, duration_ms: float = 0,
                  details: str | None = None):
    """Log an API call to the audit trail (buffered, async-safe)."""
    user_id = None
    username = None
    if hasattr(g, "current_user") and g.current_user:
        user_id = g.current_user.get("user_id")
        username = g.current_user.get("username")

    entry = {
        "user_id": user_id,
        "username": username,
        "method": method,
        "path": path,
        "status_code": status_code,
        "ip_address": auth._get_client_ip() if hasattr(auth, "_get_client_ip") else "",
        "user_agent": (request.headers.get("User-Agent", "") or "")[:256],
        "duration_ms": round(duration_ms, 2),
        "details": (details or "")[:500],
    }

    with _audit_lock:
        _audit_buffer.append(entry)

    # Flush if buffer is large enough or enough time has passed
    now = time.time()
    if (len(_audit_buffer) >= _AUDIT_FLUSH_MAX_BATCH
            or (now - _audit_last_flush) > _AUDIT_FLUSH_INTERVAL):
        _flush_audit_buffer()


# ── RBAC Placeholder ──

# Role definitions (placeholder — full implementation in M4)
_ROLE_HIERARCHY = {
    "viewer": 0,
    "analyst": 1,
    "soc_manager": 2,
    "admin": 3,
}

# Permission matrix (placeholder)
_PERMISSIONS = {
    "cases:read": ["viewer", "analyst", "soc_manager", "admin"],
    "cases:write": ["analyst", "soc_manager", "admin"],
    "alerts:acknowledge": ["analyst", "soc_manager", "admin"],
    "admin:access": ["admin"],
}


def get_user_role(user_info: dict) -> str:
    """Get the role for a user. Defaults to 'analyst' for now (placeholder)."""
    if not user_info:
        return "viewer"
    if user_info.get("is_admin"):
        return "admin"
    # In the future, role comes from user profile; for now default to analyst
    return "analyst"


def check_rbac(required_permission: str = "cases:read") -> bool:
    """Check if the current user has the required permission.

    This is a placeholder implementation. Full RBAC with granular permissions,
    custom roles, and tenant-scoped permissions will be implemented in M4.

    Currently: authenticated users with admin role have all permissions;
    others have read-only access to most resources.
    """
    if not hasattr(g, "current_user") or not g.current_user:
        return False

    user_role = get_user_role(g.current_user)

    # Admin has full access
    if user_role == "admin":
        return True

    # Check the permission matrix
    allowed_roles = _PERMISSIONS.get(required_permission, ["admin"])
    return user_role in allowed_roles


def require_permission(permission: str):
    """Decorator: require a specific RBAC permission.

    Must be used AFTER @auth.require_auth (which sets g.current_user).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not check_rbac(permission):
                return jsonify({
                    "error": "forbidden",
                    "reason": f"Missing required permission: {permission}",
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ═══════════════════════════════════════════
# V2 Routes
# ═══════════════════════════════════════════


@v2_bp.route("/status")
@auth.require_auth
def v2_status():
    """Health-check endpoint for the v2 API."""
    return jsonify({
        "data": {
            "version": "v2",
            "status": "operational",
            "timestamp": time.time(),
            "features": {
                "cases": "available",
                "hunt": "planned",
                "iocs": "planned",
                "dashboards": "planned",
                "playbooks": "planned",
                "admin": "planned",
            },
        },
    })


@v2_bp.route("/health")
def v2_health():
    """Public health-check (no auth required)."""
    return jsonify({
        "data": {
            "status": "healthy",
            "version": "2.0.0-alpha",
            "timestamp": time.time(),
        },
    })


# ── Import sub-route modules to register them on the blueprint ──
import routes.v2.docs  # noqa: E402, F401 — registers /docs/ and /openapi.json routes
import routes.v2.detection  # noqa: E402, F401 — registers /detection/ and /sigma/ routes
import routes.v2.ueba  # noqa: E402, F401 — registers /ueba/ health and model-status routes
import routes.v2.incidents  # noqa: E402, F401 — registers /incidents/ grouping routes
import routes.v2.cases  # noqa: E402, F401 — registers /cases/ management routes


def _ensure_audit_table_lazy():
    """Ensure the api_audit table exists.

    Uses CREATE TABLE IF NOT EXISTS so it's safe to call on every request.
    Called by the audit logging middleware before writing entries.
    """
    _ensure_api_audit_table()
