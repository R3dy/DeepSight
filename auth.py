"""
DeepSight Authentication Module — Industry-standard auth for a security product.

Password storage:  argon2id (OWASP-recommended)
Token storage:     SHA-256 hash (plaintext tokens never persisted)
Session tokens:    24h TTL (configurable via DEEPSIGHT_TOKEN_TTL_HOURS)
API keys:          90d TTL (configurable via DEEPSIGHT_API_KEY_TTL_DAYS)

Rate limiting:     5 failed logins / 60s per IP (in-memory)

DO NOT MODIFY the hash/token schemes without a migration plan.
"""

import hashlib
import os
import sqlite3
import time
from datetime import datetime, timezone
from functools import wraps

from flask import request, jsonify, g

# ── argon2id for password hashing ──
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError

    _ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )
    _argon2_available = True
except ImportError:
    import hashlib as _hashlib_mod
    import secrets as _secrets

    _argon2_available = False

    def _pbkdf2_hash(password: str) -> str:
        """Fallback: PBKDF2-SHA256 with 600k iterations."""
        salt = _secrets.token_bytes(16)
        dk = _hashlib_mod.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
        return f"pbkdf2:sha256:600000${salt.hex()}${dk.hex()}"

    def _pbkdf2_verify(password: str, stored: str) -> bool:
        """Verify a PBKDF2-SHA256 hash."""
        try:
            _, _, _, rest = stored.split("$", 3)
            salt_hex, dk_hex = rest.split("$")
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(dk_hex)
            dk = _hashlib_mod.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
            return _secrets.compare_digest(dk, expected)
        except Exception:
            return False


# ── Configuration ──
DB_PATH = os.environ.get("DEEPSIGHT_AUTH_DB", os.path.join(os.path.dirname(__file__), "data", "auth.db"))
TOKEN_TTL_HOURS = int(os.environ.get("DEEPSIGHT_TOKEN_TTL_HOURS", "24"))
API_KEY_TTL_DAYS = int(os.environ.get("DEEPSIGHT_API_KEY_TTL_DAYS", "90"))
INSECURE_NO_AUTH = os.environ.get("DEEPSIGHT_INSECURE_NO_AUTH", "").lower() in ("1", "true", "yes")

# ── Rate limiter (in-memory) ──
_rate_limit_store: dict[str, list[float]] = {}
_RATE_LIMIT_MAX = 5
_RATE_LIMIT_WINDOW = 60


def _ensure_db_dir():
    """Create the data directory for auth.db if it doesn't exist."""
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.isdir(db_dir):
        os.makedirs(db_dir, exist_ok=True)


def _get_db() -> sqlite3.Connection:
    """Get a connection to the auth database."""
    _ensure_db_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ═══════════════════════════════════════════
# Database Initialization
# ═══════════════════════════════════════════


def init_auth_db():
    """Create auth tables if they don't exist."""
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at TEXT,
            active INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            token_hash TEXT UNIQUE NOT NULL,
            token_type TEXT NOT NULL DEFAULT 'session',
            scope TEXT NOT NULL DEFAULT 'full',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            last_used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            key_hash TEXT UNIQUE NOT NULL,
            name TEXT,
            scope TEXT NOT NULL DEFAULT 'read-only',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            revoked_at TEXT,
            last_used_at TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            user_id INTEGER,
            token_id INTEGER,
            api_key_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);
        CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
        CREATE INDEX IF NOT EXISTS idx_audit_type ON auth_audit(event_type);
        CREATE INDEX IF NOT EXISTS idx_audit_created ON auth_audit(created_at);
    """)
    conn.commit()
    conn.close()


# ═══════════════════════════════════════════
# Password Hashing
# ═══════════════════════════════════════════


def hash_password(password: str) -> str:
    """Hash a password using argon2id (or PBKDF2-SHA256 fallback)."""
    if _argon2_available:
        return _ph.hash(password)
    return _pbkdf2_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    if _argon2_available:
        try:
            _ph.verify(password_hash, password)
            # Rehash if parameters changed
            if _ph.check_needs_rehash(password_hash):
                # We can't rehash here (we don't have the user row handy),
                # so just verify. The login flow handles rehashing.
                pass
            return True
        except (VerifyMismatchError, VerificationError):
            return False
    else:
        if password_hash.startswith("pbkdf2:"):
            return _pbkdf2_verify(password, password_hash)
        # Unknown hash format
        return False


# ═══════════════════════════════════════════
# User Management
# ═══════════════════════════════════════════


def create_user(username: str, password: str, is_admin: bool = False) -> dict:
    """Create a new user. Returns user dict or raises ValueError."""
    username = username.strip().lower()
    if not username or not password:
        raise ValueError("Username and password are required")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    conn = _get_db()
    try:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"User '{username}' already exists")

        pw_hash = hash_password(password)
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            (username, pw_hash, 1 if is_admin else 0),
        )
        conn.commit()
        user_id = cur.lastrowid
        return {"id": user_id, "username": username, "is_admin": bool(is_admin)}
    finally:
        conn.close()


def verify_user(username: str, password: str) -> dict | None:
    """Verify username/password. Returns user dict or None."""
    username = username.strip().lower()
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND active = 1",
            (username,),
        ).fetchone()
        if not row:
            return None

        if not verify_password(password, row["password_hash"]):
            return None

        # Check if password needs rehash (parameter upgrade)
        if _argon2_available and _ph.check_needs_rehash(row["password_hash"]):
            new_hash = hash_password(password)
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, row["id"]),
            )
            conn.commit()

        # Update last_login_at
        conn.execute(
            "UPDATE users SET last_login_at = datetime('now') WHERE id = ?",
            (row["id"],),
        )
        conn.commit()

        return {
            "id": row["id"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "must_change_password": bool(row["must_change_password"]),
        }
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> dict | None:
    """Get user by ID."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ? AND active = 1",
            (user_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "must_change_password": bool(row["must_change_password"]),
        }
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Token Management
# ═══════════════════════════════════════════


def _hash_token(token: str) -> str:
    """SHA-256 hash a token string for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(user_id: int, token_type: str = "session", scope: str = "full", ttl_hours: int | None = None) -> dict:
    """Create a new session token. Returns {token, token_id, expires_at}.

    The raw token is only returned here — never stored or logged.
    Only the SHA-256 hash is stored in the DB.
    """
    if ttl_hours is None:
        ttl_hours = TOKEN_TTL_HOURS

    raw_token = os.urandom(32).hex()
    token_hash = _hash_token(raw_token)
    expires_at = datetime.now(timezone.utc).timestamp() + (ttl_hours * 3600)
    expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

    conn = _get_db()
    try:
        cur = conn.execute(
            """INSERT INTO tokens (user_id, token_hash, token_type, scope, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, token_hash, token_type, scope, expires_iso),
        )
        conn.commit()
        return {
            "token": raw_token,
            "token_id": cur.lastrowid,
            "expires_at": expires_iso,
        }
    finally:
        conn.close()


def validate_token(token_string: str) -> dict | None:
    """Validate a Bearer token. Returns user dict or None."""
    if not token_string:
        return None

    # Remove Bearer prefix if present
    if token_string.startswith("Bearer "):
        token_string = token_string[7:]

    token_hash = _hash_token(token_string)

    conn = _get_db()
    try:
        row = conn.execute(
            """SELECT t.*, u.username, u.is_admin, u.must_change_password
               FROM tokens t
               JOIN users u ON t.user_id = u.id
               WHERE t.token_hash = ? AND t.revoked_at IS NULL AND u.active = 1
               ORDER BY t.created_at DESC LIMIT 1""",
            (token_hash,),
        ).fetchone()

        if not row:
            return None

        # Check expiry
        if row["expires_at"]:
            expires_ts = datetime.fromisoformat(row["expires_at"]).timestamp()
            if time.time() > expires_ts:
                return None

        # Update last_used_at
        conn.execute(
            "UPDATE tokens SET last_used_at = datetime('now') WHERE id = ?",
            (row["id"],),
        )
        conn.commit()

        return {
            "token_id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "must_change_password": bool(row["must_change_password"]),
            "scope": row["scope"],
            "token_type": row["token_type"],
            "expires_at": row["expires_at"],
        }
    finally:
        conn.close()


def revoke_token(token_string: str) -> bool:
    """Revoke a token so it can no longer be used."""
    if token_string.startswith("Bearer "):
        token_string = token_string[7:]

    token_hash = _hash_token(token_string)

    conn = _get_db()
    try:
        cur = conn.execute(
            "UPDATE tokens SET revoked_at = datetime('now') WHERE token_hash = ? AND revoked_at IS NULL",
            (token_hash,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ═══════════════════════════════════════════
# API Key Management
# ═══════════════════════════════════════════


def create_api_key(user_id: int, scope: str = "read-only", ttl_days: int | None = None, name: str | None = None) -> dict:
    """Create an API key for programmatic access. Returns {api_key, id, expires_at}.

    The raw key is only returned here — never stored or logged.
    Only the SHA-256 hash is stored in the DB.
    """
    if ttl_days is None:
        ttl_days = API_KEY_TTL_DAYS

    # API keys: dsk_ prefix + 32 random bytes for easy identification in logs
    raw_key = "dsk_" + os.urandom(32).hex()
    key_hash = _hash_token(raw_key)
    expires_at = datetime.now(timezone.utc).timestamp() + (ttl_days * 86400)
    expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()

    conn = _get_db()
    try:
        cur = conn.execute(
            """INSERT INTO api_keys (user_id, key_hash, name, scope, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, key_hash, name, scope, expires_iso),
        )
        conn.commit()
        return {
            "api_key": raw_key,
            "id": cur.lastrowid,
            "scope": scope,
            "expires_at": expires_iso,
        }
    finally:
        conn.close()


def validate_api_key(key_string: str) -> dict | None:
    """Validate an API key. Returns user dict or None."""
    if not key_string:
        return None

    key_hash = _hash_token(key_string)

    conn = _get_db()
    try:
        row = conn.execute(
            """SELECT k.*, u.username, u.is_admin
               FROM api_keys k
               JOIN users u ON k.user_id = u.id
               WHERE k.key_hash = ? AND k.revoked_at IS NULL AND u.active = 1
               ORDER BY k.created_at DESC LIMIT 1""",
            (key_hash,),
        ).fetchone()

        if not row:
            return None

        # Check expiry
        if row["expires_at"]:
            expires_ts = datetime.fromisoformat(row["expires_at"]).timestamp()
            if time.time() > expires_ts:
                return None

        # Update last_used_at
        conn.execute(
            "UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?",
            (row["id"],),
        )
        conn.commit()

        return {
            "api_key_id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "is_admin": bool(row["is_admin"]),
            "scope": row["scope"],
        }
    finally:
        conn.close()


def revoke_api_key(key_id: int) -> bool:
    """Revoke an API key by its database ID."""
    conn = _get_db()
    try:
        cur = conn.execute(
            "UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ? AND revoked_at IS NULL",
            (key_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def list_api_keys(user_id: int) -> list[dict]:
    """List all (non-revoked) API keys for a user."""
    conn = _get_db()
    try:
        rows = conn.execute(
            """SELECT id, name, scope, created_at, expires_at, last_used_at
               FROM api_keys
               WHERE user_id = ? AND revoked_at IS NULL
               ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Audit Logging
# ═══════════════════════════════════════════


def log_audit(event_type: str, username: str | None = None, user_id: int | None = None,
              token_id: int | None = None, api_key_id: int | None = None,
              ip_address: str | None = None, user_agent: str | None = None,
              details: str | None = None):
    """Log an authentication event to the audit table."""
    conn = _get_db()
    try:
        conn.execute(
            """INSERT INTO auth_audit (event_type, username, user_id, token_id, api_key_id,
               ip_address, user_agent, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (event_type, username, user_id, token_id, api_key_id, ip_address, user_agent, details),
        )
        conn.commit()
    finally:
        conn.close()


def get_audit_events(limit: int = 50, event_type: str | None = None) -> list[dict]:
    """Retrieve recent audit events."""
    conn = _get_db()
    try:
        if event_type:
            rows = conn.execute(
                "SELECT * FROM auth_audit WHERE event_type = ? ORDER BY created_at DESC LIMIT ?",
                (event_type, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM auth_audit ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ═══════════════════════════════════════════
# Rate Limiter
# ═══════════════════════════════════════════


def _get_client_ip() -> str:
    """Get the client IP, respecting X-Forwarded-For if present."""
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def check_rate_limit(ip: str | None = None, max_failures: int | None = None,
                     window_seconds: int | None = None) -> bool:
    """Check if an IP has exceeded the rate limit. Returns True if allowed.

    Clean up old entries on every call to prevent memory leak.
    """
    if ip is None:
        ip = _get_client_ip()
    if max_failures is None:
        max_failures = _RATE_LIMIT_MAX
    if window_seconds is None:
        window_seconds = _RATE_LIMIT_WINDOW

    now = time.time()
    cutoff = now - window_seconds

    # Clean up old entries
    if ip in _rate_limit_store:
        _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if t > cutoff]

    failures = _rate_limit_store.get(ip, [])
    return len(failures) < max_failures


def record_failure(ip: str | None = None):
    """Record a login failure for the given IP."""
    if ip is None:
        ip = _get_client_ip()

    now = time.time()
    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []
    _rate_limit_store[ip].append(now)

    # Clean up old entries
    cutoff = now - _RATE_LIMIT_WINDOW
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if t > cutoff]


# ═══════════════════════════════════════════
# Initial Admin Setup
# ═══════════════════════════════════════════


def init_admin_user() -> str | None:
    """If no users exist, create an admin with a random password.

    Prints the password to stdout and writes it to
    ~/.config/deepsight/admin-init.txt (mode 0600).

    Returns the admin password, or None if users already exist.
    """
    conn = _get_db()
    try:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count > 0:
            return None
    finally:
        conn.close()

    # Generate a strong random password
    password = os.urandom(24).hex()

    create_user("admin", password, is_admin=True)

    # Write to config directory
    config_dir = os.path.expanduser("~/.config/deepsight")
    os.makedirs(config_dir, exist_ok=True)
    init_file = os.path.join(config_dir, "admin-init.txt")
    with open(init_file, "w") as f:
        f.write("DeepSight Initial Admin Password\n")
        f.write("================================\n")
        f.write("Username: admin\n")
        f.write(f"Password: {password}\n")
        f.write(f"\nCreated: {datetime.now(timezone.utc).isoformat()}\n")
        f.write("\nCHANGE THIS PASSWORD on first login.\n")
    os.chmod(init_file, 0o600)

    print("\n[auth] ═══════════════════════════════════════════", flush=True)
    print("[auth]  Initial admin user created.", flush=True)
    print("[auth]  Username: admin", flush=True)
    print(f"[auth]  Password: {password}", flush=True)
    print(f"[auth]  Saved to: {init_file}", flush=True)
    print("[auth]  CHANGE THIS PASSWORD on first login.", flush=True)
    print("[auth] ═══════════════════════════════════════════\n", flush=True)

    log_audit(
        event_type="admin_init",
        username="admin",
        ip_address="localhost",
        details="Initial admin user auto-created on first startup",
    )

    return password


# ═══════════════════════════════════════════
# Flask Decorators
# ═══════════════════════════════════════════


def _extract_bearer_token() -> str | None:
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def require_auth(f):
    """Decorator: require valid Bearer token. Returns 401 JSON on failure."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # ── Backward compatibility escape hatch ──
        if INSECURE_NO_AUTH:
            print("[auth] WARNING: DEEPSIGHT_INSECURE_NO_AUTH is set — all auth bypassed!", flush=True)
            g.current_user = {
                "user_id": 0,
                "username": "insecure-mode",
                "is_admin": True,
                "scope": "full",
                "token_type": "insecure",
            }
            return f(*args, **kwargs)

        token = _extract_bearer_token()
        if not token:
            return jsonify({"error": "unauthorized", "reason": "missing token"}), 401

        user = validate_token(token)
        if not user:
            return jsonify({"error": "unauthorized", "reason": "invalid or expired token"}), 401

        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def require_agent_auth(f):
    """Decorator: require valid API key (from POST body or Authorization header). Returns 403 JSON on failure."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # ── Backward compatibility fallback ──
        if INSECURE_NO_AUTH:
            print("[auth] WARNING: DEEPSIGHT_INSECURE_NO_AUTH is set — all auth bypassed!", flush=True)
            g.current_user = {
                "user_id": 0,
                "username": "insecure-mode",
                "is_admin": True,
                "scope": "full",
                "token_type": "insecure",
            }
            return f(*args, **kwargs)

        # Check POST body first (for /api/report)
        data = request.get_json(silent=True) or {}
        api_key = data.get("api_key", "")
        secret = data.get("secret", "")  # Legacy agent field

        # Fall back to Authorization header if no api_key
        if not api_key:
            api_key = _extract_bearer_token()

        if not api_key and not secret:
            return jsonify({"error": "forbidden", "reason": "missing agent credentials"}), 403

        # Try API key first, then session token
        if api_key:
            agent = validate_api_key(api_key)
            if agent:
                g.current_user = agent
                return f(*args, **kwargs)

            user = validate_token(api_key)
            if user:
                g.current_user = user
                return f(*args, **kwargs)

        # Fall back to shared secret (legacy agent auth)
        if secret:
            # Lazy import to avoid circular dependency
            import importlib
            server = importlib.import_module("server")
            if secret == server.SHARED_SECRET:
                g.current_user = {"scope": "agent", "name": "agent"}
                return f(*args, **kwargs)

        return jsonify({"error": "forbidden", "reason": "invalid agent credentials"}), 403
    return decorated


# ═══════════════════════════════════════════
# Migration Helpers
# ═══════════════════════════════════════════


def print_migration_instructions():
    """Print migration instructions on startup."""
    print("", flush=True)
    print("[auth] ═══════════════════════════════════════════", flush=True)
    print("[auth]  DeepSight 0.4.0 — Authentication Required", flush=True)
    print("[auth] ═══════════════════════════════════════════", flush=True)
    print("[auth]  All API endpoints now require authentication.", flush=True)
    print("[auth]  An admin user has been auto-created (see above).", flush=True)
    print("[auth]", flush=True)
    print("[auth]  For backward compatibility during migration:", flush=True)
    print("[auth]    export DEEPSIGHT_INSECURE_NO_AUTH=true", flush=True)
    print("[auth]    (This bypasses all auth — REMOVE after migration.)", flush=True)
    print("[auth]", flush=True)
    print("[auth]  Agent hosts need an API key:", flush=True)
    print("[auth]    1. Login to the dashboard", flush=True)
    print("[auth]    2. Navigate to Settings → API Keys", flush=True)
    print("[auth]    3. Create an API key with agent scope", flush=True)
    print("[auth]    4. Update agent config.json with api_key field", flush=True)
    print("[auth]", flush=True)
    print("[auth]  Scripted access:", flush=True)
    print("[auth]    curl -H 'Authorization: Bearer <token>' https://...", flush=True)
    print("[auth] ═══════════════════════════════════════════", flush=True)
    print("", flush=True)
