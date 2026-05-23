"""Authentication tests for DeepSight 0.4.0.

Covers: password hashing (argon2id), token lifecycle, API key auth,
rate limiting, audit logging, admin auto-creation, and endpoint protection.
"""

import os
import sys
import time
import tempfile
import hashlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth
from server import app


# ── Helpers ──


@pytest.fixture(autouse=True)
def clean_auth_state():
    """Use a temp database for each test class and reset rate limiter."""
    # Reset rate limiter
    auth._rate_limit_store.clear()

    # Use a temp auth DB
    fd, db_path = tempfile.mkstemp(suffix=".db", prefix="test_auth_")
    os.close(fd)
    old_path = auth.DB_PATH
    auth.DB_PATH = db_path
    auth.init_auth_db()

    # Reset INSECURE_NO_AUTH
    old_insecure = auth.INSECURE_NO_AUTH
    auth.INSECURE_NO_AUTH = False

    yield

    # Cleanup
    auth.DB_PATH = old_path
    auth.INSECURE_NO_AUTH = old_insecure
    try:
        os.unlink(db_path)
        # Also remove WAL/SHM if present
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                os.unlink(db_path + suffix)
    except OSError:
        pass


@pytest.fixture
def test_user():
    """Create a test user and return their info."""
    u = auth.create_user("testuser", "testpassword123")
    return u


@pytest.fixture
def test_token(test_user):
    """Create a session token for the test user."""
    token_info = auth.create_token(test_user["id"])
    return token_info


@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ═══════════════════════════════════════════
# Story 1: Core Auth Module
# ═══════════════════════════════════════════


class TestPasswordHashing:
    """Password hashing with argon2id."""

    def test_hash_password_argon2id(self):
        """Password is stored as argon2id hash."""
        pw_hash = auth.hash_password("mypassword123")
        assert pw_hash.startswith("$argon2id$") or pw_hash.startswith("pbkdf2:"), \
            f"Expected argon2id or pbkdf2 hash, got: {pw_hash[:30]}"

    def test_password_not_plaintext(self):
        """Password is never stored in plaintext."""
        auth.create_user("notplain", "secretpass999")
        conn = auth._get_db()
        try:
            row = conn.execute("SELECT password_hash FROM users WHERE username = 'notplain'").fetchone()
            assert row is not None
            assert "secretpass999" not in row["password_hash"], \
                "Password MUST NOT be stored in plaintext"
        finally:
            conn.close()

    def test_verify_correct_password(self):
        """Correct password verifies successfully."""
        pw_hash = auth.hash_password("correctpass1")
        assert auth.verify_password("correctpass1", pw_hash) is True

    def test_verify_wrong_password(self):
        """Wrong password fails verification."""
        pw_hash = auth.hash_password("correctpass1")
        assert auth.verify_password("wrongpass!!", pw_hash) is False

    def test_password_min_length(self):
        """Passwords under 8 characters are rejected."""
        with pytest.raises(ValueError, match="at least 8"):
            auth.create_user("shortie", "abc")

    def test_empty_username_rejected(self):
        """Empty username is rejected."""
        with pytest.raises(ValueError, match="required"):
            auth.create_user("", "password123")


class TestTokenManagement:
    """Token creation, validation, revocation."""

    def test_create_token_returns_dict(self, test_user):
        """Creating a token returns token dict with raw token."""
        token_info = auth.create_token(test_user["id"])
        assert "token" in token_info
        assert "token_id" in token_info
        assert "expires_at" in token_info
        assert len(token_info["token"]) == 64  # os.urandom(32).hex()

    def test_token_stored_as_sha256_hash(self, test_token):
        """Token is stored as SHA-256 hash, not plaintext."""
        conn = auth._get_db()
        try:
            row = conn.execute("SELECT token_hash FROM tokens WHERE id = ?", (test_token["token_id"],)).fetchone()
            assert row is not None
            token_hash = row["token_hash"]
            # SHA-256 hex is 64 chars
            assert len(token_hash) == 64
            # Must not contain the raw token
            assert test_token["token"] not in token_hash
            # Verify it IS the correct SHA-256
            expected = hashlib.sha256(test_token["token"].encode()).hexdigest()
            assert token_hash == expected
        finally:
            conn.close()

    def test_validate_valid_token(self, test_token, test_user):
        """Valid token returns user dict."""
        user = auth.validate_token(test_token["token"])
        assert user is not None
        assert user["username"] == test_user["username"]
        assert user["user_id"] == test_user["id"]

    def test_validate_invalid_token(self):
        """Invalid token returns None."""
        assert auth.validate_token("not-a-real-token-at-all-1234567890abcdef") is None

    def test_validate_empty_token(self):
        """Empty token returns None."""
        assert auth.validate_token("") is None
        assert auth.validate_token(None) is None  # type: ignore

    def test_revoke_token(self, test_token):
        """Revoked token can no longer be validated."""
        assert auth.revoke_token(test_token["token"]) is True
        assert auth.validate_token(test_token["token"]) is None

    def test_revoke_already_revoked(self, test_token):
        """Revoking an already-revoked token returns False."""
        auth.revoke_token(test_token["token"])
        assert auth.revoke_token(test_token["token"]) is False


class TestAPITokenExpiry:
    """Token and API key expiry."""

    def test_expired_token_rejected(self, test_user):
        """Expired token (TTL=0) is rejected."""
        token_info = auth.create_token(test_user["id"], ttl_hours=0)
        # Small sleep to ensure expiry passes
        time.sleep(0.1)
        assert auth.validate_token(token_info["token"]) is None

    def test_expired_api_key_rejected(self, test_user):
        """Expired API key (TTL=0) is rejected."""
        key_info = auth.create_api_key(test_user["id"], ttl_days=0)
        time.sleep(0.1)
        assert auth.validate_api_key(key_info["api_key"]) is None


class TestAPIKeys:
    """API key creation and validation."""

    def test_create_api_key(self, test_user):
        """API key can be created and validated."""
        key_info = auth.create_api_key(test_user["id"], scope="agent")
        assert "api_key" in key_info
        assert key_info["api_key"].startswith("dsk_")
        assert key_info["scope"] == "agent"

    def test_validate_valid_api_key(self, test_user):
        """Valid API key returns user dict."""
        key_info = auth.create_api_key(test_user["id"], scope="agent")
        result = auth.validate_api_key(key_info["api_key"])
        assert result is not None
        assert result["username"] == test_user["username"]
        assert result["scope"] == "agent"

    def test_validate_invalid_api_key(self):
        """Invalid API key returns None."""
        assert auth.validate_api_key("dsk_badkey") is None

    def test_revoke_api_key(self, test_user):
        """Revoked API key can no longer be validated."""
        key_info = auth.create_api_key(test_user["id"])
        assert auth.revoke_api_key(key_info["id"]) is True
        assert auth.validate_api_key(key_info["api_key"]) is None

    def test_list_api_keys(self, test_user):
        """List returns all non-revoked keys."""
        auth.create_api_key(test_user["id"], name="Key1")
        auth.create_api_key(test_user["id"], name="Key2")
        keys = auth.list_api_keys(test_user["id"])
        assert len(keys) == 2


class TestAdminAutoCreation:
    """Admin user auto-creation on empty database."""

    def test_no_admin_when_users_exist(self, test_user):
        """No admin created when users already exist."""
        result = auth.init_admin_user()
        assert result is None

    def test_admin_created_on_empty_db(self):
        """Admin user auto-created when no users exist."""
        # We need a fresh empty DB for this
        fd, db_path = tempfile.mkstemp(suffix=".db", prefix="test_admin_")
        os.close(fd)
        old_path = auth.DB_PATH
        auth.DB_PATH = db_path
        auth.init_auth_db()

        try:
            password = auth.init_admin_user()
            assert password is not None
            assert len(password) == 48  # os.urandom(24).hex()

            # Verify admin user exists
            conn = auth._get_db()
            row = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
            conn.close()
            assert row is not None
            assert row["is_admin"] == 1

            # Verify ~/.config/deepsight/admin-init.txt was written
            init_file = os.path.expanduser("~/.config/deepsight/admin-init.txt")
            assert os.path.exists(init_file)
            with open(init_file) as f:
                content = f.read()
            assert "admin" in content
            assert password in content
            # Clean up the file
            os.unlink(init_file)
        finally:
            auth.DB_PATH = old_path
            try:
                os.unlink(db_path)
                for s in ("-wal", "-shm"):
                    if os.path.exists(db_path + s):
                        os.unlink(db_path + s)
            except OSError:
                pass


class TestRateLimiting:
    """Login rate limiting."""

    def test_rate_limit_allows_five(self):
        """First 5 attempts are allowed."""
        ip = "192.168.1.100"
        for i in range(5):
            assert auth.check_rate_limit(ip=ip) is True
            auth.record_failure(ip=ip)

    def test_rate_limit_blocks_sixth(self):
        """6th attempt in window is blocked."""
        ip = "10.0.0.1"
        for i in range(5):
            auth.record_failure(ip=ip)
        assert auth.check_rate_limit(ip=ip) is False

    def test_rate_limit_different_ips(self):
        """Rate limiting is per-IP."""
        auth.record_failure(ip="1.1.1.1")
        auth.record_failure(ip="1.1.1.1")
        assert auth.check_rate_limit(ip="2.2.2.2") is True


class TestAuditLogging:
    """Audit event logging."""

    def test_audit_event_logged(self):
        """Audit events are persisted."""
        auth.log_audit("test_event", username="test", details="test detail")
        events = auth.get_audit_events(limit=10)
        assert len(events) > 0
        assert events[0]["event_type"] == "test_event"
        assert events[0]["username"] == "test"

    def test_audit_event_type_filter(self):
        """Audit events can be filtered by type."""
        auth.log_audit("login_success", username="user1")
        auth.log_audit("login_failure", username="user2")
        success_events = auth.get_audit_events(event_type="login_success")
        assert len(success_events) == 1
        assert success_events[0]["username"] == "user1"

    def test_login_success_creates_audit(self, client):
        """Successful API login creates audit event."""
        auth.create_user("audituser2", "auditpass123")
        resp = client.post("/api/auth/login", json={
            "username": "audituser2",
            "password": "auditpass123",
        })
        assert resp.status_code == 200
        events = auth.get_audit_events(limit=5)
        # login_success event should be logged
        assert len(events) > 0
        assert any(e["event_type"] == "login_success" for e in events)


# ═══════════════════════════════════════════
# Story 2: Auth API Endpoints
# ═══════════════════════════════════════════


class TestAuthEndpoints:
    """Auth API endpoints (HTTP-level tests)."""

    def test_login_success(self, client, test_user):
        """POST /api/auth/login returns token with valid credentials."""
        resp = client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "testpassword123",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "token" in data
        assert data["user"]["username"] == "testuser"
        assert "expires_at" in data

    def test_login_failure_wrong_password(self, client, test_user):
        """POST /api/auth/login returns 401 for wrong password."""
        resp = client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "wrongpassword",
        })
        assert resp.status_code == 401
        assert "unauthorized" in resp.get_json()["error"]

    def test_login_missing_fields(self, client):
        """POST /api/auth/login returns 400 for missing fields."""
        resp = client.post("/api/auth/login", json={})
        assert resp.status_code == 400

    def test_auth_status(self, client, test_token):
        """GET /api/auth/status returns user info."""
        resp = client.get("/api/auth/status", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["user"]["username"] == "testuser"

    def test_auth_status_no_token(self, client):
        """GET /api/auth/status returns 401 without token."""
        resp = client.get("/api/auth/status")
        assert resp.status_code == 401

    def test_logout(self, client, test_token):
        """POST /api/auth/logout revokes token."""
        resp = client.post("/api/auth/logout", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200

        # Token should now be invalid
        resp2 = client.get("/api/auth/status", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp2.status_code == 401

    def test_create_api_key_endpoint(self, client, test_token):
        """POST /api/auth/api-keys creates an API key."""
        resp = client.post("/api/auth/api-keys", json={
            "scope": "agent",
            "name": "test-key",
        }, headers={"Authorization": f"Bearer {test_token['token']}"})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["api_key"].startswith("dsk_")
        assert data["scope"] == "agent"

    def test_list_api_keys_endpoint(self, client, test_token):
        """GET /api/auth/api-keys lists keys."""
        # Create a key first
        client.post("/api/auth/api-keys", json={"scope": "agent"}, headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        resp = client.get("/api/auth/api-keys", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200
        keys = resp.get_json()["api_keys"]
        assert len(keys) >= 1

    def test_revoke_api_key_endpoint(self, client, test_token):
        """DELETE /api/auth/api-keys/<id> revokes a key."""
        # Create a key
        create_resp = client.post("/api/auth/api-keys", json={"scope": "agent"}, headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        key_id = create_resp.get_json()["id"]

        # Revoke it
        resp = client.delete(f"/api/auth/api-keys/{key_id}", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200

    def test_audit_endpoint(self, client, test_token):
        """GET /api/auth/audit returns events."""
        resp = client.get("/api/auth/audit?limit=10", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "events" in data
        assert "count" in data


# ═══════════════════════════════════════════
# Story 3: Endpoint Protection
# ═══════════════════════════════════════════


class TestEndpointProtection:
    """All API endpoints return 401 without auth."""

    def test_stats_requires_auth(self, client):
        """GET /api/stats returns 401 without token."""
        assert client.get("/api/stats").status_code == 401

    def test_stats_works_with_auth(self, client, test_token):
        """GET /api/stats returns 200 with valid token."""
        resp = client.get("/api/stats", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200

    def test_hosts_requires_auth(self, client):
        assert client.get("/api/hosts").status_code == 401

    def test_summary_requires_auth(self, client):
        assert client.get("/api/summary").status_code == 401

    def test_cluster_requires_auth(self, client):
        assert client.get("/api/cluster").status_code == 401

    def test_network_requires_auth(self, client):
        assert client.get("/api/network").status_code == 401

    def test_users_requires_auth(self, client):
        assert client.get("/api/users").status_code == 401

    def test_alerts_requires_auth(self, client):
        assert client.get("/api/alerts").status_code == 401

    def test_security_summary_requires_auth(self, client):
        assert client.get("/api/security-summary").status_code == 401

    def test_alert_stats_requires_auth(self, client):
        assert client.get("/api/alert-stats").status_code == 401

    def test_static_routes_unprotected(self, client):
        """Static routes (/, /docs/) are NOT protected."""
        assert client.get("/").status_code == 200
        # /docs/ may 404 if no index but shouldn't be 401
        docs_resp = client.get("/docs/")
        assert docs_resp.status_code != 401

    def test_add_host_unprotected(self, client):
        """Add-host page is NOT protected."""
        assert client.get("/add-host").status_code == 200


class TestAgentAuth:
    """Agent authentication using API keys."""

    def test_report_accepted_with_valid_api_key(self, client, test_user):
        """POST /api/report with valid API key returns 200."""
        key_info = auth.create_api_key(test_user["id"], scope="agent")

        resp = client.post("/api/report", json={
            "host": "test-agent-01",
            "api_key": key_info["api_key"],
            "memory": {"percent": 45},
        })
        assert resp.status_code == 200
        assert resp.get_json()["host"] == "test-agent-01"

    def test_report_rejected_with_invalid_api_key(self, client):
        """POST /api/report with invalid API key returns 403."""
        resp = client.post("/api/report", json={
            "host": "bad-agent",
            "api_key": "dsk_notarealkey1234567890abcdef",
        })
        assert resp.status_code == 403

    def test_report_rejected_without_api_key(self, client):
        """POST /api/report without api_key returns 403."""
        resp = client.post("/api/report", json={
            "host": "no-key-agent",
            "memory": {"percent": 50},
        })
        assert resp.status_code == 403

    def test_report_accepted_with_session_token(self, client, test_token):
        """POST /api/report with session token (Bearer header) also works."""
        resp = client.post("/api/report", json={
            "host": "token-agent",
            "memory": {"percent": 55},
        }, headers={"Authorization": f"Bearer {test_token['token']}"})
        assert resp.status_code == 200


class TestBackwardCompatibility:
    """DEEPSIGHT_INSECURE_NO_AUTH backward compatibility."""

    def test_insecure_mode_bypasses_auth(self, client, test_user):
        """With INSECURE_NO_AUTH=true, endpoints work without tokens."""
        auth.INSECURE_NO_AUTH = True
        resp = client.get("/api/stats")
        assert resp.status_code == 200

    def test_insecure_mode_still_allows_auth(self, client, test_user, test_token):
        """With INSECURE_NO_AUTH=true, tokens still work."""
        auth.INSECURE_NO_AUTH = True
        resp = client.get("/api/auth/status", headers={
            "Authorization": f"Bearer {test_token['token']}",
        })
        assert resp.status_code == 200


class TestLoginRateLimitHTTP:
    """HTTP-level rate limit integration test."""

    def test_six_rapid_failures_rate_limited(self, client, test_user):
        """Six rapid login failures trigger 429."""
        for i in range(6):
            resp = client.post("/api/auth/login", json={
                "username": "testuser",
                "password": f"wrongpass{i}",
            })
            if i < 5:
                assert resp.status_code == 401, f"Attempt {i+1}: expected 401, got {resp.status_code}"
            else:
                assert resp.status_code == 429, f"Attempt {i+1}: expected 429, got {resp.status_code}"


class TestTokenEdgeCases:
    """Edge cases for token handling."""

    def test_bearer_prefix_stripped(self, test_token):
        """Bearer prefix is stripped from token."""
        user = auth.validate_token(f"Bearer {test_token['token']}")
        assert user is not None
        assert user["username"] == "testuser"

    def test_duplicate_user_rejected(self):
        """Creating a duplicate username raises ValueError."""
        auth.create_user("unique", "password123")
        with pytest.raises(ValueError, match="already exists"):
            auth.create_user("unique", "password456")
