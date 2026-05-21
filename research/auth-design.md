# BMAD Authentication Design — DeepSight

> **Phase:** Discovery → Planning → Solutioning  
> **Issue:** [#7](https://github.com/R3dy/DeepSight/issues/7)  
> **Method:** BMAD structured build — one artifact, decisions over suggestions, industry standards baseline

---

## 1. Discovery — Threat Model & Requirements

### 1.1 Attack Surface

DeepSight exposes 14 API endpoints across two trust boundaries:

| Boundary | Access | Risk |
|----------|--------|------|
| **Dashboard API** (12 endpoints) | Any network-reachable client | Read: full host telemetry, process FDs/env, alerts, user sessions. Write: alert acknowledgment. |
| **Agent API** (2 endpoints) | Agent hosts only | Write: telemetry injection. No read access. |
| **Static assets** (/ , /docs/, /add-host) | Public | Read-only, informational. Low risk. |

### 1.2 Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **Network neighbor** | Can reach the Tailscale subnet or local network | Reconnaissance: map infrastructure, read env vars, find credentials |
| **Compromised tailnet host** | Full tailnet access | Exfil: extract process/env data from all monitored hosts. Disrupt: acknowledge alerts to hide attacks. |
| **Compromised agent host** | Has the shared secret | Inject: poison telemetry data. Spoof: pretend to be a different host. |

### 1.3 Regulatory & Standards Baseline

This design targets the following standards:

- **OWASP ASVS v4.0** — Level 2 (standard for security-sensitive applications)
  - V2.1: Password Security
  - V2.2: General Authenticator Requirements
  - V2.10: Service Authentication
  - V4.1: General Access Control Design
- **NIST SP 800-63B** — Digital Identity Guidelines
  - AAL1: Single-factor authentication (baseline)
  - AAL2: Multi-factor (future consideration)
- **RFC 6750** — Bearer Token Usage (OAuth 2.0 Bearer Token)
- **RFC 7519** — JSON Web Token (JWT)

### 1.4 Requirements (MoSCoW)

**Must Have:**
- M1: All API endpoints require authentication (except /, /docs/, /add-host, /install.sh, /agent.py)
- M2: Bearer token authentication for dashboard/API access
- M3: Separate API key authentication for agent reports (not shared with dashboard)
- M4: Token generation and validation with expiration (default: 24h for sessions, 90d for API keys)
- M5: Login endpoint with rate limiting (5 attempts/60s per IP)
- M6: Audit logging for all authentication events (login, logout, token refresh, failed attempts)
- M7: Secrets never stored in plaintext — tokens hashed server-side (SHA-256)
- M8: Dashboard redirects unauthenticated users to login page

**Should Have:**
- S1: Multiple API keys with scoped permissions (read-only, read-write, agent-only)
- S2: Session management with configurable idle timeout (default: 8h)
- S3: Token revocation (server-side blacklist)
- S4: Environment-variable-based initial admin setup

**Could Have:**
- C1: OIDC/OAuth2 integration (Google, GitHub, generic OIDC provider)
- C2: MFA/TOTP support
- C3: IP-based allowlisting for agent reports
- C4: JWT-based stateless tokens (avoid server-side session store)

**Won't Have (v1):**
- W1: Full RBAC/role-based access control (v2)
- W2: LDAP/Active Directory integration (v2)

---

## 2. Planning — Architecture

### 2.1 Authentication Architecture

```
┌─────────────────────────────────────────────────┐
│                  DeepSight Server                │
│                                                 │
│  ┌──────────┐    ┌──────────────┐               │
│  │  Flask    │    │  Token       │               │
│  │  @auth    │───▶│  Validator   │               │
│  │  decorator│    │  (SHA-256    │               │
│  │           │    │   compare)   │               │
│  └──────────┘    └──────┬───────┘               │
│                         │                       │
│                    ┌────▼──────┐                │
│                    │  SQLite    │                │
│                    │  auth.db   │                │
│                    │  - users   │                │
│                    │  - tokens  │                │
│                    │  - audit   │                │
│                    └───────────┘                │
│                                                 │
│  POST /api/auth/login  →  issue bearer token    │
│  POST /api/auth/logout →  revoke token          │
│  GET  /api/auth/status →  token validation      │
└─────────────────────────────────────────────────┘
         │                          │
         ▼                          ▼
   ┌──────────┐            ┌──────────────┐
   │ Dashboard│            │  Agent Host  │
   │ Bearer   │            │  API Key     │
   │ Token    │            │  (separate)  │
   │ Header   │            │  POST body   │
   └──────────┘            └──────────────┘
```

### 2.2 Token Types

| Token Type | Scope | Lifetime | Storage | Use |
|-----------|-------|----------|---------|-----|
| **Session Token** | Dashboard API (full) | 24h (configurable) | SHA-256 hash in SQLite | Browser sessions |
| **API Key** | Dashboard API (scoped) | 90d (configurable) | SHA-256 hash in SQLite | CI/CD, scripts, integrations |
| **Agent Secret** | Agent report only | Permanent (until rotated) | SHA-256 hash in SQLite | Agent telemetry |

### 2.3 Authentication Flow

**Dashboard Login:**
```
Browser                    Server                      SQLite
  │                          │                          │
  │  POST /api/auth/login    │                          │
  │  {user, password}   ───▶ │  argon2id.verify()       │
  │                          │  ──────────────────────▶ │
  │                          │  ◀──── user record ───── │
  │                          │                          │
  │                          │  Generate token (os.urandom(32))
  │                          │  Store SHA-256(token)   │
  │  ◀── {token, expires} ── │                          │
  │                          │                          │
  │  Store token in          │                          │
  │  localStorage            │                          │
  │                          │                          │
  │  GET /api/stats          │                          │
  │  Authorization: Bearer   │                          │
  │  <token>            ───▶ │  token_validator(token)  │
  │                          │  SHA-256(token) compare  │
  │                          │  ──────────────────────▶ │
  │                          │  ◀──── match ─────────── │
  │  ◀── 200 OK ──────────── │                          │
```

**Agent Report:**
```
Agent Host                 Server
  │                          │
  │  POST /api/report        │
  │  {host, api_key, stats}  │
  │                     ───▶ │  api_key_validator(key)
  │                          │  SHA-256(key) compare
  │                          │
  │  ◀── 200 OK ──────────── │
```

### 2.4 Password Policy (NIST SP 800-63B)

- Minimum 8 characters (NIST minimum)
- No composition rules (NIST recommends against forced character classes)
- Check against known compromised passwords (optional: Have I Been Pwned API)
- Password hashing: argon2id (winner of Password Hashing Competition, OWASP recommended)
  - Parameters: time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16

### 2.5 Rate Limiting (OWASP ASVS V2.2)

| Endpoint | Limit | Window | Response |
|----------|-------|--------|----------|
| POST /api/auth/login | 5 failures | 60s per IP | 429 + exponential backoff |
| POST /api/auth/login | 20 failures | 15min per IP | 429 + lockout warning |
| All authenticated endpoints | 500 requests | 60s per token | 429 (optional, v2) |

### 2.6 Audit Events

Every authentication event logged to `auth_audit` table:
- `login_success` / `login_failure` — timestamp, IP, user, reason
- `token_created` / `token_revoked` — timestamp, token_id, scope
- `logout` — timestamp, user, session_id
- `rate_limit_hit` — timestamp, IP, endpoint

---

## 3. Solutioning — Implementation Stories

### Story 1: Auth Module Foundation
**Estimate:** 3h | **Depends on:** Nothing

Create `auth.py` with:
- `User` and `Token` model classes
- `init_auth_db()` — auto-create SQLite tables on first use
- `create_user(username, password)` — argon2id hash + store
- `verify_user(username, password)` — lookup + argon2id verify
- `create_token(user_id, token_type, scope, ttl)` — generate token, store hash
- `validate_token(token_string)` — SHA-256 hash → lookup → check expiry → return user
- `revoke_token(token_id)` — update revoked_at timestamp
- `require_auth` — Flask decorator that validates Bearer token and returns 401
- `require_agent_auth` — Flask decorator that validates agent API key

### Story 2: Auth API Endpoints
**Estimate:** 2h | **Depends on:** Story 1

Add to server.py:
- `POST /api/auth/login` — rate-limited, returns session token
- `POST /api/auth/logout` — revokes current token
- `GET /api/auth/status` — returns current user info from token
- `POST /api/auth/api-keys` — create scoped API key (requires auth)
- `DELETE /api/auth/api-keys/<id>` — revoke API key (requires auth)

### Story 3: Protect All Existing Endpoints
**Estimate:** 1h | **Depends on:** Story 2

Add `@require_auth` decorator to all 12 unprotected API routes in server.py.
Keep static routes (/, /docs/, /add-host) unauthenticated.
Migrate agent /api/report from shared secret to API key validation.

### Story 4: Login UI
**Estimate:** 2h | **Depends on:** Story 2

Add to static/index.html:
- Login page overlay when no valid token
- Token storage in localStorage
- Auto-redirect to dashboard on successful login
- "Unauthorized" handling: clear token, show login
- Session expiry: check token on each API call

### Story 5: Initial Admin Setup
**Estimate:** 1h | **Depends on:** Story 1

- On first startup (no users in auth.db), generate random admin password
- Print to stdout: `[auth] Initial admin password: <random-24-chars>`
- Write to `~/.config/deepsight/admin-init.txt` with chmod 600
- Or: accept `DEEPSIGHT_ADMIN_PASSWORD` env var for automated setup
- Force password change on first login

### Story 6: Audit Logging & Rate Limiting
**Estimate:** 2h | **Depends on:** Story 2

- IP-based rate limiter for login endpoint (in-memory dict with TTL)
- All auth events written to `auth_audit` SQLite table
- `GET /api/auth/audit?limit=50` — audit log endpoint (requires auth)
- Audit events surfaced in Security view

### Story 7: Tests, Docs, Changelog
**Estimate:** 2h | **Depends on:** All above

- 15+ test cases: login success, login failure, token validation, token expiry, rate limiting, API key auth, agent auth, unauthorized rejection
- Update docs: security section, API reference with auth headers
- CHANGELOG: v0.4.0 — Authentication & Access Control
- Migration guide: existing deployments need to set admin password

---

## 4. Backward Compatibility

DeepSight 0.3.0 → 0.4.0 migration:

| Concern | Approach |
|---------|----------|
| Existing dashboards break | Generate admin password on startup, print to stdout. Dashboard shows login page. |
| Existing agents break | Agent API key printed on startup. Update agent config.json with new key. |
| Scripted API access | Create permanent API key via POST /api/auth/api-keys |
| Monitoring integrations | API key with read-only scope |

Grace period option: `DEEPSIGHT_INSECURE_NO_AUTH=true` env var for 0.4.0 only (logs warning on every request). Removed in 0.5.0.

---

## 5. Acceptance Criteria

- [ ] All 12 unprotected API endpoints return 401 without valid Bearer token
- [ ] Login endpoint rate-limited: 5 failures/60s per IP
- [ ] Passwords hashed with argon2id (verified in test)
- [ ] Tokens stored as SHA-256 hashes (verified in test — no plaintext tokens in DB)
- [ ] Token expiry enforced (test: expired token → 401)
- [ ] Token revocation works (test: revoked token → 401)
- [ ] Agent reports accepted with valid API key, rejected otherwise
- [ ] Dashboard shows login page when no token present
- [ ] Audit events logged for all auth actions
- [ ] First-run admin password generated and printed to stdout
- [ ] All existing tests still pass
- [ ] No plaintext secrets in code, configs, or logs
