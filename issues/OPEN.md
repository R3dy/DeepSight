# Open Issues — DeepSight

> Captured from Discord #issues channel (`1507090516733595658`).
> Autonomous dev team: pick up from here. Move resolved items to `CLOSED.md`.

---

## DS-001 — Rename sysdash-agent → deep-scout (docs + code)

**Reported:** 2026-05-21 13:42 CDT by Royce | **Priority:** Medium

The agents docs page and agent code use `sysdash` / `sysdash-agent` throughout. Rename to **deep-scout**:
- `/opt/deep-scout/` (was `/opt/sysdash-agent/`)
- systemd: `deep-scout` (was `sysdash-agent`)
- Secret: `deep-scout-key-2026` (was `sysdash-agent-key-2026`)
- Files: agent.py, install.sh, server.py, docs, systemd unit

---

## DS-002 — /add-host shows hardcoded placeholder URL

**Reported:** 2026-05-21 13:51 CDT by Royce | **Priority:** High

Shows `https://your-server.your-tailnet.ts.net:8451/install.sh` — should dynamically populate the real collector URL from request headers or bound address.

---

## DS-003 — Authentication docs missing

**Reported:** 2026-05-21 14:01 CDT by Royce | **Priority:** High

No docs for: account setup, default credentials, login flow. Admin-init.txt location is server-side only — users on remote machines can't see it. Need first-run setup wizard or docs page.

---

## DS-004 — admin-init.txt can desync from DB

**Reported:** 2026-05-21 ~15:07 CDT (discovered during troubleshooting) | **Priority:** Medium

Observed: password in `~/.config/deepsight/admin-init.txt` didn't match the argon2 hash in auth.db. Likely a restart race where init_admin_user() wrote a new password file but the DB already had a user. The init flow should be atomic: don't touch the file if a user already exists.

---

## DS-005 — INSECURE_NO_AUTH was enabled, causing login UI loop

**Reported:** 2026-05-21 18:28 CDT (discovered during troubleshooting) | **Priority:** High

`DEEPSIGHT_INSECURE_NO_AUTH=true` was set in server env, bypassing all auth. `/api/auth/status` always returned `username: "insecure-mode"`, confusing the frontend's auth state machine. Flag is a migration escape hatch, not a default.

- [ ] Flag should default to off
- [ ] Flag name is misleading — rename to `DEEPSIGHT_AUTH_BYPASS` or similar
- [ ] Server should log a prominent warning on startup when enabled
- [ ] Frontend should handle insecure-mode gracefully (skip auth checks)

---

## DS-006 ✅ CLOSED — async form submit bug (login page refresh loop)

**Reported:** 2026-05-21 18:45 CDT | **Fixed:** 2026-05-21 18:52 CDT | **Commit:** `1113335`

`doLogin()` is `async` → returns Promise. `onsubmit="return doLogin()"` received a Promise (always truthy), so the browser submitted the form normally, navigating away and cancelling the in-flight fetch. Fixed: `onsubmit="doLogin(); return false"`.
