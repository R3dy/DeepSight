# Open Issues — DeepSight

> Captured from Discord #issues channel (`1507090516733595658`).
> Autonomous dev team: pick up from here. Move resolved items to `CLOSED.md`.

---

## DS-001 — Rename sysdash-agent → deep-scout (docs + code)

**Reported:** 2026-05-21 13:42 CDT by Royce
**Priority:** Medium
**Scope:** Docs site + agent code + installer + config

### Problem
The agents docs page (https://deep-sight-ecru.vercel.app/agents.html) and agent code use `sysdash` / `sysdash-agent` throughout. This is a legacy name from the original System Dashboard project. Should be renamed to match the DeepSight brand.

### Proposed naming
- Agent name: **deep-scout** (Royce's preference — "cutsie" but descriptive)
- Directory: `/opt/deep-scout/` (was `/opt/sysdash-agent/`)
- Systemd service: `deep-scout` (was `sysdash-agent`)
- Shared secret: `deep-scout-key-2026` (was `sysdash-agent-key-2026`)
- Docs: all references updated

### Files affected
| Location | Current | Target |
|---|---|---|
| `agent.py` | sysdash-agent references | deep-scout |
| `install.sh` | sysdash-agent paths | deep-scout |
| `server.py` | secret key, references | deep-scout-key-2026 |
| Docs (Vercel) | agents.html, install guide | deep-scout |
| systemd unit | sysdash-agent.service | deep-scout.service |

### Acceptance criteria
- [ ] Agent renamed in code (agent.py, install.sh, server.py)
- [ ] Docs updated on deep-sight-ecru.vercel.app
- [ ] `curl | sudo bash` install works with new name
- [ ] Old sysdash references gone from all user-facing surfaces
- [ ] Existing deployed agents get migration notes (or re-install required)
