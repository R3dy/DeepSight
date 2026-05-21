# AGENTS.md — DeepSight System Dashboard

## What This Is

DeepSight is a self-hosted, single-binary system monitoring dashboard with integrated SIEM detection engine. It monitors RAM, CPU, GPU, disk, network, and runs background threat-detection collectors (process audit, C2 beaconing, auth monitor, DNS/DGA, file integrity). Deploy agents to remote Linux hosts with a single curl command.

**Discord channel:** `#general` (channel `1506832293363318874`, Guild `1486828959718047925`)

## Architecture

```
┌──────────────┐     ┌──────────────┐
│  agent.py    │     │  agent.py    │   (remote hosts)
│  (systemd)   │     │  (systemd)   │
└──────┬───────┘     └──────┬───────┘
       │ POST /api/report    │
       ▼                     ▼
┌──────────────────────────────────────┐
│  server.py (Flask, :8451)            │
│  ├─ In-memory HOSTS dict             │
│  ├─ detection.py (SIEM engine)       │
│  └─ static/index.html (SPA, ~2930 LOC)│
└──────────────────────────────────────┘
       │ Tailscale Serve (:8451)
       ▼
┌──────────────────────────────────────┐
│  Browser SPA                         │
│  Chart.js + vanilla JS + inline CSS  │
└──────────────────────────────────────┘
```

- **No database for metrics** — host stats live in memory only
- **SQLite for alerts** — `data/alerts.db` (WAL mode, created on first use)
- **No build step for frontend** — single HTML file, inline everything

## File Map

| File | Purpose | Lines |
|------|---------|-------|
| `server.py` | Flask API server, stats collection, routes | ~600 |
| `detection.py` | SIEM engine: collectors, rules, DB | ~800 |
| `static/index.html` | Full SPA: CSS + HTML + JS inline | ~2930 |
| `static/agent.py` | Lightweight remote agent | ~360 |
| `static/add-host.html` | Agent install instructions page | ~180 |
| `docs/` | VitePress documentation | — |
| `data/alerts.db` | SQLite alert store (auto-created) | — |

## server.py — Key Patterns

### State
- `HOSTS` — dict keyed by hostname, holds `{last_seen, stats, status}`
- `HOSTS_LOCK` — threading lock for the HOSTS dict
- `STALE_SECONDS = 15` — mark host stale after 15s without report
- `SHARED_SECRET` — from env `DASHBOARD_SECRET` or hardcoded default

### Route Map
| Route | Method | Purpose |
|-------|--------|---------|
| `/` | GET | Serve SPA |
| `/api/stats?host=X&detail=true` | GET | Stats for one host |
| `/api/report` | POST | Agent upload (auth'd) |
| `/api/hosts` | GET | All host statuses |
| `/api/summary` | GET | Compact overview grid data |
| `/api/cluster` | GET | Full multi-host stats |
| `/api/process/<pid>` | GET | Process forensic detail (3s cache) |
| `/api/network` | GET | TCP/UDP/HTTP connections (5s cache) |
| `/api/users` | GET | Logged-in users from `w` command |
| `/api/alerts` | GET | Recent SIEM alerts |
| `/api/beaconing` | GET | Active beaconing detections |
| `/api/auth-events` | GET | Recent auth events |
| `/api/file-events` | GET | Recent file integrity events |
| `/api/security-summary` | GET | Aggregated security overview |
| `/api/alerts/acknowledge` | POST | Mark alert acknowledged |
| `/api/alert-stats` | GET | Alert counts by severity/category |
| `/install.sh` | GET | Dynamic agent install script |
| `/agent.py` | GET | Raw agent source |
| `/add-host` | GET | Add-host instruction page |
| `/docs/` | GET | VitePress documentation |

### Performance Caches
- `_NETWORK_CACHE` — 5s TTL (network stats are expensive)
- `_PROCESS_CACHE` — 3s per-PID TTL
- `_DISK_IO_PREV` — delta calculation state
- `_CTXT_PREV` — context switch delta state

### Known Issues
- **Bind bug**: After crash/reboot, server.py binds to Tailscale IP instead of 127.0.0.1 → 502. Root cause: `app.run(host="127.0.0.1")` works but the psutil-based collect functions may bind differently. Fix: kill + restart. Permanent fix pending (hard-bind to 127.0.0.1 patch).
- **No `collect_local_stats()` return type contract** — deep data collectors return dicts with inconsistent shapes, handled by `.get()` defensively

## detection.py — SIEM Engine

### Collectors (background threads)
| Name | Interval | Source |
|------|----------|--------|
| Process Auditor | 5s | `/proc/*/cmdline` + ancestry |
| Beaconing Analyzer | 30s | `ss -tnp` + timing analysis |
| Auth Monitor | 5s | `/var/log/auth.log` |
| DNS Monitor | 30s | `resolvectl` + syslog |
| File Integrity | 2s / event | `inotify` or mtime polling |

### Alert Rules
All rules flow through `evaluate_rules(event_type, data)` → `create_alert(...)`.
Alerts are deduplicated by (category, source_ip, title) within 300s window.

### Database
- `data/alerts.db` — auto-created on first import
- Tables: `alerts`, `auth_events`, `beaconing_events`, `file_events`, `dns_events`
- Schema migrations handled by `_migrate_beaconing_schema()` (additive only)

### Packet Sniffer
- Background thread via `tcpdump -i any -A -s 3072`
- Extracts HTTP method/path/query and TLS SNI from outbound TCP
- Metadata shared with beaconing collector via `_http_metadata` dict
- Requires `cap_net_raw` on tcpdump binary

## static/index.html — Frontend SPA

### State
- `currentHost` — selected host
- `allHosts` — full host dict from `/api/hosts`
- `currentView` — `'detail' | 'overview' | 'security'`
- `lastDetailData`, `lastClusterData`, `lastNetworkData` — cached responses
- `lastRamPct`, `lastCpuPct`, `lastGpuPct` — gauge change detection (skip if <1% delta)

### Polling
- Stats: 3s (skips gauge redraw if unchanged)
- Host list: 15s
- Network: 10s (only in detail view)
- Users: 15s
- Security: 5s alerts/auth, 10s beaconing/files

### Widgets
Each widget has inline rendering + deep-dive expansion (modal). Expansion fetches `&detail=true` for `/proc/meminfo`, PSS/USS, disk I/O, GPU temp/clocks.

### Process Tooltips
Hover triggers 200ms debounced fetch to `/api/process/<pid>`, cached in `tooltipCache`.

### Security View
Separate rendering pipeline with `startSecurityPolling()`/`stopSecurityPolling()`. Alert acknowledgment via `POST /api/alerts/acknowledge` with optimistic UI.

### Dependencies
- Chart.js 4.4.0 (CDN) — donut gauges + horizontal bar charts
- No npm dependencies at runtime (package.json is for VitePress docs only)
- Inter + JetBrains Mono fonts (Google Fonts CDN)

## static/agent.py — Remote Agent

- Works with or without `psutil` (pure `/proc` fallback)
- Reads config from `config.json` or CLI args
- POSTs to `/api/report` every N seconds
- Installed via `curl | sudo bash` from `/install.sh` endpoint

## Design Constraints

1. **Single file SPA** — no React/Vue/Svelte, no build step. Keep it that way.
2. **No metric persistence** — HOSTS dict is in-memory only. Alerts are SQLite.
3. **Read `/proc` and `/sys` directly** — psutil is a convenience, not a requirement
4. **All routes on 127.0.0.1:8451** — exposed via Tailscale Serve, not nginx
5. **Agent is dependency-free** — must work with just Python 3 stdlib
6. **Security endpoints degrade gracefully** — if `detection.py` can't import, endpoints return 503
7. **Inline CSS uses CSS variables** — dark theme, violet/cyan/amber/rose palette
8. **No WebSockets** — polling only

## VitePress Docs

- Config: `docs/.vitepress/config.js`
- Built to `static/docs/` (served at `/docs/`)
- Commands: `npm run docs:dev`, `npm run docs:build`

## Secrets

The shared secret `sysdash-agent-key-2026` is hardcoded in multiple places:
- `server.py` default value
- `install.sh` generation template
- `agent.py` default config

Override with `DASHBOARD_SECRET` env var. This is not in secrets.json — it's documentation-level, not credential-level.
