# Architecture

> How DeepSight collects, transmits, and displays system metrics across your fleet.

## System Overview

```
┌──────────────────────┐     ┌──────────────────────┐
│   Agent (Linux)      │     │   Agent (Linux)      │
│   agent.py           │     │   agent.py           │
│   systemd service    │     │   systemd service    │
└──────┬───────────────┘     └──────┬───────────────┘
       │ POST /api/report          │ POST /api/report
       │ (every 2s)                │ (every 2s)
       ▼                           ▼
┌────────────────────────────────────────────────────────────────┐
│                      Collector (Flask)                          │
│                                                                │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐             │
│  │ HOSTS    │  │ Network  │  │ Process Detail   │             │
│  │ dict     │  │ Cache 5s │  │ Cache 3s/pid     │             │
│  └──────────┘  └──────────┘  └──────────────────┘             │
│                                                                │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │                  Detection Engine (SIEM)                 │  │
│  │                                                         │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │  │
│  │  │ Process  │  │ Auth Log │  │ C2       │  │ FIM    │  │  │
│  │  │ Auditor  │  │ Monitor  │  │ Beacon   │  │ Watcher│  │  │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └───┬────┘  │  │
│  │       └──────────────┴─────────────┴────────────┘      │  │
│  │                         │                                │  │
│  │                    ┌────▼─────┐                          │  │
│  │                    │  Alert   │                          │  │
│  │                    │  Rules   │                          │  │
│  │                    │  Engine  │                          │  │
│  │                    └────┬─────┘                          │  │
│  │                         │                                │  │
│  │                    ┌────▼─────┐                          │  │
│  │                    │  SQLite  │                          │  │
│  │                    │  Alerts  │                          │  │
│  │                    └──────────┘                          │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                                │
│  Data Sources: psutil, /proc, /sys, ss, w, auth.log, inotify  │
└──────────────────────┬─────────────────────────────────────────┘
                       │ HTTPS (Tailscale Serve)
                       ▼
┌────────────────────────────────────────────────────────────────┐
│                      Browser (SPA)                              │
│                                                                │
│  Chart.js gauges  │  Tabbed process tables                     │
│  Hover tooltips   │  Click-to-forensic modals                  │
│  View switching   │  Column sorting                            │
│  Security tab     │  Alert feed + beaconing + auth + FIM       │
└────────────────────────────────────────────────────────────────┘
```

## Components

### Collector (`server.py`)

A Flask application that runs on the primary host (`your-server`). Responsibilities:

- **Self-monitoring** — collects stats from localhost using `psutil` and direct `/proc`/`/sys` reads
- **Agent ingestion** — receives reports from remote agents via `POST /api/report`
- **In-memory storage** — keeps the latest report per host in a Python dict (no database)
- **API surface** — exposes 10+ JSON endpoints for the frontend
- **Static serving** — serves the SPA, install script, and agent Python file

### Agent (`agent.py`)

A standalone Python script that runs on remote Linux hosts. Designed to be dependency-free:

- **Primary path**: Uses `psutil` for rich metrics (process list with CPU%, disk I/O)
- **Fallback path**: Parses `/proc/meminfo`, `/proc/stat`, `/proc/[pid]/statm`, and `os.statvfs` when `psutil` is unavailable
- **Transport**: HTTP POST with JSON body, authenticated via shared secret

### Frontend (SPA)

A single HTML file with inline CSS and JavaScript. No build step, no framework:

- **Charts**: Chart.js for donut gauges and bar charts
- **Tables**: DOM-generated with sortable column headers
- **Tooltips**: CSS-positioned divs with data fetched on hover (400ms debounce, per-PID cache)
- **Modals**: Full-screen overlays for process forensics and expanded widget views

## Detection Engine

DeepSight's SIEM layer runs background collectors that continuously analyze host telemetry and fire alerts based on configurable rules.

### Collectors

Each collector runs on its own background thread with a dedicated polling interval:

| Collector | Interval | Data Source |
|-----------|----------|-------------|
| Process Auditor | 10s | Process list with ancestry + cmdline |
| C2 Beacon Analyzer | 30s | Outbound HTTP connections with timing history |
| Auth Log Monitor | 5s | `/var/log/auth.log` (local + agent-reported) |
| DNS Analyzer | 10s | DNS query cache from `systemd-resolved` |
| FIM Watcher | Event-driven | `inotify` on watched paths |

### Alert Rules Engine

Processed data flows through a rule evaluation pipeline:

1. **Ingest** — collector threads push observations onto an internal queue
2. **Evaluate** — each rule checks observations against its threshold criteria
3. **Correlate** — related events are grouped (e.g., brute force attempts from same source IP)
4. **Persist** — alerts are written to SQLite with full context
5. **Notify** — the frontend polls new alerts on each refresh cycle

Rules are defined declaratively with severity, MITRE mappings, and threshold parameters. See the [Security Monitoring guide](/security#alert-rules-reference) for the full rules reference.

### SQLite Storage

Alerts are stored in a local SQLite database (`alerts.db`) with a default 30-day retention window. Each alert record includes:

- Rule ID, severity, host, timestamp
- JSON context blob (process tree, connection details, file diffs)
- Acknowledged status and operator notes

The database is optimized for time-range queries with an index on `(host, timestamp)`. Cleanup runs hourly, removing alerts older than the retention window.

### Performance

All detection runs server-side with zero agent overhead. The most expensive operation — C2 beacon periodicity analysis — runs on a 30-second interval using cached connection history.

| Collector | CPU Impact | Memory |
|-----------|-----------|--------|
| Process Auditor | <1% | ~2 MB |
| C2 Beacon Analyzer | ~2% | ~5 MB (connection history) |
| Auth Log Monitor | <1% | ~1 MB |
| DNS Analyzer | ~1% | ~2 MB |
| FIM Watcher | <1% | ~1 MB |

## Data Flow

### Real-time polling (detail view)

1. Browser polls `GET /api/stats?host=X` every 3 seconds
2. Server collects fresh stats via `psutil` and `/proc`
3. Frontend updates gauges (skipped if value unchanged by >1%), process tables, disk bars
4. Network widget polls `GET /api/network` every 10 seconds (cached 5s server-side)
5. Users widget polls `GET /api/users` every 15 seconds

### Cluster view

1. Browser polls `GET /api/cluster` every 3 seconds
2. Server returns full stats for all hosts plus cross-host aggregated process tables
3. Frontend renders stacked bar charts via Chart.js

### On-demand deep data

1. User clicks expand (⛶) on a widget
2. Frontend fetches `GET /api/stats?host=X&detail=true` (or the cluster/network/process endpoint)
3. Deep data includes `/proc/meminfo` full fields, PSI pressure, PSS/USS from `smaps_rollup`, disk I/O, GPU temp/clocks
4. Modal renders the expanded view

### Process forensic drill-down

1. User clicks a process row
2. Frontend fetches `GET /api/process/<pid>` (cached 3s)
3. Server reads `/proc/pid/status`, `/proc/pid/cmdline`, `/proc/pid/environ`, `/proc/pid/fd/`, `/proc/pid/task/pid/children`
4. Modal displays command line, memory map, FDs, children, network connections, environment

## Performance Design

| Concern | Solution |
|---------|----------|
| Heavy `/api/network` (FD traversal) | Switched to `ss -tnp`, cached 5s server-side |
| Process detail per hover | Per-PID 3s cache, 200ms debounce |
| Chart re-renders | Gauge updates skipped when value unchanged by >1% |
| Polling frequency | Stats 3s, network 10s, users 15s |
| Alert feed polling | Security endpoints polled every 5s, alerts cached 10s |
| C2 periodicity analysis | 30s interval, FFT over sliding 10-min window |
| Auth log parsing | Tail-based (no full re-read), 5s poll |
| DOM rebuilds | Table `innerHTML` per poll (acceptable at 3s interval with <20 rows) |
| SQLite write volume | Batch inserts per collector cycle, WAL mode |

## Security

- **Network isolation**: All endpoints bound to `127.0.0.1`, exposed via Tailscale Serve
- **Agent auth**: Shared secret in POST body, validated by collector
- **Metric storage**: Host stats in memory only (no disk persistence for metrics)
- **Alert storage**: SQLite with local-only access, 30-day retention
- **No shell access**: Agents only collect and report metrics
- **Read-only**: Dashboard and API are entirely read operations (except `/api/report`, `/api/alerts/acknowledge`)
- **Detection isolation**: SIEM engine runs on collector only — agents never execute detection logic

## Limits

- **No persistent metric history** — metric data exists only in memory, lost on restart (alerts are persisted in SQLite)
- **Agent network only** — agents don't report network connections (only collector has `/api/network`)
- **Single collector** — no federation or failover
- **Linux only** — agent and collector require Linux `/proc` and `/sys` filesystems
- **Auth log monitoring** — agent hosts must have `auth.log` accessible (root agent or syslog forwarding)
