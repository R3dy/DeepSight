# DeepSight Development Roadmap

> Implementation plan for the top 10 missing SIEM features.  
> Based on the [SIEM Feature Gap Report](research/siem-feature-gap-report-2026-05-21.md).

---

## Architecture Decisions (Applies to All Phases)

**Language:** Python 3 only. No JS build pipeline, no new dependencies that break the single-file SPA.

**Shared infrastructure built once, used everywhere:**
- `baseline.py` — rolling z-score engine (powers UEBA #4 + Anomaly Detection #10)
- `notifier.py` — apprise-based notification dispatch (powers #5 + SOAR #9)
- `threat_intel.py` — feed ingestion + lookup API (powers #3 + enrichment in #6/#9)

**Frontend principle:** New widgets go in `static/index.html` inline. No React, no build step. Use existing Chart.js, follow existing CSS variable system.

---

## Phase 1: Immediate Impact (3 features, ~21 hours)

### #5 — Real-Time Notifications & Alerting ⚡

**Effort:** ~3 hours  
**Dependency on:** Nothing. Ships independently.

**Implementation:**
- Create `notifier.py` — wraps `apprise` library
- Config in `~/.config/deepsight/notifications.toml` or env vars
- Severity-based routing: critical → Discord/Slack + push; high → Discord; medium/low → dashboard only
- Quiet hours: `22:00-07:00` configurable
- Hook into `detection.create_alert()` — call `notifier.dispatch(alert)` after alert creation
- Add `notification_test` CLI: `python3 notifier.py --test`

**Files:**
- New: `notifier.py` (~80 lines)
- Modify: `detection.py` — add `notifier.dispatch()` call in `create_alert()`
- New: `config/notifications.example.toml` — documented config template
- Modify: `requirements.txt` (or pip install docs) — add `apprise`

**Config shape:**
```toml
[discord]
webhook_url = "https://discord.com/api/webhooks/..."

[slack]
webhook_url = "https://hooks.slack.com/services/..."

[routing]
critical = ["discord", "slack"]
high = ["discord"]
medium = []
low = []

[quiet_hours]
start = "22:00"
end = "07:00"
```

---

### #2 — Syslog & External Log Ingestion

**Effort:** ~6 hours  
**Dependency on:** Nothing.

**Implementation:**
- Create `syslog_ingest.py` — `socketserver.UDPServer` on port 514
- Parse RFC 3164/5424 with `re` (no new deps) or optional `syslogmp`
- Store in new SQLite table `syslog_events` with: timestamp, host, facility, severity, message, raw
- Background thread in detection.py: `syslog_ingest.start()`
- Basic API: `GET /api/syslog-events?host=X&facility=Y&limit=100`
- Frontend: new widget in Security view — "External Logs" with host selector + message scroll
- Firewall alert rules: `evaluate_rules("syslog", data)` — matches against message patterns (auth fail, ACL deny, etc.)

**Files:**
- New: `syslog_ingest.py` (~150 lines)
- Modify: `detection.py` — add syslog event type to `evaluate_rules()`, start syslog thread
- Modify: `server.py` — add `/api/syslog-events` route
- Modify: `static/index.html` — add External Logs widget in Security view

**New alert rules from syslog:**
- Firewall ACL deny spike (≥10/min from same IP)
- Router/switch auth failure
- NAS login from unusual IP
- Printer admin page access

---

### #3 — Threat Intelligence Feed Integration

**Effort:** ~12 hours  
**Dependency on:** Nothing. Ships independently.

**Implementation:**
- Create `threat_intel.py` with feed fetchers:
  - `fetch_abuseipdb()` — AbuseIPDB v2 API (1K queries/day free tier)
  - `fetch_alienvault_otx()` — AlienVault OTX (unlimited free)
  - `fetch_urlhaus()` — URLhaus malware URL database
  - `fetch_feodo()` — Feodo Tracker C2 IPs
  - `fetch_tor_exits()` — Tor exit node list
- Background thread pulls feeds every hour → store in SQLite tables:
  - `intel_ips(ip, source, category, confidence, last_seen)`
  - `intel_domains(domain, source, category, confidence, last_seen)`
- Lookup API: `threat_intel.lookup_ip(ip)` → `{malicious: bool, categories: [...], confidence: float, sources: [...]}`
- Enrichment hooks:
  - `evaluate_rules("beaconing", ...)` → enrich with IP reputation before firing alert
  - `evaluate_rules("ssh_brute_force", ...)` → enrich source IP
  - `auth_monitor()` → check auth failure IPs against intel
  - DNS collector → check resolved domains against intel

**Files:**
- New: `threat_intel.py` (~250 lines)
- Modify: `detection.py` — add enrichment calls in beaconing, auth, DNS collectors
- New: `config/threat_intel.example.toml` — API key config

**Config shape:**
```toml
[abuseipdb]
api_key = "your-key-here"
enabled = true

[alienvault_otx]
api_key = "your-key-here"
enabled = true

[urlhaus]
enabled = true

[tor_exit_nodes]
enabled = true
```

---

## Phase 2: Deeper Visibility (3 features, ~41 hours)

### Shared Infrastructure: Baseline Engine

Build once, used by both #4 (UEBA) and #10 (Anomaly Detection).

**Implementation:** `baseline.py`
- `RollingBaseline` class: maintains mean, stddev, min, max over configurable window
- Default: 7-day sliding window, hourly buckets
- `is_anomalous(value)` → `{z_score: float, pct_deviation: float, alert: bool}`
- Threshold: `mean + 3σ` (configurable, per-metric)
- Backed by SQLite: `baselines(metric_name, entity_id, bucket_ts, value)`
- Prune old buckets on update (keep last 30 days max)
- Recompute mean/stddev on each update (O(1) via Welford's algorithm)

---

### #6 — Advanced Search & Investigation UI

**Effort:** ~15 hours  
**Dependency on:** Nothing (works with existing data).

**Implementation:**
- Backend: `GET /api/search?q=X&from=...&to=...&limit=50`
  - Parse query syntax: `src_ip:10.0.0.1`, `severity:critical`, `event_type:ssh_fail`, `host:your-server`
  - Full-text search via SQLite FTS5 on alert descriptions, auth events, beaconing events
  - Return: matched rows with highlight snippets, total count
  - FTS5 virtual tables created on startup for `alerts`, `auth_events`, `beaconing_events`
- Frontend: Search bar in Security view header
  - Input with autocomplete dropdown (field suggestions: `src_ip:`, `severity:`, `event_type:`, `host:`, `process:`)
  - Date range picker (two `<input type="datetime-local">`)
  - Results rendered as sortable table with relevance score column
  - Click result → expand detail card (reuse existing alert/event rendering)
  - "Save Query" button → localStorage
  - Result count badge: "142 results in 0.8s"

**Files:**
- New: `search.py` (~150 lines) — FTS5 setup, query parser, ranking
- Modify: `server.py` — add `/api/search` route, init FTS5 on startup
- Modify: `static/index.html` — search bar UI + results panel in Security view

---

### #7 — Security Dashboards & Visualization

**Effort:** ~10 hours  
**Dependency on:** Nothing (uses existing Chart.js + alert data).

**Implementation:**
- New API endpoint: `GET /api/security-metrics?range=24h`
  - Returns pre-computed aggregations: alert volume timeline, top source IPs, severity distribution, MITRE technique coverage, agent health
- Frontend: 4-6 new Chart.js panels in Security view:
  1. **Alert Timeline** — stacked bar by severity over time (last 24h/7d/30d toggle)
  2. **Top Attacking IPs** — horizontal bar chart, colored by most common severity
  3. **Alert Severity Pie** — donut chart with drill-down to alert list
  4. **MITRE Technique Coverage** — radar/spider chart showing which techniques are triggering
  5. **Agent Health Ring** — green/yellow/red status for each reporting host
  6. **Geographic Source IP Map** — (optional, if we add GeoIP) — world heatmap of attack sources

**Files:**
- Modify: `server.py` — add `/api/security-metrics` with SQL aggregation queries
- Modify: `static/index.html` — 4-6 new Chart.js panels, API polling every 30s

---

### #4 + #10 — UEBA + Anomaly Detection (Shared Infrastructure)

**Effort:** ~16 hours combined  
**Dependency on:** `baseline.py` (built first in Phase 2).

**Implementation (UEBA — User & Entity Behavior):**
- Track per-entity metrics hourly:
  - Per user: login count, sudo count, failed auth count, unique hosts touched
  - Per host: outbound connection count, unique destination IPs, DNS query count, process spawn count
- Compute rolling baselines via `baseline.py`
- `ueba_collector` thread (5 min interval): samples metrics → stores in `baselines` table → evaluates anomalies
- Alert when `z_score > 3.0`: "User admin averaged 2.3 logins/hr over 7d, current: 47 logins/hr (z=12.4)"
- UEBA alerts stored with `category: "ueba"`, enriched with baseline context

**Implementation (Anomaly Detection):**
- Same `baseline.py` infrastructure, different metrics:
  - SSH attempts per host per hour
  - Outbound bytes per host per hour
  - DNS query volume per host per hour
  - File modification events per host per hour
- Alert on deviation: "Host db-server averaged 120 outbound connections/hr over 7d, current: 1,847 (z=14.2)"

**Alert design:**
```
🔵 UEBA Anomaly — user 'deploy'
   Metric: failed_auth_per_hour
   Baseline: 0.5/hr (7d avg, σ=0.3)
   Current: 14/hr (z-score: 45.0)
   → Possible credential brute force or compromised account
```

**Files:**
- New: `baseline.py` (~200 lines) — RollingBaseline class, Welford's algorithm, SQLite storage
- New: `ueba.py` (~200 lines) — metric collectors, anomaly evaluation, alert generation
- Modify: `detection.py` — add `ueba` event type to `evaluate_rules()`, start UEBA thread
- Modify: `server.py` — add anomaly enrichment to security summary endpoint
- Modify: `static/index.html` — UEBA alert rendering (reuse alert card template, add baseline context)

---

## Phase 3: Platform Maturity (3 features, ~48 hours)

### #1 — Real-Time Event Correlation Engine

**Effort:** ~20 hours  
**Dependency on:** Phase 1 notifications, Phase 2 baseline engine.

**Implementation:**
- Create `correlation.py` with `CorrelationEngine` class
- **Rule format** (TOML or JSON):
  ```toml
  [rules.credential_theft_to_lateral]
  sequence = [
    { event_type = "ssh_fail", source_ip = "$src_ip", min_count = 3 },
    { event_type = "ssh_success", source_ip = "$src_ip", host = "$host" },
    { event_type = "sudo", host = "$host" },
    { event_type = "outbound_conn", host = "$host", remote_port = [22, 3389, 445] },
  ]
  window_minutes = 10
  severity = "critical"
  title = "Possible credential theft → lateral movement chain"
  mitre_tactic = "Lateral Movement"
  mitre_technique = "T1021 (Remote Services)"
  ```
- **Engine loop:** Maintain sliding window buffer of all recent events (5 min). On each new event, evaluate all correlation rules whose first step matches. Track partial matches as "pending chains." Fire correlated alert when chain completes.
- Store correlation rules in `config/correlation_rules/` directory (one TOML per rule)
- Pre-built rules: credential theft chain, webshell → C2 chain, persistence chain (useradd → sudoers → crontab)

**Alert design:**
```
🔴 Correlated Incident: Credential Theft → Lateral Movement
   Chain: 7x SSH fail (203.0.113.50) → SSH success (admin@web-01)
          → sudo apt install nmap (admin@web-01)
          → outbound SSH to db-01:22 (web-01)
   Confidence: 92%  |  Window: 8.2 minutes
   MITRE: T1021 (Remote Services), T1110 (Brute Force)
```

**Files:**
- New: `correlation.py` (~350 lines) — engine, rule parser, chain tracker, alert generator
- New: `config/correlation_rules/credential_theft.toml`
- New: `config/correlation_rules/webshell_to_c2.toml`
- New: `config/correlation_rules/persistence_chain.toml`
- Modify: `detection.py` — add `correlation` event type, register CorrelationEngine in `start_collectors()`
- Modify: `server.py` — add correlation incidents to security summary
- Modify: `static/index.html` — correlated incident rendering (shows chain steps with timeline)

---

### #8 — Case Management & Incident Tracking

**Effort:** ~16 hours  
**Dependency on:** Alerts system (Phase 1). Nice-to-have: correlation (Phase 3).

**Implementation:**
- New SQLite schema:
  ```sql
  CREATE TABLE cases (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT CHECK(status IN ('open','triaging','investigating','contained','closed')),
    severity TEXT,
    assigned_to TEXT,
    created_at TEXT, updated_at TEXT, closed_at TEXT,
    summary TEXT, root_cause TEXT, resolution TEXT
  );
  CREATE TABLE case_alerts (case_id INT, alert_id INT);
  CREATE TABLE case_notes (id INT, case_id INT, author TEXT, note TEXT, created_at TEXT);
  CREATE TABLE case_timeline (id INT, case_id INT, action TEXT, detail TEXT, timestamp TEXT);
  ```
- API:
  - `POST /api/cases` — create from alert(s)
  - `GET /api/cases?status=open` — list
  - `PATCH /api/cases/<id>` — update status, assign, notes
  - `POST /api/cases/<id>/alerts` — link alert
- Frontend: Cases tab in Security view
  - Case list: status badge, title, assigned, age, alert count
  - Case detail modal: status workflow buttons (Triaging → Investigating → Contained → Closed), notes thread, linked alerts, timeline
  - "Create Case" button on any alert — pre-fills title, links alert

**Files:**
- New: `case_management.py` (~200 lines) — schema, CRUD, API helpers
- Modify: `server.py` — add case API routes
- Modify: `static/index.html` — Cases tab + case detail modal in Security view

---

### #9 — SOAR Playbooks (Enrichment Only)

**Effort:** ~12 hours  
**Dependency on:** Threat intel (#3), notifications (#5).

**Implementation:**
- **Enrichment-only scope** — no auto-blocking, no iptables, no host isolation. Those are dangerous defaults for a self-hosted tool where the operator is also the target.
- Playbook engine in `playbooks.py`:
  - Loads playbook definitions from `config/playbooks/` (YAML)
  - Trigger on alert creation (category + severity match)
  - Executes enrichment steps sequentially
  - Stores results in alert enrichment field
- **Pre-built enrichment playbooks:**
  ```yaml
  # playbooks/enrich_beaconing.yaml
  trigger:
    category: beaconing
    severity: [critical, high]
  steps:
    - action: threat_intel_lookup_ip
      field: source_ip
    - action: threat_intel_lookup_domain
      field: remote_host
    - action: reverse_dns
      field: source_ip
    - action: geoip_lookup
      field: source_ip
  ```
- Playbook actions: `threat_intel_lookup_ip`, `threat_intel_lookup_domain`, `reverse_dns`, `geoip_lookup`, `whois`, `notify_discord`, `notify_slack`
- Minimum viable: enrichment-only, no response actions in v1

**Files:**
- New: `playbooks.py` (~250 lines) — engine, YAML parser, action dispatcher
- New: `config/playbooks/enrich_beaconing.yaml`
- New: `config/playbooks/enrich_brute_force.yaml`
- New: `config/playbooks/enrich_reverse_shell.yaml`
- Modify: `detection.py` — call playbook engine in `create_alert()`

---

## Implementation Order & Dependencies

```
Week 1: Phase 1 (Weekend Sprint)
├── Day 1 AM: #5 Notifications (3h)          ← ship first, independent
├── Day 1 PM: #2 Syslog Ingestion (6h)       ← independent, unlocks data
├── Day 2:    #3 Threat Intel (12h)          ← independent, enriches everything

Week 2-3: Phase 2
├── Day 1:    baseline.py shared infra (4h)  ← prerequisite for #4/#10
├── Day 2-3:  #6 Search UI (15h)             ← independent of baseline
├── Day 4-5:  #7 Security Dashboards (10h)   ← independent, uses existing data
├── Day 6-8:  #4 UEBA + #10 Anomaly (16h)    ← depends on baseline.py

Week 4+: Phase 3
├── Day 1-3:  #1 Correlation Engine (20h)    ← biggest feature, most architecture
├── Day 4-5:  #8 Case Management (16h)       ← ties alerts → incidents
├── Day 6-7:  #9 SOAR Enrichment (12h)       ← depends on threat intel + notifications
```

**Total:** ~110 hours across all 10 features.

---

## Out of Scope (by design)

- **Compliance reporting** (PCI-DSS, HIPAA, SOC2) — enterprise-only, not home lab relevant
- **Vulnerability scanner integration** — adds operational complexity, maintain your own Nessus/OpenVAS
- **Windows Event Log collection** — Linux-only project, scope boundary
- **Full UEBA with ML models** — statistical baselining is sufficient for self-hosted use
- **Auto-response playbooks** (iptables blocking, user disable) — dangerous defaults for home lab where operator is also target

---

## Success Criteria

After Phase 1: "DeepSight catches attacks AND tells me about them"
After Phase 2: "DeepSight catches attacks I didn't know to look for"
After Phase 3: "DeepSight hunts, correlates, and triages — I investigate"
