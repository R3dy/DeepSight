# DeepSight SIEM Feature Gap Report
**Date:** 2026-05-21  
**Scope:** Top 10 SIEM features missing or incomplete in DeepSight, benchmarked against Splunk ES, Microsoft Sentinel, IBM QRadar, Elastic Security, Chronicle, Sumo Logic, Exabeam, Securonix, LogRhythm, and CrowdStrike Falcon LogScale.

---

## What DeepSight Has Today

| Capability | Status |
|-----------|--------|
| SSH brute force detection | ✅ Working |
| Reverse shell detection (15+ patterns) | ✅ Working |
| Web shell detection (web server → shell) | ✅ Working |
| Process from suspect dirs (/tmp, /dev/shm) | ✅ Working |
| Beaconing/C2 detection (interval analysis) | ✅ Working |
| DGA detection (entropy analysis) | ✅ Working |
| File integrity monitoring (polling + inotify) | ✅ Working |
| Auth event monitoring (SSH/sudo/su/useradd) | ✅ Working |
| Packet sniffing (HTTP/TLS metadata via tcpdump) | ⚠️ Partial (needs cap_net_raw) |
| MITRE ATT&CK tagging on alerts | ✅ Working |
| Multi-host agent reporting | ✅ Working |
| SQLite alert store with basic API | ✅ Working |
| Static dashboard (Chart.js gauges) | ✅ Working |

---

## Top 10 Missing Features (Prioritized)

### 1. Real-Time Event Correlation Engine
**Coverage:** All 10 platforms require it. **DeepSight:** Has none.

**What it is:** An engine that links disparate log entries into coherent security incidents using rule chains, sequence matching, and temporal windows. Converts "10 failed SSH + 1 success + sudo + outbound connection" into a single compromise incident rather than 13 unrelated alerts.

**Why it's there:** Correlation is what separates a SIEM from a log aggregator. Individual alerts are noise; chains are signal. Without correlation, every detection fires independently and the analyst must mentally connect the dots — which doesn't happen at 3 AM.

**How teams improve posture with it:** Analysts see attack chains instead of atomized alerts. Multi-stage attacks (credential theft → lateral movement → exfiltration) get caught as coherent incidents rather than slipping through as individually benign events. MTTR drops significantly because the platform does the connecting work.

**DeepSight path:** Rule chains with sequence matching. Store recent events in-memory dict keyed by host/IP, evaluate correlation rules on new alerts. Example rule: `[ssh_fail(x3) → ssh_success → sudo → outbound_conn]` within 10 min window. ~15-20 hours effort. **Priority: MED (high value, real work to implement).**

---

### 2. Syslog & External Log Ingestion
**Coverage:** All 10 platforms. **DeepSight:** Has zero external log ingestion.

**What it is:** The ability to ingest security telemetry from network devices, routers, switches, firewalls, printers, IoT devices, NAS appliances — anything that speaks syslog (RFC 3164/5424). Also covers cloud log APIs, application logs, and third-party security tool output.

**Why it's there:** Without broad data ingestion, a SIEM has nothing to analyze. Your router, NAS, printers, switches, and IoT devices all speak syslog. A compromised router doing DNS hijacking won't appear in any of DeepSight's current detection surfaces. Ingestion is the universal first step that feeds every downstream capability.

**How teams improve posture with it:** Security teams centralize telemetry from silos into a single pane of glass. They eliminate blind spots across on-prem, cloud, and hybrid environments. No attacker activity goes uncollected just because the log source wasn't monitored.

**DeepSight path:** `socketserver.UDPServer` on port 514 (stdlib, ~30 lines). Parse RFC 3164/5424 with regex or `syslogmp`. Store in SQLite. Or use `rsyslog` → file → DeepSight tails it. ~4-6 hours effort. **Priority: HIGH — unlocks network infrastructure visibility, low effort.**

---

### 3. Threat Intelligence Feed Integration
**Coverage:** All 10 platforms. **DeepSight:** Has zero threat intel.

**What it is:** Ingests structured threat intel feeds (STIX/TAXII, commercial feeds, open-source blocklists, custom IOCs) and enriches every alert and log entry with contextual data — IP reputation, domain risk scores, malware family attribution, threat actor profiles, TTP mappings.

**Why it's there:** Without intel context, an alert about a connection to an unknown IP is noise. With it, that same IP is tied to a known APT group's C2 infrastructure and the alert becomes an incident. Intel turns data into decision-grade information. DeepSight currently detects patterns (timing, heuristics) but has zero knowledge of known-bad IPs, domains, or hashes.

**How teams improve posture with it:** Analysts see intel-enriched alerts with risk context pre-attached. Threat hunters pivot through intel to find matches against known adversary infrastructure. Detection engineers build rules around emerging IOCs. A single-beacon hit to a known-malicious IP that your beaconing detector might miss (low sample count) gets caught by IP reputation alone.

**DeepSight path:** Free feeds: AbuseIPDB (1K/day free), AlienVault OTX (unlimited free), URLhaus, Feodo Tracker, Tor exit node list. Background thread pulls feeds every hour → store in SQLite → match against source/destination IPs in auth logs, DNS lookups, HTTP hosts from packet sniffer. ~8-12 hours effort. **Priority: HIGH — medium effort, dramatically improves alert quality.**

---

### 4. User & Entity Behavior Analytics (UEBA)
**Coverage:** 7 of 10 platforms have dedicated UEBA. **DeepSight:** Has none.

**What it is:** Machine learning that baselines normal behavior for users, hosts, and services over time, then surfaces anomalous deviations — unusual login times, atypical data access patterns, impossible-travel geolocation, abnormal process execution chains, unusual data volume transfers. Detects what signature rules can't define in advance.

**Why it's there:** Credential-based attacks and insider threats don't trigger signature rules. An attacker with valid credentials looks normal to rule-based detection. UEBA catches the behavioral anomaly — "Why is the CFO logging in from Moldova at 2 AM?" — that signature-based rules miss entirely.

**How teams improve posture with it:** SOC analysts investigate high-fidelity behavioral anomalies correlated with attack frameworks. Risk-score trends reveal slowly-developing compromises. Behavioral watchlists for privileged users and sensitive assets catch credential theft before data exfiltration occurs. Insider threat detection becomes possible without spy-on-employees surveillance.

**DeepSight path:** Start simple — rolling z-score baselining. Track login count per user per hour, connection count per host per hour, DNS query count per host, data transfer volume. Compute mean + stddev over 7-day sliding window. Alert when current value exceeds mean + 3σ. Libraries: `numpy`/`scipy` + SQLite. ~12-16 hours effort. **Priority: MED-HIGH — big false-positive reduction, moderate effort.**

---

### 5. Real-Time Notifications & Alerting
**Coverage:** All 10 platforms (essential). **DeepSight:** Has zero notification delivery.

**What it is:** Configurable alert routing to Slack, Discord, email, PagerDuty, webhooks, SMS, and mobile push notifications. Includes severity-based routing rules (critical → PagerDuty + SMS; medium → Slack channel; low → dashboard only), alert deduplication windows, and quiet hours.

**Why it's there:** Alerts that nobody sees are worthless. SSH brute-forcing at 3 AM means nothing if you find out at 9 AM. This is the single biggest gap between "detection" and "defense" — detection without delivery is just logging with opinions.

**How teams improve posture with it:** Critical alerts reach responders within seconds regardless of time of day. On-call rotations receive only high-severity, high-confidence alerts. Medium alerts route to triage channels for next-business-day review. Alert fatigue is managed through routing rules rather than "just turn the volume down."

**DeepSight path:** Trivial. `apprise` library (one-liner to support Slack, Discord, Telegram, email, Pushover, Matrix, ntfy, Gotify, 80+ services). Severity-based routing rules in config. Scheduled quiet hours. ~2-3 hours effort. **Priority: HIGH — massive value, near-zero effort. Ship first.**

---

### 6. Advanced Search & Investigation Interface
**Coverage:** All 10 platforms. **DeepSight:** Has basic SQL API with no UI search.

**What it is:** A search interface with a query language (SPL, KQL, Lucene), field-level filtering, time range selection, result aggregation, saved searches, and pivot-from-alert-to-raw-logs drilldown. Converts "I think something happened" into "show me every outbound connection from this host to rare countries in the last 72 hours, grouped by destination port."

**Why it's there:** Alerts tell you something happened. Investigation tells you what, how, and whether there's more. Without search, analysts hunt blind through raw database tables. A proper search interface turns your existing data from a pile of records into an answer engine.

**How teams improve posture with it:** Analysts answer ad-hoc questions during incidents: "Has this IP touched any other host?" "Show all DNS queries for *.xyz domains from this subnet." Threat hunters build and save complex queries as reusable hunt templates. Incident responders pivot from a single alert to the full activity timeline of the affected host.

**DeepSight path:** FTS5 full-text search on alert descriptions in SQLite. Frontend: search bar with field autocomplete (`src_ip:`, `event_type:`, `severity:`), date range picker, sortable columns, result count, save queries. ~10-15 hours effort. **Priority: HIGH — makes existing data actionable.**

---

### 7. Dashboards & Security Visualization
**Coverage:** All 10 platforms. **DeepSight:** Has system-health gauges only; no security-specific visualizations.

**What it is:** Interactive dashboards rendering security data as attack timelines, top-talkers charts, alert volume trends, geographic IP maps, detection-coverage heat maps by MITRE technique, agent health status, and real-time SOC overview walls. Purpose-built for security operations, not system administration.

**Why it's there:** Humans process visual patterns far faster than raw logs and tables. A SOC manager glancing at a wall dashboard instantly knows alert volume, top attacking IPs, and whether detection coverage has gaps. Dashboards turn abstract telemetry into situational awareness.

**How teams improve posture with it:** SOC managers project Security Posture dashboards on NOC walls for real-time situational awareness. Analysts build custom views for specific investigation workflows. Executives receive trend-driven weekly summaries. Detection engineers visualize rule performance and false-positive rates over time.

**DeepSight path:** Add 4-6 security-focused Chart.js panels to existing dashboard: alert volume over time (bar), top source IPs (horizontal bar), alert severity pie, MITRE technique coverage (radar chart), agent health ring, geographic source-IP map. New API endpoints returning pre-computed aggregations, cached in SQLite. ~6-10 hours effort. **Priority: MED — low complexity, meaningful awareness improvement.**

---

### 8. Case Management & Incident Tracking
**Coverage:** 9 of 10 platforms. **DeepSight:** Has an `acknowledged` boolean flag. That's it.

**What it is:** Structured workflows for tracking security incidents from creation through triage, investigation, containment, and closure. Includes evidence collection, task assignment, collaboration notes, SLA timers, audit trails, and resolution documentation — all within the platform rather than scattered across Slack, spreadsheets, and mental notes.

**Why it's there:** Without case management, incidents live in analysts' heads, Slack threads, and spreadsheets. Structured case management ensures handoff continuity between shifts, measurable MTTR metrics, defensible audit records, and institutional memory about how past incidents were resolved.

**How teams improve posture with it:** Analysts open cases from alerts, attach evidence (logs, PCAP, screenshots), assign investigation tasks to team members, document findings step-by-step, and close with root cause analysis and remediation notes. Managers report on case volume, resolution time, and analyst performance. Repeat incidents are resolved faster because the playbook is documented.

**DeepSight path:** Add `cases` table with status enum (open/triaging/investigating/contained/closed), assigned analyst, notes (JSON array), evidence attachments, SLA timers, and timeline audit log. Linked from alerts via `case_id` FK. Simple frontend workflow: Create Case → Assign → Investigate → Resolve. ~12-16 hours effort. **Priority: MED — big operational maturity boost, moderate effort.**

---

### 9. SOAR Playbooks & Automated Response
**Coverage:** 9 of 10 platforms. **DeepSight:** Has zero automation.

**What it is:** Automated incident response workflows triggered on alert, on-schedule, or on-demand. Playbooks execute enrichment lookups, IP blocking (iptables/firewall API), host isolation, user account disablement, ticket creation, and notification routing — replacing the "analyst copy-pasting IOCs between consoles" workflow.

**Why it's there:** Alert-to-remediation time is the metric that matters. Without SOAR, even perfect detection leaves analysts manually executing the same 12 steps for every phishing alert. SOAR closes the detection-to-action gap and ensures consistent, auditable response regardless of which analyst (or no analyst) is on shift.

**How teams improve posture with it:** Tier 1 analysts run enrichment playbooks with one click. High-confidence alerts trigger fully automated response (auto-block confirmed C2 IPs at the firewall). Incident managers track response SLAs through playbook execution logs. MTTR drops by 60-90% for well-understood alert types.

**DeepSight path:** Start with automated enrichment (look up source IPs against threat intel on alert) and notification routing. Graduated to iptables block scripts for high-confidence C2 alerts (with opt-in only — "auto-block" is a dangerous default). Python `subprocess` + config-driven playbook YAML. **Priority: LOW for auto-response (dangerous in home lab), MED for auto-enrichment.** Start with enrichment-only playbooks.

---

### 10. Anomaly Detection Baselining & Statistical Alerting
**Coverage:** 8+ of 10 platforms (varies by implementation — dedicated ML vs. statistical rules). **DeepSight:** Uses static thresholds only.

**What it is:** Statistical analysis and machine learning that learns normal behavioral patterns from historical data, then generates alerts when current behavior deviates significantly — adaptive thresholds, outlier detection, trend analysis, seasonal pattern recognition. Replaces the "pick a number and hope it's right" approach to alert thresholds.

**Why it's there:** Static thresholds fail systematically. A server that normally has 2 SSH logins/day spiking to 50 is far more suspicious than a jump host with 200/day hitting 250. Without baselining, you get either alert fatigue (thresholds too low) or missed attacks (thresholds too high). There's no universal "right" threshold — only per-entity baselines.

**How teams improve posture with it:** Detection engineers tune rules against learned baselines rather than guessing. Alerts fire on deviation-from-normal rather than crossing arbitrary lines, slashing false positives. Slowly-developing compromises that stay under static thresholds get caught because the trend deviation triggers the alert. Seasonal patterns (month-end batch jobs, weekend maintenance) are learned rather than generating alerts every cycle.

**DeepSight path:** Rolling z-score for key metrics (SSH attempts per host, outbound connections, DNS queries). Mean + stddev over 7-day sliding window. Alert when current value exceeds mean + 3σ. Libraries: `numpy`/`scipy` for stats, SQLite for baseline storage. ~12-16 hours effort. Overlaps with UEBA (#4) — build as shared infrastructure. **Priority: MED-HIGH — big false-positive reduction.**

---

## Priority Roadmap

```
Phase 1 (Weekend Sprint) — HIGH ROI, LOW Effort
├── #5 Real-Time Notifications     (~3h)  ⚡ Ship first
├── #2 Syslog Ingestion            (~6h)  Network visibility
└── #3 Threat Intel Integration    (~12h) Alert quality multiplier

Phase 2 (Next 1-2 Weeks) — HIGH ROI, MEDIUM Effort
├── #6 Search & Investigation UI   (~15h) Data usability
├── #7 Security Dashboards         (~10h) Situational awareness
└── #4 UEBA / #10 Anomaly Detection (~16h shared infra)

Phase 3 (Month+) — MEDIUM-HIGH Effort
├── #1 Correlation Engine          (~20h) True SIEM capability
├── #8 Case Management             (~16h) Operational maturity
└── #9 SOAR (enrichment only)      (~12h) Automated context

Out of Scope for Home Lab
└── Compliance reporting, vulnerability scanner integration, Windows Event Log, full UEBA
```

---

## Key Insight

DeepSight already has solid detection primitives — reverse shell pattern matching, beaconing analysis, DGA entropy checks, file integrity — that many home-grown tools never reach. The gap isn't detection quality; it's **everything around detection**. Notifications, log sources, intel context, searchability, and correlation are what turn "this tool detects stuff" into "this tool improves my security posture." The Phase 1 items alone would transform DeepSight from a detection engine into a real SIEM.

---

*Research compiled from public documentation and product pages for Splunk Enterprise Security, Microsoft Sentinel, IBM QRadar, Elastic Security, Chronicle Security Operations, Sumo Logic Cloud SIEM, Exabeam Fusion, Securonix Unified Defense SIEM, LogRhythm SIEM, and CrowdStrike Falcon Next-Gen SIEM. May 2026.*
