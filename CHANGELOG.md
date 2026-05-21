# Changelog

All notable changes to DeepSight will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-05-21

### Added
- UDP syslog ingestion server (`syslog_ingest.py`) on configurable port 514
- RFC 3164 (BSD) and RFC 5424 (IETF) syslog message parsing with auto-detection
- SQLite storage for syslog events with indexed host/facility/severity columns
- Security alert rules for incoming syslog: firewall DENY floods, device auth failures, NAS external logins, port scan detection
- External Logs widget in Security view with host/facility filter dropdowns and scrollable message feed
- `GET /api/syslog-events` and `GET /api/syslog-hosts` API endpoints with filtering
- Example config at `config/syslog.example.toml` with device configuration guides
- Syslog integration tests (27 new test cases)

## [0.2.0] — 2026-05-21

### Added
- Real-time alert notifications via apprise (Discord, Slack, Telegram, email, 80+ services)
- Severity-based alert routing (critical/high/medium/low → configurable channels)
- Configurable quiet hours to suppress notifications during off-hours
- Thread-safe background dispatch (non-blocking detection pipeline)
- Example notification config at `config/notifications.example.toml`
- Notification tests (9 new test cases)

## [0.1.0] — 2026-05-21

### Added
- Initial public release
- Real-time system monitoring dashboard (RAM, CPU, GPU, disk, network)
- Process forensic drill-down (cmdline, memory map, FDs, children, network connections)
- Multi-host agent deployment with single curl command
- SIEM detection engine: process audit, C2 beaconing, auth monitoring, DNS/DGA, file integrity
- 22 MITRE ATT&CK-mapped alert rules
- Dark-themed SPA frontend with Chart.js gauges
- VitePress documentation site
- AGENTS.md and LLMs.txt for AI coding agent context
- Social preview card and Open Graph meta tags

### Security
- SSH brute force detection (T1110)
- Reverse shell detection — 15+ patterns (T1059)
- Web shell detection — web server → shell spawning (T1505)
- C2 beaconing detection — interval variance analysis (T1071)
- DGA domain detection — Shannon entropy scoring (T1568)
- File integrity monitoring — inotify + polling fallback
- Hidden process and /tmp execution detection (T1564, T1204)

[0.1.0]: https://github.com/R3dy/DeepSight/releases/tag/v0.1.0
