# Changelog

All notable changes to DeepSight will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
