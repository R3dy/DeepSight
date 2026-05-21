# Security Monitoring

> Real-time threat detection — process auditing, C2 beaconing analysis, auth monitoring, DNS/DGA detection, and file integrity watching.

DeepSight's detection engine runs five background collectors that continuously analyze system activity for signs of compromise. Alerts are scored by severity, tagged with MITRE ATT&CK mappings, and surfaced in the Security dashboard view.

## Process Execution Auditing

The process audit collector polls `/proc` every 5 seconds to detect:

| Pattern | Severity | MITRE | Description |
|---------|----------|-------|-------------|
| Reverse shell | Critical | T1059 | `bash -i >& /dev/tcp/...`, Python socket one-liners, netcat listeners |
| Hidden cmdline | High | T1564 | Process with no visible command line — stealth malware |
| Process from /tmp | High | T1204 | Executables running from world-writable directories |
| Web server spawn | Critical | T1505 | Apache/nginx/httpd spawning bash/sh — webshell execution |
| Python one-liner | High | T1059 | `python -c` with socket/pty imports |
| Perl/Ruby shell | High | T1059 | Perl/Ruby one-liners with socket operations |

::: warning Process Audit Limitations
The collector runs without root privileges. It can detect process metadata but cannot intercept syscalls. For kernel-level auditing, deploy `auditd` alongside DeepSight.
:::

## C2 Beaconing Detection

Every 30 seconds, the beaconing collector analyzes the last 3 minutes of outbound HTTP connections for periodic patterns — the signature of command-and-control traffic.

**How it works:**
1. Monitors all ESTABLISHED TCP connections to external IPs (detected via `ss -tnp`)
2. Groups connections by (process, remote IP, remote port)
3. Calculates timing deltas between successive connections
4. Flags patterns where variance < 5% across 5+ samples, interval 10s–3600s
5. Confidence score = 1 − (variance / mean)

**Example alert:**
```
Confidence: 94% | Process: malware_implant (PID 12345)
Remote: 203.0.113.50:443 | Interval: 60.0s (±1.2s)
```
→ Alert: HIGH, MITRE T1071 (Application Layer Protocol: Web Protocols)

## Auth Monitoring

Parses `/var/log/auth.log` every 5 seconds for security-relevant events:

| Event | Threshold | Alert |
|-------|-----------|-------|
| SSH failure | >5 from same IP in 10s | Critical — Brute Force (T1110) |
| SSH success | Any | Logged (not alerted) |
| `sudo` execution | Any | Logged for audit trail |
| `su` to root | Any | Logged |
| `useradd`/`groupadd` | Any | High — Account Creation (T1136) |

Auth events appear in the Security dashboard with colored indicators: red for failures, green for successes, yellow for privilege escalation.

## DNS / DGA Detection

Monitors DNS resolution activity every 30 seconds (via `resolvectl statistics` and `/var/log/syslog`). Calculates **Shannon entropy** on resolved domain names to detect Domain Generation Algorithms (DGA) used by malware.

| Score | Meaning |
|-------|---------|
| < 2.5 | Normal domain (e.g., `github.com`) |
| 2.5–3.5 | Suspicious — long/random subdomain |
| 3.5–3.8 | Highly suspicious — likely DGA |
| > 3.8 | Almost certainly DGA (e.g., `xs8f2q9a.xyz`) |

::: tip Entropy Calculation
Shannon entropy measures randomness in the domain's character distribution. Legitimate domains have low entropy (repeated characters, common patterns). DGA domains have uniformly distributed characters — approaching the theoretical maximum of ~4.7 for lowercase alphanumeric.
:::

## File Integrity Monitoring

Watches critical system files for unauthorized modification using `inotify` (falls back to mtime polling if the kernel API is unavailable):

**Watched paths:**
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- `/root/.ssh/authorized_keys`
- `/etc/crontab`, `/var/spool/cron/crontabs/`
- `/tmp` and `/dev/shm` (for new executable files)

Any modification triggers an alert within 2 seconds.

::: warning Requires inotify
File monitoring requires the `inotify_simple` Python package. Install with:
```bash
pip install inotify_simple --break-system-packages
```
Without it, the collector gracefully degrades — other SIEM features continue working.
:::

## Alert Rules Reference

| Rule | Category | Severity | MITRE Tactic | MITRE Technique | Threshold |
|------|----------|----------|-------------|-----------------|-----------|
| SSH Brute Force | credential_access | Critical | Credential Access | T1110 (Brute Force) | >5 failures/10s |
| Reverse Shell | execution | Critical | Execution | T1059 (Command & Scripting) | Any match |
| Web Server Spawn | persistence | Critical | Persistence | T1505 (Server Software) | Any match |
| C2 Beaconing | command_and_control | High | C2 | T1071 (App Layer Protocol) | Confidence >0.7 |
| Hidden Cmdline | evasion | High | Defense Evasion | T1564 (Hide Artifacts) | Any match |
| Process from /tmp | execution | High | Execution | T1204 (User Execution) | Any match |
| DGA Domain | command_and_control | Medium | C2 | T1568 (Dynamic Resolution) | Entropy >3.8 |
| Sudoers Change | privilege_escalation | Critical | Priv Escalation | T1548 (Abuse Elevation) | Any modification |
| Authorized Keys Change | persistence | Critical | Persistence | T1098 (Account Manipulation) | Any modification |
| New User Creation | persistence | High | Persistence | T1136 (Create Account) | Any match |

Alerts are deduplicated — the same (category, source, title) won't re-alert within 5 minutes.

## Viewing Alerts

Click the **🛡️ Security** tab in the dashboard to see:
- Alert summary cards (critical/high/medium/low counts)
- Active alerts list with MITRE ATT&CK tags
- C2 beaconing detections with confidence scores
- Auth event timeline
- File integrity events

Acknowledge alerts by clicking the **Acknowledge** button — they fade out and are excluded from the active count.
