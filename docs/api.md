# API Reference

> Programmatic access to all DeepSight data — use these endpoints to build integrations, alerts, or custom dashboards.

## Authentication

The agent report endpoint requires a shared secret. All other endpoints are unauthenticated (protected by Tailscale network-level access control).

## Endpoints

### GET `/api/stats`

Returns full system stats for a host.

**Query params:**
| Param | Default | Description |
|-------|---------|-------------|
| `host` | (collector) | Host to query |
| `detail` | `false` | Set to `true` for deep data (meminfo, pressure, PSS, disk I/O, GPU temp/clocks) |

**Response shape:**
```json
{
  "host": "your-server",
  "timestamp": 1778782773,
  "memory": { "total_gb": 7.5, "used_gb": 4.4, "hard_used_gb": 3.8, "kernel_reserved_gb": 0.6, ... },
  "swap": { "total_gb": 8.0, "used_gb": 0.1, ... },
  "cpu": { "percent": 12.5, "cores": [12.5, 8.3, ...], "freq_current": 2700000000, ... },
  "gpu": { "name": "Example GPU", "usage": 0, "vram_used_gb": 15.8, ... },
  "disks": [{ "mountpoint": "/", "used_gb": 398, "total_gb": 915, ... }],
  "ram_processes": [{ "pid": 2112747, "name": "example-process", "memory_gb": 0.5, ... }],
  "cpu_processes": [...]
}
```

### GET `/api/hosts`

Returns all known hosts and their status.

```json
{
  "current": "your-server",
  "hosts": {
    "your-server": { "last_seen": 1778782773, "status": "online" },
    "another-host": { "last_seen": 1778782770, "status": "online" }
  }
}
```

### GET `/api/cluster`

Returns full stats for all hosts plus cross-host process tables.

```json
{
  "hosts": {
    "your-server": { "memory": {...}, "cpu": {...}, "disks": [...], ... },
    "another-host": { "memory": {...}, "cpu": {...}, ... }
  },
  "cluster_top_ram": [{ "host": "your-server", "name": "firefox", "memory_gb": 1.2, ... }],
  "cluster_top_cpu": [...]
}
```

### GET `/api/summary`

Compact summary for all hosts (used by overview grid).

### POST `/api/report`

Agent endpoint — submit system stats from a remote host.

**Request body:**
```json
{
  "host": "my-server",
  "secret": "sysdash-agent-key-2026",
  "timestamp": 1778782773,
  "memory": { "total_gb": 16.0, "percent": 42.5, ... },
  "cpu": { "percent": 8.2, "cores": [...], ... },
  "disks": [...],
  "ram_processes": [...],
  "cpu_processes": [...]
}
```

### GET `/api/network`

Network connections and interface stats (cached 5s).

```json
{
  "summary": { "tcp_established": 22, "tcp_listen": 121, "udp_listeners": 64 },
  "tcp_connections": [{ "local_port": 443, "state": "LISTEN", "process": "nginx", "pid": 1234, ... }],
  "outbound_http": [{ "process": "firefox", "pid": 1029411, "url_hint": "https://api.example.com", ... }],
  "interfaces": [{ "name": "eth0", "rx_gb": 45.2, "tx_gb": 12.8, ... }],
  "dns": { "queries": 15234, "cache_size": 421 }
}
```

### GET `/api/process/{pid}`

Deep forensic detail for a single process (cached 3s).

```json
{
  "pid": 2112747,
  "name": "example-process",
  "user": "admin",
  "state": "S (sleeping)",
  "threads": 27,
  "cmdline": "my-app --config ...",
  "argv": ["my-app", "--config", "..."],
  "vm_rss_mb": 516.8,
  "vm_size_mb": 2048.0,
  "vm_data_mb": 320.5,
  "vm_stk_mb": 0.5,
  "vm_exe_mb": 32.1,
  "vm_lib_mb": 180.2,
  "vm_swap_mb": 0,
  "fd_count": 89,
  "fd_samples": [{"fd": "0", "target": "/dev/null"}, ...],
  "children": [2842287, 2844388],
  "child_count": 15,
  "network_connections": [{"proto": "tcp", "local": "0.0.0.0:18789", "state": "LISTEN"}, ...],
  "environ": {"PATH": "/usr/bin:...", "HOME": "/root", ...},
  "voluntary_ctxt_switches": 45231,
  "nonvoluntary_ctxt_switches": 8921,
  "cpu_user_s": 1250.3,
  "cpu_system_s": 340.8,
  "cpu_percent": 0.5
}
```

### GET `/api/users`

Logged-in users with session details.

```json
{
  "users": [
    {
      "name": "admin",
      "terminal": "ssh",
      "from_ip": "203.0.113.20",
      "idle": "0.00s",
      "what": "session: admin"
    }
  ]
}
```

## Security Endpoints

The SIEM engine exposes these endpoints for alerting, beaconing detection, auth monitoring, and file integrity.

### GET `/api/security-summary`

Compact overview of the current security posture across all hosts.

```json
{
  "alert_counts": {
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 12,
    "info": 3
  },
  "hosts_at_risk": ["db-server", "web-02"],
  "beaconing_count": 3,
  "active_brute_force": 1,
  "fim_events_24h": 7,
  "last_updated": 1778782773
}
```

### GET `/api/alerts`

Returns recent alerts with optional filtering.

**Query params:**
| Param | Default | Description |
|-------|---------|-------------|
| `host` | (all) | Filter by hostname |
| `severity` | (all) | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `acknowledged` | `false` | Include acknowledged alerts |
| `limit` | `50` | Max alerts to return |
| `since` | `24h` | Time window (e.g., `1h`, `24h`, `7d`) |

**Response:**
```json
{
  "alerts": [
    {
      "id": 142,
      "rule_id": "PRC-001",
      "rule_name": "Reverse shell detected",
      "severity": "critical",
      "host": "web-02",
      "timestamp": 1778782773,
      "acknowledged": false,
      "context": {
        "pid": 28421,
        "process": "bash",
        "parent": "nginx",
        "cmdline": "bash -i",
        "connection": "203.0.113.55:4444"
      }
    }
  ],
  "total": 142,
  "returned": 1
}
```

### GET `/api/alert-stats`

Aggregated alert statistics for dashboard charts.

```json
{
  "by_severity": [
    {"severity": "critical", "count": 2, "trend": "up"},
    {"severity": "high", "count": 5, "trend": "steady"},
    {"severity": "medium", "count": 8, "trend": "down"}
  ],
  "by_rule": [
    {"rule_id": "BCN-001", "count": 1},
    {"rule_id": "ATH-001", "count": 4}
  ],
  "by_host": [
    {"host": "web-02", "count": 12},
    {"host": "db-server", "count": 7}
  ],
  "timeline_24h": [
    {"hour": 0, "count": 3},
    {"hour": 1, "count": 1},
    ...
  ]
}
```

### POST `/api/alerts/acknowledge`

Acknowledge one or more alerts.

**Request body:**
```json
{
  "alert_ids": [142, 143],
  "note": "False positive — monitoring health check"
}
```

**Response:**
```json
{
  "acknowledged": 2,
  "status": "ok"
}
```

### GET `/api/beaconing`

C2 beaconing detection results with periodicity analysis.

**Response:**
```json
{
  "beacons": [
    {
      "host": "web-02",
      "process": "apache2",
      "pid": 1284,
      "destination": "203.0.113.99:443",
      "interval_s": 120,
      "periodicity_score": 92,
      "confidence": "high",
      "jitter_ms": 150,
      "first_seen": 1778778000,
      "last_seen": 1778782800,
      "bytes_sent": 45200
    }
  ],
  "analysis_window_s": 600,
  "total_beacons": 1
}
```

### GET `/api/auth-events`

Authentication events across all hosts.

**Query params:**
| Param | Default | Description |
|-------|---------|-------------|
| `host` | (all) | Filter by hostname |
| `type` | (all) | `ssh_failure`, `ssh_success`, `sudo`, `su` |
| `limit` | `50` | Max events to return |
| `since` | `1h` | Time window |

**Response:**
```json
{
  "events": [
    {
      "id": 891,
      "host": "web-02",
      "type": "ssh_failure",
      "timestamp": 1778782773,
      "user": "root",
      "source_ip": "45.33.32.156",
      "details": {
        "attempts": 12,
        "window_s": 300,
        "auth_method": "password"
      }
    },
    {
      "id": 892,
      "host": "open-claw01",
      "type": "sudo",
      "timestamp": 1778782700,
      "user": "royce",
      "target_user": "root",
      "command": "systemctl restart nginx"
    }
  ],
  "brute_force_active": [
    {"host": "web-02", "source_ip": "45.33.32.156", "attempts": 12}
  ]
}
```

### GET `/api/file-events`

File integrity monitoring events.

**Query params:**
| Param | Default | Description |
|-------|---------|-------------|
| `host` | (all) | Filter by hostname |
| `path` | (all) | Filter by file path (prefix match) |
| `type` | (all) | `created`, `modified`, `deleted`, `permission`, `owner` |
| `limit` | `50` | Max events to return |
| `since` | `24h` | Time window |

**Response:**
```json
{
  "events": [
    {
      "id": 42,
      "host": "web-02",
      "path": "/etc/sudoers",
      "type": "modified",
      "timestamp": 1778782773,
      "before_checksum": "a1b2c3d4...",
      "after_checksum": "e5f6g7h8...",
      "user": "root",
      "severity": "critical"
    },
    {
      "id": 43,
      "host": "db-server",
      "path": "/etc/cron.d/backup",
      "type": "created",
      "timestamp": 1778782000,
      "user": "root",
      "severity": "high"
    }
  ],
  "watched_paths": [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/etc/cron.d", "/etc/systemd/system",
    "~/.ssh/authorized_keys"
  ]
}
```

### GET `/install.sh`

Returns the agent install script with the collector URL and secret embedded.

### GET `/agent.py`

Returns the raw agent Python script.

### GET `/add-host`

Instruction page for adding a new host (HTML).
