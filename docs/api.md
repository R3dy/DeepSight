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

### GET `/install.sh`

Returns the agent install script with the collector URL and secret embedded.

### GET `/agent.py`

Returns the raw agent Python script.

### GET `/add-host`

Instruction page for adding a new host (HTML).
