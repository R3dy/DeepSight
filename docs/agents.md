# Remote Agents

> Deploy lightweight monitoring agents to any Linux host with a single command.

## How Agents Work

1. The agent script (`agent.py`) collects system metrics locally using `psutil` (or `/proc` fallback)
2. It POSTs the data to the collector's `/api/report` endpoint every 2 seconds
3. The collector stores the latest report per host in memory
4. The dashboard UI shows each host in the dropdown selector

## Agent Data Collection

| Metric | Source | Fallback |
|--------|--------|----------|
| RAM | `psutil.virtual_memory()` | `/proc/meminfo` |
| CPU | `psutil.cpu_percent()` | `/proc/stat` delta calculation |
| Disk | `psutil.disk_usage()` | `os.statvfs()` |
| GPU | `/sys/class/drm/card*/device/` sysfs | — (agents report GPU if available) |
| Processes | `psutil.process_iter()` | `/proc/[pid]/statm` |
| Network | — | Network data only available on collector host |

## Installation

```bash
curl -sSL https://your-server.your-tailnet.ts.net:8451/install.sh | sudo bash
```

The install script is generated dynamically by the collector and includes the correct URL and shared secret.

### What the installer does

1. Creates `/opt/sysdash-agent/`
2. Downloads `agent.py` from the collector
3. Installs `psutil` if available
4. Writes `config.json` with collector URL, secret, hostname, and interval
5. Creates and enables a `sysdash-agent` systemd service
6. Starts the service immediately

## Configuration

Edit `/opt/sysdash-agent/config.json`:

```json
{
    "collector_url": "https://your-server.your-tailnet.ts.net:8451",
    "secret": "sysdash-agent-key-2026",
    "host": "my-server",
    "interval": 2
}
```

| Field | Description |
|-------|-------------|
| `collector_url` | URL of the DeepSight collector |
| `secret` | Shared secret for authentication |
| `host` | Display name in the dashboard (default: hostname) |
| `interval` | Seconds between reports (default: 2) |

## Command-line Overrides

```bash
python3 agent.py --host staging-box --collector https://192.168.1.100:8451 --secret my-key --interval 5
```

CLI arguments override `config.json` values.

## Managing Agents

```bash
# Stop reporting
sudo systemctl stop sysdash-agent

# Start reporting
sudo systemctl start sysdash-agent

# View logs
journalctl -u sysdash-agent -f

# Check status
systemctl status sysdash-agent
```

## Agent Lifecycle

- **Online**: Last report received within 15 seconds
- **Stale**: No report for 15+ seconds (shown dimmed in dropdown)
- **Pruned**: Removed from host list after 60 seconds without a report

Stopping the systemd service will mark the host as stale after 15 seconds, then prune it after 60.

## Troubleshooting

### Agent not appearing in dashboard

```bash
# Check agent is running
systemctl status sysdash-agent

# Check logs for connection errors
journalctl -u sysdash-agent -n 20

# Test connectivity from agent host
curl -k https://your-server.your-tailnet.ts.net:8451/api/hosts
```

### Permission errors

The agent reads `/proc` and `/sys` files. If `psutil` is unavailable, it falls back to pure `/proc` parsing — no root required for basic metrics. Process listing via `/proc` works without elevated privileges.

### Wrong hostname

Edit the `"host"` field in `/opt/sysdash-agent/config.json` and restart the agent:

```bash
sudo systemctl restart sysdash-agent
```
