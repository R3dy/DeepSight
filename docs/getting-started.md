# Getting Started

> Get DeepSight running on your collector host in under a minute, then deploy agents to every Linux machine you want to monitor.

## Prerequisites

- **Collector host:** Linux with Python 3.8+, `pip`, and systemd
- **Agent hosts:** Linux with Python 3 and systemd
- **Network:** Agents must be able to reach the collector over HTTPS (Tailscale recommended, but any network path works)

## Quick Install

### 1. Clone and install dependencies

```bash
git clone https://github.com/R3dy/DeepSight.git
cd DeepSight
pip install flask psutil
```

::: tip Python environment
If your system uses externally-managed Python (PEP 668), add `--break-system-packages` or use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install flask psutil
```
:::

### 2. Start the server

```bash
python3 server.py
```

The dashboard is now running at `http://localhost:8451`.

### 3. Verify it works

Open your browser to `http://localhost:8451`. You should see the DeepSight dashboard with your local host's metrics already populating.

## Expose with Tailscale (Recommended)

Tailscale gives you automatic TLS certificates and restricts access to your tailnet — no nginx or Let's Encrypt configuration needed.

```bash
tailscale serve --bg 8451
```

Your dashboard will be available at:

```
https://your-server.your-tailnet.ts.net:8451/
```

Replace `your-server` with your Tailscale node name and `your-tailnet.ts.net` with your tailnet's MagicDNS suffix.

::: info No Tailscale?
You can also put DeepSight behind nginx or any reverse proxy. Just proxy to `127.0.0.1:8451` and configure TLS as you normally would. The dashboard itself has no opinion about how it's exposed.
:::

## Deploy Remote Agents

On any Linux host you want to monitor:

```bash
curl -sSL https://your-server.your-tailnet.ts.net:8451/install.sh | sudo bash
```

The installer:
1. Downloads the agent Python script
2. Installs `psutil` if available (falls back to `/proc` parsing otherwise)
3. Creates a `sysdash-agent` systemd service
4. Starts reporting immediately

### Verify the agent

```bash
systemctl status sysdash-agent
journalctl -u sysdash-agent -f
```

### Customize the agent

Edit `/opt/sysdash-agent/config.json`:

```json
{
    "collector_url": "https://your-server.your-tailnet.ts.net:8451",
    "secret": "sysdash-agent-key-2026",
    "host": "my-server-name",
    "interval": 3
}
```

| Field | Description |
|-------|-------------|
| `collector_url` | URL of your DeepSight collector |
| `secret` | Shared secret for authentication |
| `host` | Display name in the dashboard (defaults to hostname) |
| `interval` | Seconds between reports (default: 3) |

Restart the agent after changes:

```bash
sudo systemctl restart sysdash-agent
```

### Remove an agent

```bash
sudo systemctl disable --now sysdash-agent
sudo rm -rf /opt/sysdash-agent /etc/systemd/system/sysdash-agent.service
```

## Security Notes

- The collector and agent share a secret key for authentication
- Set the `DASHBOARD_SECRET` environment variable on the collector to override the default
- Agents only report system metrics — no shell access, no file access
- All traffic goes over HTTPS when using Tailscale Serve

## Enabling Security Monitoring

SIEM detection starts automatically — no configuration required. As soon as the collector is running, DeepSight begins:

- **Process auditing** — watching for reverse shells, webshells, and suspicious parent chains
- **C2 beaconing detection** — analyzing outbound HTTP patterns for periodic callbacks
- **Auth monitoring** — tracking SSH failures, sudo usage, and privilege escalations
- **DNS/DGA detection** — scoring domain entropy to catch malware C2
- **File integrity monitoring** — watching critical system paths for unauthorized changes

All alerts are stored in a local SQLite database (`alerts.db`) with 30-day retention. Open the **🛡️ Security** tab in the dashboard to view alerts and triage findings.

::: tip Detection is collector-side only
All SIEM analysis runs on the collector host. Remote agents continue to report standard system metrics — no additional agent overhead or configuration is required for security monitoring.
:::

## Troubleshooting

### Agent not appearing in the dashboard

```bash
# Check the agent is running
systemctl status sysdash-agent

# Check logs for connection errors
journalctl -u sysdash-agent -n 20

# Test connectivity from the agent host
curl -k https://your-server.your-tailnet.ts.net:8451/api/hosts
```

### Permission errors

The agent reads `/proc` and `/sys` files. If `psutil` isn't available, it falls back to pure `/proc` parsing — no root required for basic metrics. Process listing via `/proc` works without elevated privileges.

### Wrong hostname in the dashboard

Edit the `"host"` field in `/opt/sysdash-agent/config.json` and restart:

```bash
sudo systemctl restart sysdash-agent
```

### Dashboard shows nothing / blank page

Make sure your browser can reach the collector. If you're using Tailscale Serve, verify it's running:

```bash
tailscale serve status
```

If using a reverse proxy, check that it's forwarding to `127.0.0.1:8451`.

### Port already in use

If port 8451 is taken, you can change it by setting the `PORT` environment variable:

```bash
PORT=9000 python3 server.py
```

## Next Steps

- [Dashboard UI guide](/dashboard) — learn what every widget shows
- [Security Monitoring](/security) — understand threat detection rules
- [Remote Agents](/agents) — deeper agent config and lifecycle
- [API Reference](/api) — programmatic access to all data
- [Architecture](/architecture) — how the pieces fit together
