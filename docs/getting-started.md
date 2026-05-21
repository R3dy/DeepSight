# Getting Started

> Install DeepSight on your collector host and deploy agents to every Linux machine you want to monitor.

## Prerequisites

- **Collector host**: Linux with Python 3.8+, `pip`, and systemd
- **Agent hosts**: Linux with Python 3 and systemd
- **Network**: Agents must be able to reach the collector over HTTPS (Tailscale recommended)

## Install the Collector

### 1. Clone and install dependencies

```bash
git clone https://github.com/R3dy/myclaw
cd apps/ram-dashboard
pip3 install flask psutil --break-system-packages
```

### 2. Start the server

```bash
python3 server.py
```

The dashboard listens on `127.0.0.1:8451` by default.

### 3. Expose with Tailscale (recommended)

Add a Tailscale Serve route for port 8451. The dashboard will be available at:

```
https://open-claw01.tail9058f7.ts.net:8451/
```

::: tip
Tailscale Serve provides automatic TLS certificates and restricts access to your tailnet. No need to configure nginx or Let's Encrypt.
:::

## Deploy Agents

On any Linux host you want to monitor:

```bash
curl -sSL https://<collector-url>:8451/install.sh | sudo bash
```

The installer:
1. Downloads the agent Python script
2. Installs `psutil` if available (falls back to `/proc` parsing)
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
    "collector_url": "https://open-claw01.tail9058f7.ts.net:8451",
    "secret": "sysdash-agent-key-2026",
    "host": "my-custom-hostname",
    "interval": 3
}
```

Restart the agent after changes:

```bash
systemctl restart sysdash-agent
```

### Remove an agent

```bash
sudo systemctl disable --now sysdash-agent
sudo rm -rf /opt/sysdash-agent /etc/systemd/system/sysdash-agent.service
```

## Security

- The collector and agent share a secret key for authentication
- Set `DASHBOARD_SECRET` environment variable on the collector to override the default
- Agents only report system metrics — no shell access, no file access
- All traffic goes over HTTPS when using Tailscale Serve

## Next Steps

- [Dashboard UI guide](/dashboard) — learn what every widget shows
- [API Reference](/api) — programmatic access to all data
- [Architecture](/architecture) — how the pieces fit together
