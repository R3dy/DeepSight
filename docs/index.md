# DeepSight

> Real-time system monitoring, process forensics, and network visibility — across every host in your fleet.

DeepSight is a lightweight, self-hosted dashboard that gives you SIEM-like visibility into your servers. Monitor RAM, CPU, GPU, disk, and network usage in real time. Drill into individual processes with forensic detail. Track logged-in users and outbound HTTP connections. Deploy agents to remote Linux hosts with a single curl command.

<figure class="screenshot">
  <img src="/screenshots/detail-view.png" alt="DeepSight detail view" />
  <figcaption>DeepSight detail view — RAM gauge, tabbed process widget, CPU heatmap, network monitoring</figcaption>
</figure>

## Why DeepSight?

Most system monitors show you pretty graphs but stop there. DeepSight goes deeper:

- **Process forensics** — click any process to see its full command line, memory map (PSS/USS/RSS), open file descriptors, child processes, environment variables, and network connections
- **Multi-host** — deploy a lightweight Python agent to any Linux box and it reports back to your dashboard
- **Security visibility** — see logged-in users, their current activity, and outbound HTTP/HTTPS connections in real time
- **Zero dependencies on agents** — the agent works with just Python 3, no pip packages required
- **Dark, responsive UI** — built for production, looks great on desktop and mobile

## Quick Start

```bash
# On the collector host
git clone https://github.com/R3dy/myclaw
cd apps/ram-dashboard
python3 server.py
```

Then open `https://open-claw01.tail9058f7.ts.net:8451/` in your browser.

## Add a Remote Host

```bash
curl -sSL https://open-claw01.tail9058f7.ts.net:8451/install.sh | sudo bash
```

The agent installs as a systemd service and starts reporting immediately.

## What You'll See

| Widget | Data |
|--------|------|
| 🧠 Memory | User, Kernel, Cached, Buffers, Free breakdown with PSI pressure |
| ⚙️ CPU | Per-core utilization, freq, temp, context switches, load averages |
| 💾 Disk | Usage bars, I/O throughput, IOPS, inode usage per volume |
| 🎮 GPU | VRAM, utilization, temperature, clock speeds, power draw |
| 🔍 Processes | Tabbed RAM/CPU tables, sortable columns, click-to-forensics |
| 👤 Users | Logged-in sessions with activity and source IP |
| 🌐 Network | TCP listeners, outbound HTTP connections with reverse DNS |

<div class="screenshot-callout">
<strong>📸 Screenshots:</strong> To capture screenshots, open the dashboard in Chrome, right-click → Inspect → click the Device Toolbar icon (Ctrl+Shift+M), set to 1400×900, and use the "Capture screenshot" option in the three-dot menu. Save to <code>docs/public/screenshots/</code> and rebuild with <code>npm run docs:build</code>.
</div>
