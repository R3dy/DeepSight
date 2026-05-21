#!/usr/bin/env python3
"""
DeepSight Notification Engine — alert routing via apprise.

Supports 80+ services (Discord, Slack, Telegram, email, Pushover, ntfy,
Matrix, Gotify, and more) with severity-based routing and quiet hours.

Config: ~/.config/deepsight/notifications.toml (or NOTIFIER_CONFIG env var)
Test:   python3 notifier.py --test
"""

import os
import sys
import threading
from datetime import datetime, time as dt_time

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Python < 3.11 fallback

try:
    import apprise
    HAS_APPRISE = True
except ImportError:
    HAS_APPRISE = False

CONFIG_PATHS = [
    os.environ.get("NOTIFIER_CONFIG", ""),
    os.path.expanduser("~/.config/deepsight/notifications.toml"),
    "notifications.toml",
]

# Default to a 24h schedule (no quiet hours)
_quiet_start = dt_time(0, 0)
_quiet_end = dt_time(0, 0)
_quiet_enabled = False


def _log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[notifier {ts}] {msg}", flush=True)


def load_config(path=None):
    """Load notification config from TOML. Returns {channels: {}, routing: {}, quiet_hours: {}}."""
    paths_to_try = [path] if path else CONFIG_PATHS
    for p in paths_to_try:
        if p and os.path.exists(p):
            with open(p, "rb") as f:
                return tomllib.load(f)
    return {}


def _in_quiet_hours():
    """Check if current time falls within configured quiet hours."""
    if not _quiet_enabled:
        return False
    now = datetime.now().time()
    if _quiet_start <= _quiet_end:
        return _quiet_start <= now <= _quiet_end
    else:
        # Overnight window (e.g. 22:00–07:00)
        return now >= _quiet_start or now <= _quiet_end


def dispatch(alert, config=None):
    """
    Route an alert to configured notification channels based on severity.

    Args:
        alert: dict with keys: severity, title, category, description, mitre_technique, source_ip, process_name, timestamp
        config: dict from load_config() — uses cached config if None

    Returns:
        list of (service_name, success: bool)
    """
    global _quiet_enabled, _quiet_start, _quiet_end

    if not HAS_APPRISE:
        _log("apprise not installed — install with: pip install apprise")
        return []

    cfg = config or load_config()
    if not cfg:
        return []

    # Parse quiet hours
    qh = cfg.get("quiet_hours", {})
    if qh:
        start_str = qh.get("start", "00:00")
        end_str = qh.get("end", "00:00")
        if start_str != "00:00" or end_str != "00:00":
            _quiet_enabled = True
            _quiet_start = dt_time(*map(int, start_str.split(":")))
            _quiet_end = dt_time(*map(int, end_str.split(":")))

    severity = alert.get("severity", "low").lower()

    # Determine which channels to notify
    routing = cfg.get("routing", {})
    channels_to_notify = routing.get(severity, [])
    if not channels_to_notify:
        return []

    # Check quiet hours
    if _in_quiet_hours():
        _log(f"quiet hours active — suppressing {severity} alert: {alert.get('title', '')}")
        return []

    # Build apprise message
    title = f"[DeepSight] [{severity.upper()}] {alert.get('title', 'Untitled Alert')}"
    body_parts = []
    if alert.get("description"):
        body_parts.append(alert.get("description"))
    if alert.get("category"):
        body_parts.append(f"Category: {alert['category']}")
    if alert.get("mitre_technique"):
        body_parts.append(f"MITRE: {alert['mitre_technique']}")
    if alert.get("source_ip"):
        body_parts.append(f"Source IP: {alert['source_ip']}")
    if alert.get("process_name"):
        proc = alert['process_name']
        if alert.get("process_pid"):
            proc += f" (PID {alert['process_pid']})"
        body_parts.append(f"Process: {proc}")
    if alert.get("timestamp"):
        body_parts.append(f"Time: {alert['timestamp']}")

    body = "\n".join(body_parts)

    # Send to each configured channel
    results = []
    channels = cfg.get("channels", cfg)  # support flat config or nested

    for service_name in channels_to_notify:
        service_cfg = channels.get(service_name, {})
        webhook_url = service_cfg.get("webhook_url", "")
        if not webhook_url:
            _log(f"channel '{service_name}' has no webhook_url — skipping")
            results.append((service_name, False))
            continue

        apobj = apprise.Apprise()
        result = apobj.add(webhook_url)
        if not result:
            _log(f"apprise: invalid URL for '{service_name}' — skipping")
            results.append((service_name, False))
            continue

        try:
            apobj.notify(title=title, body=body)
            results.append((service_name, True))
        except Exception as e:
            _log(f"failed to notify '{service_name}': {e}")
            results.append((service_name, False))

    return results


def dispatch_alert(alert):
    """
    Thread-safe wrapper called from detection.create_alert().
    Runs in background thread to avoid blocking the detection pipeline.
    """
    if not alert or not HAS_APPRISE:
        return
    t = threading.Thread(
        target=dispatch, args=(alert,), name="notifier-dispatch", daemon=True
    )
    t.start()


def test_notifications(config=None):
    """Send a test notification to all configured channels. Returns results."""
    test_alert = {
        "severity": "critical",
        "title": "🔔 DeepSight Notification Test",
        "description": "This is a test notification from DeepSight. If you see this, alert routing is working correctly.",
        "category": "test",
        "mitre_technique": "N/A (Test)",
        "source_ip": "127.0.0.1",
        "process_name": "notifier.py",
        "timestamp": datetime.now().isoformat(),
    }
    return dispatch(test_alert, config)


# ── CLI ──
if __name__ == "__main__":
    if not HAS_APPRISE:
        print("apprise is not installed. Install with: pip install apprise")
        sys.exit(1)

    if "--test" in sys.argv:
        print("═══ DeepSight Notification Test ═══")
        config = load_config()
        if not config:
            print("No notification config found. Create one at:")
            print("  ~/.config/deepsight/notifications.toml")
            print("Or copy the example:")
            print("  cp config/notifications.example.toml ~/.config/deepsight/notifications.toml")
            sys.exit(1)

        results = test_notifications(config)
        for service, ok in results:
            status = "✅" if ok else "❌"
            print(f"  {status} {service}")
        if all(ok for _, ok in results):
            print("✅ All notifications sent successfully.")
        else:
            print("⚠️ Some notifications failed — check config and network.")
    else:
        print("Usage: python3 notifier.py --test")
