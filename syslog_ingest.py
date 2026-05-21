#!/usr/bin/env python3
"""
DeepSight Syslog Ingestion Engine — UDP syslog server for router, switch,
firewall, NAS, and other syslog-speaking devices.

Features:
- UDP listener on port 514 (configurable) via socketserver.UDPServer
- RFC 3164 and RFC 5424 message parsing
- SQLite storage in syslog_events table
- Security alert rule evaluation (firewall floods, auth failures, port scans)

Usage:
    python3 syslog_ingest.py          # run standalone on default port 514
    python3 syslog_ingest.py --port 1514  # custom port (no root needed)

Config: config/syslog.example.toml
"""

import os
import re
import sys
import json
import time
import struct
import socket
import sqlite3
import threading
import socketserver
from datetime import datetime, timezone

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # Python < 3.11 fallback

# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "syslog.db")

CONFIG_PATHS = [
    os.environ.get("SYSLOG_CONFIG", ""),
    os.path.expanduser("~/.config/deepsight/syslog.toml"),
    "syslog.toml",
]

DEFAULT_PORT = 514
DEFAULT_BIND = "0.0.0.0"

# Facility names per RFC 3164/5424
FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon",
    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "audit", 14: "alert", 15: "clock",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SEVERITY_NAMES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# Alert rule thresholds
FIREWALL_DENY_FLOOD_COUNT = 20      # DENY messages from single IP in window
FIREWALL_DENY_FLOOD_WINDOW = 60     # seconds
AUTH_FAIL_FLOOD_COUNT = 5           # auth failures from single host
AUTH_FAIL_FLOOD_WINDOW = 60         # seconds
RESET_FLOOD_COUNT = 15              # connection resets in window (port scan)
RESET_FLOOD_WINDOW = 60             # seconds


# ═══════════════════════════════════════════
# Database
# ═══════════════════════════════════════════

_db_conn = None
_db_lock = threading.Lock()


def get_db():
    """Return thread-safe SQLite connection (creates tables on first call)."""
    global _db_conn
    with _db_lock:
        if _db_conn is None:
            os.makedirs(DATA_DIR, exist_ok=True)
            _db_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            _db_conn.row_factory = sqlite3.Row
            _db_conn.execute("PRAGMA journal_mode=WAL")
            _db_conn.execute("PRAGMA synchronous=NORMAL")
            _db_conn.execute("PRAGMA busy_timeout=3000")
            _create_tables(_db_conn)
    return _db_conn


def _create_tables(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS syslog_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            host TEXT NOT NULL DEFAULT '',
            facility TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            raw TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_syslog_timestamp ON syslog_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_syslog_host ON syslog_events(host);
        CREATE INDEX IF NOT EXISTS idx_syslog_facility ON syslog_events(facility);
        CREATE INDEX IF NOT EXISTS idx_syslog_severity ON syslog_events(severity);
    """)


# ═══════════════════════════════════════════
# Config loading
# ═══════════════════════════════════════════

def load_config(path=None):
    """Load syslog config from TOML. Returns dict with port, bind, alert_rules keys."""
    paths_to_try = [path] if path else CONFIG_PATHS
    for p in paths_to_try:
        if p and os.path.exists(p):
            with open(p, "rb") as f:
                return tomllib.load(f)
    return {}


# ═══════════════════════════════════════════
# RFC 3164 Parsing (BSD syslog)
# ═══════════════════════════════════════════

# RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG
# PRI = facility * 8 + severity
# Example: <134>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8

_RFC3164_RE = re.compile(
    r'^<(\d{1,3})>'                           # PRI
    r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'  # timestamp (Mon DD HH:MM:SS)
    r'\s+(\S+)'                                 # hostname
    r'\s+(.*)$'                                 # message (tag + content)
)


def parse_rfc3164(raw):
    """Parse an RFC 3164 BSD syslog message. Returns dict or None."""
    m = _RFC3164_RE.match(raw.strip())
    if not m:
        return None

    pri = int(m.group(1))
    facility = pri // 8
    severity = pri % 8
    timestamp_str = m.group(2)
    hostname = m.group(3)
    message = m.group(4)

    # Try to convert timestamp
    try:
        parsed_year = datetime.now().year
        dt = datetime.strptime(f"{parsed_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
        # If parsed month > current month, it was from last year
        now = datetime.now()
        if dt > now:
            dt = dt.replace(year=parsed_year - 1)
        ts_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "timestamp": ts_iso,
        "host": hostname,
        "facility": FACILITY_NAMES.get(facility, f"unknown({facility})"),
        "severity": SEVERITY_NAMES.get(severity, f"unknown({severity})"),
        "message": message,
        "facility_code": facility,
        "severity_code": severity,
        "raw": raw.strip(),
    }


# ═══════════════════════════════════════════
# RFC 5424 Parsing (IETF syslog)
# ═══════════════════════════════════════════

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
# Example: <34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 iut="3"] 'su root' failed

_RFC5424_RE = re.compile(
    r'^<(\d{1,3})>'                     # PRI
    r'(\d{1,3})\s+'                     # VERSION
    r'(\S+)\s+'                         # TIMESTAMP
    r'(\S+)\s+'                         # HOSTNAME
    r'(\S+)\s+'                         # APP-NAME
    r'(\S+)\s+'                         # PROCID
    r'(\S+)\s+'                         # MSGID
    r'(\[[^\]]*\]|-)?\s*'              # STRUCTURED-DATA (optional, - = NIL)
    r'(.*)$'                            # MSG
)


def parse_rfc5424(raw):
    """Parse an RFC 5424 IETF syslog message. Returns dict or None."""
    m = _RFC5424_RE.match(raw.strip())
    if not m:
        return None

    pri = int(m.group(1))
    facility = pri // 8
    severity = pri % 8
    version = m.group(2)
    timestamp_str = m.group(3)
    hostname = m.group(4)
    app_name = m.group(5)
    procid = m.group(6)
    msgid = m.group(7)
    structured_data = m.group(8) or ""
    message = m.group(9) or ""

    # Normalize timestamp (strip trailing Z/offset, handle milliseconds)
    try:
        ts_clean = re.sub(r'(\d{2}:\d{2}:\d{2})\.\d+', r'\1', timestamp_str)
        if ts_clean.endswith('Z'):
            ts_clean = ts_clean[:-1]
        if '+' in ts_clean:
            ts_clean = ts_clean.rsplit('+', 1)[0]
        if '-' in ts_clean and ts_clean.index('-') > 4:
            ts_clean = ts_clean.rsplit('-', 1)[0]
        dt = datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S")
        ts_iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, IndexError):
        ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build readable message with app context
    full_message = message
    if app_name and app_name != "-":
        prefix = app_name
        if procid and procid != "-":
            prefix += f"[{procid}]"
        if msgid and msgid != "-":
            prefix += f" {msgid}"
        full_message = f"{prefix}: {message}" if message else prefix

    return {
        "timestamp": ts_iso,
        "host": hostname,
        "facility": FACILITY_NAMES.get(facility, f"unknown({facility})"),
        "severity": SEVERITY_NAMES.get(severity, f"unknown({severity})"),
        "message": full_message,
        "facility_code": facility,
        "severity_code": severity,
        "raw": raw.strip(),
    }


# ═══════════════════════════════════════════
# Message parser (auto-detect RFC)
# ═══════════════════════════════════════════

def parse_syslog(raw):
    """
    Auto-detect RFC 3164 vs 5424 and parse. Returns dict or None.
    Detection: RFC 5424 has "VERSION " immediately after PRI (e.g. <34>1 ...)
    """
    raw = raw.strip()
    if not raw or not raw.startswith("<"):
        return None

    # Check for RFC 5424: <PRI>VERSION ... (version always follows PRI)
    pri_match = re.match(r'^<(\d{1,3})>(\d+)\s', raw)
    if pri_match:
        version = pri_match.group(2)
        # Version 1 is RFC 5424; version > 0 strongly suggests 5424
        if version in ("1", "2", "3"):
            return parse_rfc5424(raw)

    return parse_rfc3164(raw)


# ═══════════════════════════════════════════
# UDP Syslog Server
# ═══════════════════════════════════════════

class SyslogHandler(socketserver.BaseRequestHandler):
    """Handle incoming UDP syslog packets."""

    def handle(self):
        data = self.request[0].strip()
        if not data:
            return

        try:
            raw = data.decode("utf-8", errors="replace")
        except Exception:
            return

        parsed = parse_syslog(raw)
        if parsed is None:
            return

        # Store in database
        try:
            conn = get_db()
            conn.execute("""
                INSERT INTO syslog_events (timestamp, host, facility, severity, message, raw)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (parsed["timestamp"], parsed["host"], parsed["facility"],
                  parsed["severity"], parsed["message"], parsed["raw"]))
            conn.commit()
        except Exception:
            pass  # Don't crash on DB errors

        # Notify alert engine if available
        try:
            _notify_alert_engine(parsed)
        except Exception:
            pass


# ═══════════════════════════════════════════
# Alert rule evaluation
# ═══════════════════════════════════════════

# Per-IP counters for flood detection (cleared periodically)
_source_ip_counter = {}
_source_ip_counter_lock = threading.Lock()
_counter_cleanup_ts = time.time()


def _notify_alert_engine(parsed):
    """Evaluate alert rules and notify detection engine if loaded."""
    global _source_ip_counter, _counter_cleanup_ts

    message = parsed["message"]
    host = parsed["host"]
    facility = parsed["facility"]

    # Clean up old counters periodically
    now = time.time()
    if now - _counter_cleanup_ts > 120:
        with _source_ip_counter_lock:
            cutoff = now - max(FIREWALL_DENY_FLOOD_WINDOW, AUTH_FAIL_FLOOD_WINDOW, RESET_FLOOD_WINDOW)
            _source_ip_counter = {
                k: v for k, v in _source_ip_counter.items()
                if any(c.get("last", 0) > cutoff for c in v.values())
            }
            _counter_cleanup_ts = now

    severity_code = parsed.get("severity_code", 6)

    # Rule 1: Firewall ACL DENY flood (high volume from single source IP)
    if severity_code <= 4 and ("deny" in message.lower() or "blocked" in message.lower()
                               or "DROP" in message or "REJECT" in message
                               or "ACL" in message.upper()):
        ip_match = re.search(r'SRC[= ](\d+\.\d+\.\d+\.\d+)', message, re.IGNORECASE)
        if not ip_match:
            ip_match = re.search(r'src[= ](\d+\.\d+\.\d+\.\d+)', message, re.IGNORECASE)
        if not ip_match:
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message, re.IGNORECASE)
        if not ip_match:
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)

        if ip_match:
            src_ip = ip_match.group(1)
            # Skip private IPs for this check (internal traffic is expected)
            if not _is_private_ip(src_ip):
                with _source_ip_counter_lock:
                    key = f"deny:{host}"
                    entry = _source_ip_counter.setdefault(key, {})
                    ip_entry = entry.setdefault(src_ip, {"count": 0, "last": now})
                    ip_entry["count"] += 1
                    ip_entry["last"] = now

                    # Check threshold
                    recent_count = sum(
                        1 for v in entry.values()
                        if now - v["last"] < FIREWALL_DENY_FLOOD_WINDOW
                    )
                    if recent_count >= FIREWALL_DENY_FLOOD_COUNT:
                        _try_create_syslog_alert(
                            severity="high",
                            category="firewall_flood",
                            title=f"Firewall DENY flood: {recent_count} blocked from {src_ip}",
                            description=f"Firewall {host} has blocked {recent_count} packets from {src_ip} in {FIREWALL_DENY_FLOOD_WINDOW}s. Possible port scan or brute force.",
                            source_ip=src_ip,
                            mitre_tactic="Discovery",
                            mitre_technique="T1046 (Network Service Discovery)",
                            raw_data={"host": host, "count": recent_count, "window_s": FIREWALL_DENY_FLOOD_WINDOW},
                        )
                        entry.clear()  # Reset to avoid repeat alerts

    # Rule 2: Auth failure on network device (router/switch)
    auth_patterns = [
        (r'[Ll]ogin\s+(failed|incorrect|invalid)', "login failure"),
        (r'[Aa]uthentication\s+(failed|failure|rejected)', "authentication failure"),
        (r'[Ff]ailed\s+password', "failed password"),
        (r'[Uu]nauthorized\s+access', "unauthorized access"),
        (r'[Ss]SH.*[Ff]ail', "SSH failure"),
    ]

    is_auth_fail = False
    fail_reason = ""
    for pattern, reason in auth_patterns:
        if re.search(pattern, message):
            is_auth_fail = True
            fail_reason = reason
            break

    if is_auth_fail:
        with _source_ip_counter_lock:
            key = f"authfail:{host}"
            entry = _source_ip_counter.setdefault(key, {"count": 0, "last": now})
            entry["count"] += 1
            entry["last"] = now

            recent = sum(
                1 for v in _source_ip_counter.get(key, {}).values()
                if isinstance(v, dict) and now - v.get("last", 0) < AUTH_FAIL_FLOOD_WINDOW
            )
            # Also count the top-level counter
            total_in_window = recent + (1 if now - entry.get("last", 0) < AUTH_FAIL_FLOOD_WINDOW else 0)
            if total_in_window < AUTH_FAIL_FLOOD_WINDOW:
                total_in_window = max(entry.get("count", 0), 1)

            if total_in_window >= AUTH_FAIL_FLOOD_COUNT:
                _try_create_syslog_alert(
                    severity="high",
                    category="device_auth_fail",
                    title=f"Auth failure flood on {host}: {total_in_window} failures",
                    description=f"Network device {host} has {total_in_window} authentication failures ({fail_reason}) in {AUTH_FAIL_FLOOD_WINDOW}s. Possible brute force against network infrastructure.",
                    source_ip=host,
                    mitre_tactic="Credential Access",
                    mitre_technique="T1110 (Brute Force)",
                    raw_data={"host": host, "count": total_in_window, "reason": fail_reason},
                )
                entry["count"] = 0  # Reset

    # Rule 3: NAS login from unusual external IP
    if facility in ("auth", "authpriv") and \
       ("login" in message.lower() or "session opened" in message.lower() or
        "connection from" in message.lower()):
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
        if ip_match:
            src_ip = ip_match.group(1)
            if not _is_private_ip(src_ip) and not src_ip.startswith("127."):
                _try_create_syslog_alert(
                    severity="medium",
                    category="nas_external_login",
                    title=f"NAS login from external IP: {src_ip}",
                    description=f"Device {host} accepted a login from external IP {src_ip}. Verify this is authorized.",
                    source_ip=src_ip,
                    mitre_tactic="Initial Access",
                    mitre_technique="T1078 (Valid Accounts)",
                    raw_data={"host": host, "source_ip": src_ip, "message": message[:200]},
                )

    # Rule 4: Repeated connection resets (port scan indication)
    reset_patterns = [
        r'[Cc]onnection\s+reset',
        r'[Rr]eset\s+by\s+peer',
        r'RST\b',
        r'[Rr]ST\s+packet',
        r'TCP\s+RST',
    ]

    is_reset = any(re.search(p, message) for p in reset_patterns)
    if is_reset:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
        if ip_match:
            src_ip = ip_match.group(1)
            if not _is_private_ip(src_ip):
                with _source_ip_counter_lock:
                    key = f"reset:{host}"
                    entry = _source_ip_counter.setdefault(key, {})
                    ip_entry = entry.setdefault(src_ip, {"count": 0, "last": now})
                    ip_entry["count"] += 1
                    ip_entry["last"] = now

                    recent_count = sum(
                        1 for v in entry.values()
                        if now - v["last"] < RESET_FLOOD_WINDOW
                    )
                    if recent_count >= RESET_FLOOD_COUNT:
                        _try_create_syslog_alert(
                            severity="medium",
                            category="port_scan",
                            title=f"Possible port scan: {recent_count} connection resets from {src_ip}",
                            description=f"Firewall {host} has seen {recent_count} connection resets from {src_ip} in {RESET_FLOOD_WINDOW}s. Consistent with port scanning activity.",
                            source_ip=src_ip,
                            mitre_tactic="Discovery",
                            mitre_technique="T1046 (Network Service Discovery)",
                            raw_data={"host": host, "count": recent_count, "window_s": RESET_FLOOD_WINDOW},
                        )
                        entry.clear()


def _is_private_ip(ip):
    """Check if an IP is in a private range."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return True  # Fail-safe: treat non-IPv4 as private
        octets = [int(p) for p in parts]
        if octets[0] == 10:
            return True
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        if octets[0] == 192 and octets[1] == 168:
            return True
        if octets[0] == 127:
            return True
        return False
    except (ValueError, IndexError):
        return True  # Fail safe — treat malformed as private


def _try_create_syslog_alert(severity, category, title, description, source_ip,
                             mitre_tactic, mitre_technique, raw_data=None):
    """Try to create an alert via detection.py if it's loaded."""
    try:
        from detection import create_alert
        create_alert(
            severity=severity,
            category=category,
            title=title,
            description=description,
            source_ip=source_ip,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            raw_data=raw_data,
        )
    except ImportError:
        pass


# ═══════════════════════════════════════════
# Server lifecycle
# ═══════════════════════════════════════════

_server = None
_server_thread = None
_server_running = False


def start_server(port=None, bind=None):
    """Start the UDP syslog server in a daemon thread."""
    global _server, _server_thread, _server_running

    if _server_running:
        _log("Syslog server already running, skipping")
        return

    config = load_config()
    port = port or config.get("server", {}).get("port", DEFAULT_PORT)
    bind = bind or config.get("server", {}).get("bind", DEFAULT_BIND)

    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        get_db()  # Ensure tables exist
        _server = socketserver.UDPServer((bind, port), SyslogHandler)
        _server_thread = threading.Thread(
            target=_server.serve_forever,
            name="syslog-udp-server",
            daemon=True,
        )
        _server_thread.start()
        _server_running = True
        _log(f"Syslog server listening on UDP {bind}:{port}")
    except PermissionError:
        _log(f"Permission denied binding to port {port}. Try a port >= 1024 or run as root.")
        _server_running = False
    except OSError as e:
        _log(f"Cannot bind to {bind}:{port}: {e}")
        _server_running = False


def stop_server():
    """Stop the UDP syslog server."""
    global _server, _server_running
    if _server:
        _server.shutdown()
        _server.server_close()
        _server = None
    _server_running = False
    _log("Syslog server stopped")


def is_running():
    """Check if syslog server is running."""
    return _server_running


# ═══════════════════════════════════════════
# Query helpers (used by API)
# ═══════════════════════════════════════════

def get_events(host=None, facility=None, limit=100):
    """Query syslog events from the database with optional filters."""
    conn = get_db()
    query = "SELECT * FROM syslog_events WHERE 1=1"
    params = []

    if host:
        query += " AND host LIKE ?"
        params.append(f"%{host}%")
    if facility:
        query += " AND facility = ?"
        params.append(facility)

    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_distinct_hosts():
    """Return list of distinct hosts that have sent syslog messages."""
    conn = get_db()
    rows = conn.execute(
        "SELECT DISTINCT host FROM syslog_events ORDER BY host"
    ).fetchall()
    return [r["host"] for r in rows]


def get_distinct_facilities():
    """Return list of distinct facilities in the database."""
    conn = get_db()
    rows = conn.execute(
        "SELECT DISTINCT facility FROM syslog_events ORDER BY facility"
    ).fetchall()
    return [r["facility"] for r in rows]


def get_event_count(hours=1):
    """Return event count in the last N hours."""
    conn = get_db()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM syslog_events "
        "WHERE timestamp >= datetime('now', ?)",
        (f"-{hours} hours",)
    ).fetchone()
    return row["cnt"] if row else 0


def prune_old_events(max_age_hours=168):
    """Delete syslog events older than max_age_hours (default 7 days)."""
    conn = get_db()
    conn.execute(
        "DELETE FROM syslog_events WHERE timestamp < datetime('now', ?)",
        (f"-{max_age_hours} hours",)
    )
    conn.commit()


# ═══════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════

def _log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[syslog {ts}] {msg}", flush=True)


# ═══════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DeepSight Syslog Ingestion Engine"
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help=f"UDP port to listen on (default: {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--bind", type=str, default=None,
        help=f"IP to bind to (default: {DEFAULT_BIND})"
    )
    args = parser.parse_args()

    print("═══ DeepSight Syslog Ingestion Engine ═══")
    print(f"Database: {DB_PATH}")

    start_server(port=args.port, bind=args.bind)

    if _server_running:
        print("Syslog server is running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            stop_server()
    else:
        print("Server failed to start. Check permissions or port availability.")
        sys.exit(1)
