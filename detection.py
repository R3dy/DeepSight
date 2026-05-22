#!/usr/bin/env python3
"""
DeepSight SIEM Detection Engine — integrated with the System Dashboard.
Background collectors + alert rules engine + SQLite event store.

Runs as non-root with graceful degradation when privileges are missing.
"""

import json
import os
import re
import time
import math
import glob
import threading
import socket
import sqlite3
import subprocess
from collections import defaultdict
from datetime import datetime, timezone, timedelta

# ── Optional notifier integration ──
try:
    from notifier import dispatch_alert as _dispatch_notification
except ImportError:
    def _dispatch_notification(alert):
        pass  # notifier.py not available

# ── Optional syslog integration ──
try:
    import syslog_ingest
    HAS_SYSLOG = True
except ImportError:
    HAS_SYSLOG = False

# ── Optional threat intel integration ──
try:
    import threat_intel
    HAS_THREAT_INTEL = True
except ImportError:
    HAS_THREAT_INTEL = False

# ── Optional imports ──
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from inotify_simple import INotify, flags as in_flags
    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False

# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "alerts.db")

# Collector intervals (seconds)
INTERVAL_PROCESS_AUDIT = 5
INTERVAL_BEACONING = 30
INTERVAL_AUTH_MONITOR = 5
INTERVAL_DNS = 30

# Thresholds
SSH_BRUTE_FORCE_COUNT = 5          # failed attempts in window
SSH_BRUTE_FORCE_WINDOW_S = 10      # seconds
BEACONING_CONFIDENCE_MIN = 0.7
BEACONING_MIN_SAMPLES = 5
BEACONING_WINDOW_S = 180            # lookback for connections
BEACONING_VARIANCE_MAX = 0.05       # 5% drift = beacon-like
DGA_ENTROPY_THRESHOLD = 3.5
DGA_ALERT_THRESHOLD = 3.8
ALERT_DEDUP_WINDOW_S = 300          # 5 minutes

# Files to watch for integrity
SENSITIVE_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh/authorized_keys",
    "/etc/crontab",
    "/var/spool/cron/crontabs/",
]

# Web server user names
WEB_SERVER_USERS = {"www-data", "apache", "nginx", "httpd", "lighttpd", "caddy"}

# Reverse-shell patterns
REVERSE_SHELL_PATTERNS = [
    # bash -i >& /dev/tcp/ip/port 0>&1
    (r"bash.*-i.*>&\s*/dev/tcp/", "bash reverse shell (interactive + /dev/tcp)"),
    # /bin/bash -i  
    (r"bash\s+-i\s+.*/dev/tcp/", "bash reverse shell"),
    # bash >& /dev/tcp/ip/port
    (r"bash\s+.*>&\s*/dev/tcp/", "bash reverse shell (/dev/tcp redirect)"),
    # python -c '...socket...'
    (r"python.*socket\.(connect|send|recv)", "python reverse shell"),
    (r"python.*subprocess.*/dev/tcp", "python reverse shell (subprocess)"),
    (r"python.*os\.dup2.*socket", "python reverse shell (dup2)"),
    # perl -e '...socket...'
    (r"perl.*-e.*socket.*connect", "perl reverse shell"),
    # ruby -e '...socket...'
    (r"ruby.*-e.*TCPSocket", "ruby reverse shell"),
    # netcat / ncat reverse shells
    (r"nc\s+.*-e\s+/bin/(sh|bash)", "netcat reverse shell (-e)"),
    (r"ncat\s+.*-e\s+/bin/(sh|bash)", "ncat reverse shell (-e)"),
    # mkfifo reverse shell
    (r"mkfifo.*nc\s", "netcat FIFO reverse shell"),
    # php reverse shell
    (r"php.*fsockopen", "php reverse shell (fsockopen)"),
]

# DGA / DNS tool patterns
DGA_TOOL_PATTERNS = [
    r"dnscat2?", r"iodine", r"dns2tcp", r"dnsteal",
]

# ═══════════════════════════════════════════
# Database
# ═══════════════════════════════════════════

_db_conn = None
_db_lock = threading.Lock()

# ── Packet-sniff metadata cache: (src_port) → {method, path, query, sni, ua, ts} ──
_http_metadata = {}
_http_metadata_lock = threading.Lock()
_HTTP_METADATA_TTL = 60  # seconds before stale entries are pruned


def get_db():
    """Return a thread-safe SQLite connection (WAL mode, auto-create)."""
    global _db_conn
    if _db_conn is None:
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
    """Create all detection tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            source_host TEXT DEFAULT '',
            source_ip TEXT DEFAULT '',
            mitre_tactic TEXT DEFAULT '',
            mitre_technique TEXT DEFAULT '',
            process_pid INTEGER,
            process_name TEXT DEFAULT '',
            raw_data TEXT DEFAULT '{}',
            acknowledged INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            event_type TEXT NOT NULL CHECK(event_type IN (
                'ssh_fail','ssh_success','sudo','su','useradd','groupadd','passwd'
            )),
            username TEXT DEFAULT '',
            source_ip TEXT DEFAULT '',
            details TEXT DEFAULT '',
            count_window_10s INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS beaconing_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            process_name TEXT NOT NULL DEFAULT '',
            pid INTEGER,
            remote_ip TEXT NOT NULL DEFAULT '',
            remote_host TEXT DEFAULT '',
            remote_port INTEGER,
            src_port INTEGER DEFAULT 0,
            interval_seconds REAL DEFAULT 0,
            confidence REAL DEFAULT 0 CHECK(confidence >= 0 AND confidence <= 1),
            sample_count INTEGER DEFAULT 0,
            http_method TEXT DEFAULT '',
            http_path TEXT DEFAULT '',
            http_query TEXT DEFAULT '',
            tls_sni TEXT DEFAULT '',
            user_agent TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            event_type TEXT NOT NULL CHECK(event_type IN ('created','modified','deleted')),
            path TEXT NOT NULL DEFAULT '',
            process_name TEXT DEFAULT '',
            process_pid INTEGER
        );

        CREATE TABLE IF NOT EXISTS dns_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            domain TEXT NOT NULL DEFAULT '',
            process_name TEXT DEFAULT '',
            pid INTEGER,
            entropy_score REAL DEFAULT 0 CHECK(entropy_score >= 0 AND entropy_score <= 1),
            is_dga INTEGER DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
        CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_auth_events_type ON auth_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_beaconing_timestamp ON beaconing_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_file_events_timestamp ON file_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_dns_events_timestamp ON dns_events(timestamp);

        -- FTS5 virtual tables for full-text search
        CREATE VIRTUAL TABLE IF NOT EXISTS alerts_fts USING fts5(
            title, description, content='alerts', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS auth_events_fts USING fts5(
            username, source_ip, details, content='auth_events', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS file_events_fts USING fts5(
            path, content='file_events', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS beaconing_fts USING fts5(
            process_name, remote_ip, remote_host, http_path, tls_sni, user_agent,
            content='beaconing_events', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS dns_events_fts USING fts5(
            domain, content='dns_events', content_rowid='id'
        );
    """)
    # ── FTS5 sync triggers — keep indexes in sync with source tables ──
    _create_fts_triggers(conn)

    # ── Schema migrations for new columns ──
    _migrate_beaconing_schema(conn)
    conn.commit()


def _migrate_beaconing_schema(conn):
    """Add new columns to beaconing_events if they don't exist (safe migration)."""
    new_cols = [
        ("src_port", "INTEGER DEFAULT 0"),
        ("http_method", "TEXT DEFAULT ''"),
        ("http_path", "TEXT DEFAULT ''"),
        ("http_query", "TEXT DEFAULT ''"),
        ("tls_sni", "TEXT DEFAULT ''"),
        ("user_agent", "TEXT DEFAULT ''"),
    ]
    existing = {row[1] for row in conn.execute("PRAGMA table_info(beaconing_events)")}
    for col_name, col_def in new_cols:
        if col_name not in existing:
            conn.execute(f"ALTER TABLE beaconing_events ADD COLUMN {col_name} {col_def}")


def _create_fts_triggers(conn):
    """Create INSERT/UPDATE/DELETE triggers so FTS5 indexes stay in sync."""
    # alerts_fts (columns: title, description)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS alerts_fts_ai AFTER INSERT ON alerts BEGIN
            INSERT INTO alerts_fts(rowid, title, description)
            VALUES (new.id, new.title, new.description);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS alerts_fts_ad AFTER DELETE ON alerts BEGIN
            INSERT INTO alerts_fts(alerts_fts, rowid, title, description)
            VALUES ('delete', old.id, old.title, old.description);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS alerts_fts_au AFTER UPDATE ON alerts BEGIN
            INSERT INTO alerts_fts(alerts_fts, rowid, title, description)
            VALUES ('delete', old.id, old.title, old.description);
            INSERT INTO alerts_fts(rowid, title, description)
            VALUES (new.id, new.title, new.description);
        END
    """)

    # auth_events_fts (columns: username, source_ip, details)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS auth_events_fts_ai AFTER INSERT ON auth_events BEGIN
            INSERT INTO auth_events_fts(rowid, username, source_ip, details)
            VALUES (new.id, new.username, new.source_ip, new.details);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS auth_events_fts_ad AFTER DELETE ON auth_events BEGIN
            INSERT INTO auth_events_fts(auth_events_fts, rowid, username, source_ip, details)
            VALUES ('delete', old.id, old.username, old.source_ip, old.details);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS auth_events_fts_au AFTER UPDATE ON auth_events BEGIN
            INSERT INTO auth_events_fts(auth_events_fts, rowid, username, source_ip, details)
            VALUES ('delete', old.id, old.username, old.source_ip, old.details);
            INSERT INTO auth_events_fts(rowid, username, source_ip, details)
            VALUES (new.id, new.username, new.source_ip, new.details);
        END
    """)

    # file_events_fts (columns: path)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS file_events_fts_ai AFTER INSERT ON file_events BEGIN
            INSERT INTO file_events_fts(rowid, path)
            VALUES (new.id, new.path);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS file_events_fts_ad AFTER DELETE ON file_events BEGIN
            INSERT INTO file_events_fts(file_events_fts, rowid, path)
            VALUES ('delete', old.id, old.path);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS file_events_fts_au AFTER UPDATE ON file_events BEGIN
            INSERT INTO file_events_fts(file_events_fts, rowid, path)
            VALUES ('delete', old.id, old.path);
            INSERT INTO file_events_fts(rowid, path)
            VALUES (new.id, new.path);
        END
    """)

    # beaconing_fts (columns: process_name, remote_ip, remote_host, http_path, tls_sni, user_agent)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS beaconing_fts_ai AFTER INSERT ON beaconing_events BEGIN
            INSERT INTO beaconing_fts(rowid, process_name, remote_ip, remote_host,
                                     http_path, tls_sni, user_agent)
            VALUES (new.id, new.process_name, new.remote_ip, new.remote_host,
                    new.http_path, new.tls_sni, new.user_agent);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS beaconing_fts_ad AFTER DELETE ON beaconing_events BEGIN
            INSERT INTO beaconing_fts(beaconing_fts, rowid, process_name, remote_ip,
                                     remote_host, http_path, tls_sni, user_agent)
            VALUES ('delete', old.id, old.process_name, old.remote_ip, old.remote_host,
                    old.http_path, old.tls_sni, old.user_agent);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS beaconing_fts_au AFTER UPDATE ON beaconing_events BEGIN
            INSERT INTO beaconing_fts(beaconing_fts, rowid, process_name, remote_ip,
                                     remote_host, http_path, tls_sni, user_agent)
            VALUES ('delete', old.id, old.process_name, old.remote_ip, old.remote_host,
                    old.http_path, old.tls_sni, old.user_agent);
            INSERT INTO beaconing_fts(rowid, process_name, remote_ip, remote_host,
                                     http_path, tls_sni, user_agent)
            VALUES (new.id, new.process_name, new.remote_ip, new.remote_host,
                    new.http_path, new.tls_sni, new.user_agent);
        END
    """)

    # dns_events_fts (columns: domain)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS dns_events_fts_ai AFTER INSERT ON dns_events BEGIN
            INSERT INTO dns_events_fts(rowid, domain)
            VALUES (new.id, new.domain);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS dns_events_fts_ad AFTER DELETE ON dns_events BEGIN
            INSERT INTO dns_events_fts(dns_events_fts, rowid, domain)
            VALUES ('delete', old.id, old.domain);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS dns_events_fts_au AFTER UPDATE ON dns_events BEGIN
            INSERT INTO dns_events_fts(dns_events_fts, rowid, domain)
            VALUES ('delete', old.id, old.domain);
            INSERT INTO dns_events_fts(rowid, domain)
            VALUES (new.id, new.domain);
        END
    """)


def rebuild_fts_indexes():
    """Rebuild all FTS5 indexes from existing data. Called on startup."""
    _log("Rebuilding FTS5 full-text search indexes...")
    conn = get_db()
    try:
        # alerts_fts
        conn.execute("INSERT INTO alerts_fts(alerts_fts) VALUES('rebuild')")
        _log("  alerts_fts: rebuilt")
    except Exception as e:
        _log(f"  alerts_fts rebuild: {e}")
    try:
        # auth_events_fts
        conn.execute("INSERT INTO auth_events_fts(auth_events_fts) VALUES('rebuild')")
        _log("  auth_events_fts: rebuilt")
    except Exception as e:
        _log(f"  auth_events_fts rebuild: {e}")
    try:
        # file_events_fts
        conn.execute("INSERT INTO file_events_fts(file_events_fts) VALUES('rebuild')")
        _log("  file_events_fts: rebuilt")
    except Exception as e:
        _log(f"  file_events_fts rebuild: {e}")
    try:
        # beaconing_fts
        conn.execute("INSERT INTO beaconing_fts(beaconing_fts) VALUES('rebuild')")
        _log("  beaconing_fts: rebuilt")
    except Exception as e:
        _log(f"  beaconing_fts rebuild: {e}")
    try:
        # dns_events_fts
        conn.execute("INSERT INTO dns_events_fts(dns_events_fts) VALUES('rebuild')")
        _log("  dns_events_fts: rebuilt")
    except Exception as e:
        _log(f"  dns_events_fts rebuild: {e}")
    conn.commit()
    _log("FTS5 indexes rebuilt successfully")


def search_events(query_str, limit=200):
    """
    Search across all event types (alerts, auth, file, beaconing, dns)
    with field-level query syntax and free-text search.

    Query syntax:
      category:intrusion  severity:high  host:open-claw01  source:ssh
      type:alert|auth|file|beaconing|dns|process|network
      after:2026-05-20  before:2026-05-22

    Returns: {results: [...], total: int, query_parsed: dict}
    """
    conn = get_db()
    results = []

    # Parse query
    parsed = _parse_search_query(query_str)
    free_text = parsed["free_text"]
    category = parsed.get("category")
    severity = parsed.get("severity")
    host_filter = parsed.get("host")
    source = parsed.get("source")
    event_type = parsed.get("type")  # filter by event source type
    after_ts = parsed.get("after_ts")
    before_ts = parsed.get("before_ts")
    limit = parsed.get("limit", limit)

    # Determine which sources to search
    search_alerts = not event_type or event_type in ("alert",)
    search_auth = not event_type or event_type in ("auth",)
    search_file = not event_type or event_type in ("fim", "file")
    search_beaconing = not event_type or event_type in ("beaconing",)
    search_dns = not event_type or event_type in ("dns",)
    search_process = not event_type or event_type in ("process",)
    search_network = not event_type or event_type in ("network",)

    # ── 1. Alerts ──
    if search_alerts:
        try:
            q = "SELECT * FROM alerts WHERE 1=1 "
            params = []
            if free_text:
                # Use FTS5 for free-text search on alerts
                q = """
                    SELECT a.* FROM alerts a
                    JOIN alerts_fts f ON a.id = f.rowid
                    WHERE alerts_fts MATCH ?
                """
                params = [_fts_sanitize(free_text)]
            if category:
                q += " AND category = ?"
                params.append(category)
            if severity:
                q += " AND severity = ?"
                params.append(severity)
            if after_ts:
                q += " AND timestamp >= ?"
                params.append(after_ts)
            if before_ts:
                q += " AND timestamp <= ?"
                params.append(before_ts)
            q += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(q, params).fetchall()
            for r in rows:
                results.append({
                    "type": "alert",
                    "icon": "🚨",
                    "id": r["id"],
                    "title": r["title"],
                    "description": r["description"],
                    "severity": r["severity"],
                    "timestamp": r["timestamp"],
                    "host": r["source_host"] or "",
                    "source": r["source_ip"] or "",
                    "category": r["category"],
                    "metadata": {
                        "mitre_tactic": r["mitre_tactic"],
                        "mitre_technique": r["mitre_technique"],
                        "process_name": r["process_name"],
                        "process_pid": r["process_pid"],
                        "acknowledged": bool(r["acknowledged"]),
                    },
                })
        except Exception as e:
            _log(f"search alerts error: {e}")

    # ── 2. Auth events ──
    if search_auth:
        try:
            q = "SELECT * FROM auth_events WHERE 1=1 "
            params = []
            if free_text:
                q = """
                    SELECT a.* FROM auth_events a
                    JOIN auth_events_fts f ON a.id = f.rowid
                    WHERE auth_events_fts MATCH ?
                """
                params = [_fts_sanitize(free_text)]
            if source:
                q += " AND source_ip LIKE ?"
                params.append(f"%{source}%")
            if after_ts:
                q += " AND timestamp >= ?"
                params.append(after_ts)
            if before_ts:
                q += " AND timestamp <= ?"
                params.append(before_ts)
            q += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(q, params).fetchall()
            for r in rows:
                results.append({
                    "type": "auth",
                    "icon": "🔑",
                    "id": r["id"],
                    "title": f"{r['event_type']} — {r['username'] or '?'}",
                    "description": r["details"] or "",
                    "severity": "high" if r["event_type"] == "ssh_fail" and (dict(r).get("count_window_10s", 0) or 0) > 3 else "medium",
                    "timestamp": r["timestamp"],
                    "host": "",
                    "source": r["source_ip"] or "",
                    "category": r["event_type"],
                    "metadata": {
                        "username": r["username"],
                        "count_window_10s": dict(r).get("count_window_10s", 1) or 1,
                    },
                })
        except Exception as e:
            _log(f"search auth_events error: {e}")

    # ── 3. File events ──
    if search_file:
        try:
            q = "SELECT * FROM file_events WHERE 1=1 "
            params = []
            if free_text:
                q = """
                    SELECT f.* FROM file_events f
                    JOIN file_events_fts ft ON f.id = ft.rowid
                    WHERE file_events_fts MATCH ?
                """
                params = [_fts_sanitize(free_text)]
            if after_ts:
                q += " AND timestamp >= ?"
                params.append(after_ts)
            if before_ts:
                q += " AND timestamp <= ?"
                params.append(before_ts)
            q += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(q, params).fetchall()
            for r in rows:
                results.append({
                    "type": "fim",
                    "icon": "📁",
                    "id": r["id"],
                    "title": f"File {r['event_type']}: {r['path']}",
                    "description": r["path"] or "",
                    "severity": "high",
                    "timestamp": r["timestamp"],
                    "host": "",
                    "source": "",
                    "category": "file_integrity",
                    "metadata": {
                        "event_type": r["event_type"],
                        "process_name": r["process_name"],
                        "process_pid": r["process_pid"],
                    },
                })
        except Exception as e:
            _log(f"search file_events error: {e}")

    # ── 4. Beaconing events ──
    if search_beaconing:
        try:
            q = "SELECT * FROM beaconing_events WHERE 1=1 "
            params = []
            if free_text:
                q = """
                    SELECT b.* FROM beaconing_events b
                    JOIN beaconing_fts bf ON b.id = bf.rowid
                    WHERE beaconing_fts MATCH ?
                """
                params = [_fts_sanitize(free_text)]
            if source:
                q += " AND (remote_ip LIKE ? OR remote_host LIKE ?)"
                params.extend([f"%{source}%", f"%{source}%"])
            if after_ts:
                q += " AND timestamp >= ?"
                params.append(after_ts)
            if before_ts:
                q += " AND timestamp <= ?"
                params.append(before_ts)
            q += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(q, params).fetchall()
            for r in rows:
                target = r["remote_host"] or r["remote_ip"]
                results.append({
                    "type": "beaconing",
                    "icon": "📡",
                    "id": r["id"],
                    "title": f"{r['process_name']} → {target}:{r['remote_port']}",
                    "description": (
                        f"Beacon-like behavior: interval {r['interval_seconds']}s, "
                        f"confidence {r['confidence']}, {r['sample_count']} samples"
                    ),
                    "severity": "high",
                    "timestamp": r["timestamp"],
                    "host": "",
                    "source": r["remote_ip"],
                    "category": "beaconing",
                    "metadata": {
                        "process_name": r["process_name"],
                        "pid": r["pid"],
                        "remote_ip": r["remote_ip"],
                        "remote_host": r["remote_host"],
                        "remote_port": r["remote_port"],
                        "interval_seconds": r["interval_seconds"],
                        "confidence": r["confidence"],
                        "tls_sni": r["tls_sni"],
                        "http_method": r["http_method"],
                        "http_path": r["http_path"],
                    },
                })
        except Exception as e:
            _log(f"search beaconing error: {e}")

    # ── 5. DNS events ──
    if search_dns:
        try:
            q = "SELECT * FROM dns_events WHERE 1=1 "
            params = []
            if free_text:
                q = """
                    SELECT d.* FROM dns_events d
                    JOIN dns_events_fts df ON d.id = df.rowid
                    WHERE dns_events_fts MATCH ?
                """
                params = [_fts_sanitize(free_text)]
            if after_ts:
                q += " AND timestamp >= ?"
                params.append(after_ts)
            if before_ts:
                q += " AND timestamp <= ?"
                params.append(before_ts)
            q += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(q, params).fetchall()
            for r in rows:
                results.append({
                    "type": "dns",
                    "icon": "🌐",
                    "id": r["id"],
                    "title": f"DNS: {r['domain']}",
                    "description": (
                        f"Domain: {r['domain']}, entropy: {r['entropy_score']}, "
                        f"DGA: {'yes' if r['is_dga'] else 'no'}"
                    ),
                    "severity": "medium" if r["is_dga"] else "low",
                    "timestamp": r["timestamp"],
                    "host": "",
                    "source": "",
                    "category": "dns",
                    "metadata": {
                        "domain": r["domain"],
                        "entropy_score": r["entropy_score"],
                        "is_dga": bool(r["is_dga"]),
                    },
                })
        except Exception as e:
            _log(f"search dns_events error: {e}")

    # ── 6. Active processes (in-memory, from current stats) ──
    if search_process:
        try:
            import psutil as _psutil
            for proc in _psutil.process_iter(["pid", "name", "cmdline", "username", "memory_info", "cpu_percent"]):
                try:
                    info = proc.info
                    name = info["name"] or ""
                    cmd = " ".join(info.get("cmdline") or []) if info.get("cmdline") else name
                    searchable = f"{name} {cmd} {info.get('username', '')}"

                    if free_text and free_text.lower() not in searchable.lower():
                        continue
                    if host_filter and host_filter.lower() not in socket.gethostname().lower():
                        continue

                    mem_mb = round((info.get("memory_info") or _psutil._common.smem(0)).rss / 1024**2, 1)
                    results.append({
                        "type": "process",
                        "icon": "⚙️",
                        "id": info["pid"],
                        "title": f"{name} (PID {info['pid']})",
                        "description": (cmd[:300] if cmd != name else name) or name,
                        "severity": "low",
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "host": socket.gethostname(),
                        "source": "",
                        "category": "process",
                        "metadata": {
                            "pid": info["pid"],
                            "user": info.get("username", ""),
                            "cpu_percent": round(info.get("cpu_percent", 0) or 0, 1),
                            "memory_mb": mem_mb,
                        },
                    })
                except Exception:
                    continue
        except Exception as e:
            _log(f"search processes error: {e}")

    # ── 7. Network connections ──
    if search_network:
        try:
            import subprocess as _sp
            out = _sp.check_output(
                ["ss", "-tnp", "state", "established"],
                text=True, timeout=5, stderr=_sp.DEVNULL
            )
            for line in out.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                remote = parts[3] if len(parts) > 3 else ""
                if ":" not in remote:
                    continue
                remote_ip = ":".join(remote.split(":")[:-1])
                remote_port = remote.split(":")[-1]
                if remote_ip in ("127.0.0.1", "0.0.0.0", "::1", "[::1]", "*"):
                    continue

                proc_name = "?"
                proc_pid = None
                proc_field = parts[-1] if parts else ""
                if "users:" in proc_field:
                    try:
                        inner = proc_field.split("users:(")[1].rstrip(")")
                        for chunk in inner.split("),("):
                            chunk = chunk.strip("()")
                            elems = [e.strip('"') for e in chunk.split(",")]
                            if len(elems) >= 1:
                                proc_name = elems[0]
                                for e in elems[1:]:
                                    if "=" in e:
                                        kv = e.split("=", 1)
                                        if kv[0].strip() == "pid":
                                            try:
                                                proc_pid = int(kv[1].strip())
                                            except ValueError:
                                                pass
                                            break
                                break
                    except Exception:
                        pass

                searchable = f"{proc_name} {remote_ip} {remote_port}"
                if free_text and free_text.lower() not in searchable.lower():
                    continue

                results.append({
                    "type": "network",
                    "icon": "🔗",
                    "id": proc_pid or 0,
                    "title": f"{proc_name} → {remote_ip}:{remote_port}",
                    "description": f"Outbound connection from {proc_name} to {remote_ip}:{remote_port}",
                    "severity": "low",
                    "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "host": socket.gethostname(),
                    "source": remote_ip,
                    "category": "network",
                    "metadata": {
                        "process_name": proc_name,
                        "pid": proc_pid,
                        "remote_ip": remote_ip,
                        "remote_port": int(remote_port) if remote_port.isdigit() else remote_port,
                    },
                })
        except Exception as e:
            _log(f"search network error: {e}")

    # Sort results by timestamp (newest first)
    results.sort(key=lambda x: x["timestamp"], reverse=True)

    # Trim to limit
    total = len(results)
    results = results[:limit]

    return {
        "results": results,
        "total": total,
        "query_parsed": parsed,
    }


def _fts_sanitize(text):
    """Sanitize user text for FTS5 MATCH query. Escapes special chars."""
    # FTS5 special chars: - " * ( )
    # Remove them to avoid syntax errors; keep alphanumeric, spaces, and basic punctuation
    import re as _re
    cleaned = _re.sub(r'[()\\[\\]{}~@#$%^&+=|\\\\<>]', '', text)
    # Strip leading hyphens (FTS5 NOT operator) to avoid zero-result queries
    cleaned = cleaned.lstrip('-')
    # Escape double quotes
    cleaned = cleaned.replace('"', '""')
    # If text has multiple words, wrap in quotes for phrase matching
    if ' ' in cleaned.strip():
        cleaned = f'"{cleaned.strip()}"'
    elif cleaned.strip():
        cleaned = cleaned.strip() + '*'
    return cleaned if cleaned.strip() else '*'


def _parse_search_query(query_str):
    """
    Parse a search query string into structured fields.
    Supports: field:value syntax, time ranges, free text.
    """
    if not query_str:
        query_str = ""

    parsed = {
        "free_text": "",
        "category": None,
        "severity": None,
        "host": None,
        "source": None,
        "type": None,
        "after_ts": None,
        "before_ts": None,
        "limit": 200,
    }

    import re as _re

    # Map field names captured by regex to parsed dict keys
    # (after/before are parsed as "after_ts"/"before_ts")
    TIME_FIELD_MAP = {"after": "after_ts", "before": "before_ts"}

    # Extract field:value pairs
    field_pattern = _re.compile(
        r'\b(category|severity|host|source|type|after|before|limit):(\S+)'
    )
    remaining = query_str
    for m in field_pattern.finditer(query_str):
        field = m.group(1)
        value = m.group(2)
        resolved = TIME_FIELD_MAP.get(field, field)
        if resolved in parsed:
            parsed[resolved] = value
        # Remove matched text
        remaining = remaining.replace(m.group(0), "", 1)

    # Clean up remaining free text
    parsed["free_text"] = " ".join(remaining.split()).strip()

    # Parse timestamps
    if parsed["after_ts"]:
        parsed["after_ts"] = _parse_time_string(parsed["after_ts"])
    if parsed["before_ts"]:
        parsed["before_ts"] = _parse_time_string(parsed["before_ts"])

    # Parse limit
    if parsed["limit"]:
        try:
            parsed["limit"] = int(parsed["limit"])
        except ValueError:
            parsed["limit"] = 200

    return parsed


def _parse_time_string(s):
    """Parse a time string like '2026-05-20' or '2026-05-20T14:30:00Z' into ISO format."""
    if not s:
        return None
    s = s.strip().rstrip("Z")
    # Try ISO format
    try:
        datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")
        return s + "Z"
    except ValueError:
        pass
    # Try date-only
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return s + "T00:00:00Z"
    except ValueError:
        pass
    # Try relative: 24h, 7d, etc.
    import re as _re
    rel = _re.match(r'^(\d+)([hdm])$', s)
    if rel:
        amount = int(rel.group(1))
        unit = rel.group(2)
        dt = datetime.now(timezone.utc)
        if unit == 'h':
            dt = dt - timedelta(hours=amount)
        elif unit == 'd':
            dt = dt - timedelta(days=amount)
        elif unit == 'm':
            dt = dt - timedelta(minutes=amount)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return s


def _log(msg):
    """Timestamped log to stdout."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[deep-sight {ts}] {msg}", flush=True)


# ═══════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════

def shannon_entropy(s):
    """Calculate Shannon entropy of a string. Returns value 0–~4.7."""
    if not s:
        return 0.0
    n = len(s)
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def normalized_entropy(s):
    """Entropy normalized by string length to roughly 0–1 scale."""
    if not s or len(s) < 2:
        return 0.0
    raw = shannon_entropy(s)
    # Max entropy for given length is log2(len)
    max_entropy = math.log2(len(s)) if len(s) > 1 else 1.0
    return min(raw / max_entropy, 1.0)


def _read_file(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def _read_lines(path):
    try:
        with open(path) as f:
            return f.readlines()
    except Exception:
        return []


# ═══════════════════════════════════════════
# Alert Rules Engine
# ═══════════════════════════════════════════

# Keep recent alerts in memory for dedup
_recent_alerts = []  # list of (category, source_ip, title, timestamp)
_recent_alerts_lock = threading.Lock()


def _is_duplicate(category, source_ip, title, now_epoch=None):
    """Check if an alert for this (category, source_ip, title) was raised recently."""
    if now_epoch is None:
        now_epoch = time.time()
    with _recent_alerts_lock:
        # Prune old
        cutoff = now_epoch - ALERT_DEDUP_WINDOW_S
        _recent_alerts[:] = [a for a in _recent_alerts if a[3] > cutoff]
        for cat, ip, ttl, ts in _recent_alerts:
            if cat == category and ip == source_ip and ttl == title:
                return True
        _recent_alerts.append((category, source_ip, title, now_epoch))
        return False


def create_alert(severity, category, title, description="", source_host="",
                 source_ip="", mitre_tactic="", mitre_technique="",
                 process_pid=None, process_name="", raw_data=None):
    """Insert an alert if not a duplicate and return the alert dict."""
    now_epoch = time.time()
    if _is_duplicate(category, source_ip, title, now_epoch):
        return None

    raw_json = json.dumps(raw_data or {})
    now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        conn = get_db()
        cur = conn.execute("""
            INSERT INTO alerts (timestamp, severity, category, title, description,
                                source_host, source_ip, mitre_tactic, mitre_technique,
                                process_pid, process_name, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (now_ts, severity, category, title, description,
              source_host, source_ip, mitre_tactic, mitre_technique,
              process_pid, process_name, raw_json))
        conn.commit()
        alert_id = cur.lastrowid
        _log(f"⚠ ALERT [{severity.upper()}] {title} (id={alert_id})")
        alert_dict = {
            "id": alert_id, "timestamp": now_ts, "severity": severity,
            "category": category, "title": title, "description": description,
            "source_host": source_host, "source_ip": source_ip,
            "mitre_tactic": mitre_tactic, "mitre_technique": mitre_technique,
            "process_pid": process_pid, "process_name": process_name,
            "raw_data": raw_data, "acknowledged": False,
        }
        # Dispatch notification (non-blocking background thread)
        _dispatch_notification(alert_dict)
        return alert_dict
    except Exception as e:
        _log(f"Error creating alert: {e}")
        return None


def evaluate_rules(event_type, data):
    """
    Main rule evaluation entry point. Called by collectors with event type and data dict.
    Returns list of alerts created.
    """
    alerts = []

    if event_type == "ssh_brute_force":
        ip = data.get("source_ip", "")
        count = data.get("count", 0)
        if count > SSH_BRUTE_FORCE_COUNT:
            a = create_alert(
                severity="critical",
                category="brute_force",
                title=f"SSH brute force: {count} failures from {ip}",
                description=f"Detected {count} SSH authentication failures from {ip} within {SSH_BRUTE_FORCE_WINDOW_S}s window",
                source_ip=ip,
                mitre_tactic="Credential Access",
                mitre_technique="T1110 (Brute Force)",
                raw_data={"failed_count": count, "window_s": SSH_BRUTE_FORCE_WINDOW_S},
            )
            if a:
                alerts.append(a)

    elif event_type == "reverse_shell":
        pid = data.get("pid")
        cmdline = data.get("cmdline", "")
        pattern_desc = data.get("pattern", "")
        ppid = data.get("ppid")
        pname = data.get("process_name", "")
        a = create_alert(
            severity="critical",
            category="reverse_shell",
            title=f"Reverse shell detected: {pname} (PID {pid})",
            description=f"Process matched pattern: {pattern_desc}\nCommand: {cmdline[:300]}",
            mitre_tactic="Execution",
            mitre_technique="T1059 (Command and Scripting Interpreter)",
            process_pid=pid,
            process_name=pname,
            raw_data={"cmdline": cmdline, "ppid": ppid, "pattern": pattern_desc},
        )
        if a:
            alerts.append(a)

    elif event_type == "webshell":
        pid = data.get("pid")
        parent = data.get("parent_name", "")
        child = data.get("process_name", "")
        a = create_alert(
            severity="critical",
            category="webshell",
            title=f"Webshell suspected: {parent} spawned {child} (PID {pid})",
            description=f"Web server process '{parent}' spawned shell process '{child}'. This is a common webshell indicator.",
            mitre_tactic="Persistence",
            mitre_technique="T1505 (Server Software Component)",
            process_pid=pid,
            process_name=child,
            raw_data={"parent_name": parent},
        )
        if a:
            alerts.append(a)

    elif event_type == "process_from_suspect_dir":
        pid = data.get("pid")
        pname = data.get("process_name", "")
        exe_path = data.get("exe_path", "")
        a = create_alert(
            severity="high",
            category="suspicious_execution",
            title=f"Process from suspicious location: {pname} from {exe_path}",
            description=f"Process '{pname}' (PID {pid}) executing from {exe_path}",
            mitre_tactic="Execution",
            mitre_technique="T1204 (User Execution)",
            process_pid=pid,
            process_name=pname,
            raw_data={"exe_path": exe_path},
        )
        if a:
            alerts.append(a)

    elif event_type == "beaconing":
        pname = data.get("process_name", "")
        pid = data.get("pid")
        remote_ip = data.get("remote_ip", "")
        remote_host = data.get("remote_host", "")
        remote_port = data.get("remote_port")
        interval = data.get("interval_seconds", 0)
        confidence = data.get("confidence", 0)
        samples = data.get("sample_count", 0)
        if confidence >= BEACONING_CONFIDENCE_MIN:
            a = create_alert(
                severity="high",
                category="beaconing",
                title=f"C2 beaconing: {pname} → {remote_host or remote_ip}:{remote_port}",
                description=(
                    f"Process '{pname}' (PID {pid}) shows beacon-like behavior to "
                    f"{remote_host or remote_ip}:{remote_port} — interval {interval:.1f}s, "
                    f"confidence {confidence:.2f}, {samples} samples"
                ),
                source_ip=remote_ip,
                mitre_tactic="Command and Control",
                mitre_technique="T1071 (Application Layer Protocol)",
                process_pid=pid,
                process_name=pname,
                raw_data={
                    "interval_seconds": interval, "confidence": confidence,
                    "sample_count": samples, "remote_host": remote_host,
                    "remote_port": remote_port,
                },
            )
            if a:
                alerts.append(a)

    elif event_type == "dga":
        domain = data.get("domain", "")
        entropy = data.get("entropy_score", 0)
        pid = data.get("pid")
        pname = data.get("process_name", "")
        if entropy >= DGA_ALERT_THRESHOLD:
            a = create_alert(
                severity="medium",
                category="dga",
                title=f"DGA domain suspected: {domain} (entropy={entropy:.2f})",
                description=f"Domain '{domain}' has high entropy ({entropy:.2f}), possibly DGA-generated. Process: {pname} (PID {pid})",
                mitre_tactic="Command and Control",
                mitre_technique="T1568 (Dynamic Resolution)",
                process_pid=pid,
                process_name=pname,
                raw_data={"domain": domain, "entropy_score": entropy},
            )
            if a:
                alerts.append(a)

    elif event_type == "file_integrity":
        path = data.get("path", "")
        event = data.get("event_type", "modified")
        a = create_alert(
            severity="critical",
            category="file_integrity",
            title=f"Sensitive file {event}: {path}",
            description=f"File integrity violation: {path} was {event}",
            mitre_tactic="Privilege Escalation",
            mitre_technique="T1548 (Abuse Elevation Control Mechanism)",
            raw_data={"path": path, "event_type": event},
        )
        if a:
            alerts.append(a)

    elif event_type == "sudoers_change":
        a = create_alert(
            severity="critical",
            category="privilege_escalation",
            title=f"Sudoers modified: {data.get('path', '')}",
            description="sudoers file was modified — possible privilege escalation attempt",
            mitre_tactic="Privilege Escalation",
            mitre_technique="T1548 (Abuse Elevation Control Mechanism)",
            raw_data=data,
        )
        if a:
            alerts.append(a)

    elif event_type == "authorized_keys_change":
        a = create_alert(
            severity="critical",
            category="persistence",
            title=f"Authorized SSH keys modified: {data.get('path', '')}",
            description="authorized_keys file was modified — possible backdoor deployment",
            mitre_tactic="Persistence",
            mitre_technique="T1098 (Account Manipulation)",
            raw_data=data,
        )
        if a:
            alerts.append(a)

    elif event_type == "hidden_cmdline":
        a = create_alert(
            severity="high",
            category="evasion",
            title=f"Process with hidden cmdline: PID {data.get('pid')}",
            description="A process has no visible command line — possible stealth malware",
            mitre_tactic="Defense Evasion",
            mitre_technique="T1564 (Hide Artifacts)",
            process_pid=data.get("pid"),
        )
        if a:
            alerts.append(a)

    elif event_type == "syslog_alert":
        # Syslog alerts are created directly by syslog_ingest.py via create_alert().
        # This handler exists for completeness — external syslog events that
        # arrived while detection was starting can be replayed through here.
        severity = data.get("severity", "medium")
        category = data.get("category", "syslog")
        title = data.get("title", "Syslog alert")
        description = data.get("description", "")
        source_ip = data.get("source_ip", "")
        a = create_alert(
            severity=severity,
            category=category,
            title=title,
            description=description,
            source_ip=source_ip,
            mitre_tactic=data.get("mitre_tactic", ""),
            mitre_technique=data.get("mitre_technique", ""),
            raw_data=data.get("raw_data", {}),
        )
        if a:
            alerts.append(a)

    return alerts


# ═══════════════════════════════════════════
# Collector: Process Audit
# ═══════════════════════════════════════════

# Track previously seen PIDs
_seen_pids = set()
_seen_pids_lock = threading.Lock()


def _get_process_info(pid):
    """Safely extract process info from /proc/<pid>."""
    try:
        cmdline = _read_file(f"/proc/{pid}/cmdline").replace("\x00", " ").strip()
        comm = _read_file(f"/proc/{pid}/comm").strip()
        exe = os.readlink(f"/proc/{pid}/exe") if os.path.exists(f"/proc/{pid}/exe") else ""
        stat = _read_file(f"/proc/{pid}/stat").strip()
        ppid = None
        if stat:
            # stat format: pid (comm) state ppid ...
            parts = stat.split(")")
            if len(parts) >= 2:
                ppid = int(parts[1].split()[1])
        return {
            "cmdline": cmdline or f"[{comm}]",
            "comm": comm,
            "exe": exe,
            "ppid": ppid,
        }
    except Exception:
        return None


def _get_parent_name(ppid):
    """Get the process name of a parent PID."""
    if ppid is None:
        return ""
    try:
        return _read_file(f"/proc/{ppid}/comm").strip()
    except Exception:
        return ""


def _scan_process(pid):
    """Scan a single process for suspicious indicators. Returns list of alert data dicts."""
    info = _get_process_info(pid)
    if not info:
        return []

    cmdline = info["cmdline"]
    comm = info["comm"]
    exe = info["exe"]
    ppid = info["ppid"]
    events = []

    # ── Check reverse shells ──
    for pattern, desc in REVERSE_SHELL_PATTERNS:
        try:
            if re.search(pattern, cmdline, re.IGNORECASE):
                events.append({
                    "type": "reverse_shell",
                    "pid": pid, "process_name": comm,
                    "cmdline": cmdline, "pattern": desc, "ppid": ppid,
                })
                break  # one pattern match is enough
        except re.error:
            continue

    # ── Check for process from /tmp or /dev/shm ──
    suspect_dirs = ["/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"]
    if exe:
        exe_lower = exe.lower()
        for sd in suspect_dirs:
            if exe_lower.startswith(sd):
                events.append({
                    "type": "process_from_suspect_dir",
                    "pid": pid, "process_name": comm, "exe_path": exe,
                })
                break

    # Also check if argv[0] or cmdline starts with a suspect path
    if cmdline:
        cmd_lower = cmdline.lower()
        for sd in suspect_dirs:
            if cmd_lower.startswith(sd) or f" {sd}" in cmd_lower:
                # Only fire if not already caught by exe check
                if not any(e["type"] == "process_from_suspect_dir" for e in events):
                    events.append({
                        "type": "process_from_suspect_dir",
                        "pid": pid, "process_name": comm,
                        "exe_path": cmdline.split()[0] if cmdline.split() else cmdline[:50],
                    })
                break

    # ── Hidden cmdline (only if comm exists but cmdline is empty/just comm name) ──
    if comm and (not cmdline or cmdline == f"[{comm}]"):
        events.append({
            "type": "hidden_cmdline",
            "pid": pid,
        })

    # ── Web server spawning shell ──
    if ppid is not None:
        parent_name = _get_parent_name(ppid).lower()
        if parent_name in WEB_SERVER_USERS and comm.lower() in ("bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "php"):
            events.append({
                "type": "webshell",
                "pid": pid, "process_name": comm,
                "parent_name": parent_name,
            })

    return events


def process_audit_collector():
    """Poll /proc for new processes and scan them for suspicious behaviour."""
    _log("process_audit_collector started (interval={}s)".format(INTERVAL_PROCESS_AUDIT))
    global _seen_pids

    while True:
        try:
            current_pids = set()
            for pid_dir in glob.glob("/proc/[0-9]*"):
                try:
                    pid = int(os.path.basename(pid_dir))
                    current_pids.add(pid)
                except ValueError:
                    continue

            with _seen_pids_lock:
                # Seed on first run
                if not _seen_pids:
                    _seen_pids = current_pids
                    _log(f"process_audit: seeded with {len(_seen_pids)} existing PIDs")
                else:
                    new_pids = current_pids - _seen_pids
                    _seen_pids = current_pids
                    # Also re-scan old PIDs if cmdline changed — but for now, just new

            if new_pids:
                for pid in new_pids:
                    events = _scan_process(pid)
                    for evt in events:
                        evaluate_rules(evt.pop("type"), evt)

            # Also do a periodic full scan for webshell detection (every 60s)
            # Tracked via simple counter
            pass

        except Exception as e:
            _log(f"process_audit_collector error: {e}")

        time.sleep(INTERVAL_PROCESS_AUDIT)


# ═══════════════════════════════════════════
# Collector: Beaconing Detection
# ═══════════════════════════════════════════

# Track outbound HTTP connections: {(process_name, remote_ip, remote_port): [(timestamp,)]}
_beacon_tracker = defaultdict(list)
_beacon_tracker_lock = threading.Lock()


def _collect_outbound_connections():
    """Collect established outbound connections using ss -tnp (non-root)."""
    http_ports = {80, 443, 8080, 8443, 3000, 8000, 8888, 9090}
    connections = []

    try:
        out = subprocess.check_output(
            ["ss", "-tnp", "state", "established"],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        for line in out.strip().split("\n")[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue

            # Parse local port (for correlation with packet sniffer)
            local = parts[2] if len(parts) > 2 else ""
            src_port = 0
            if ":" in local:
                try:
                    src_port = int(local.split(":")[-1])
                except ValueError:
                    pass

            # Parse remote IP:port
            remote = parts[3] if len(parts) > 3 else ""
            if ":" not in remote:
                continue
            remote_port_str = remote.split(":")[-1]
            try:
                remote_port = int(remote_port_str)
            except ValueError:
                continue

            remote_ip = ":".join(remote.split(":")[:-1])
            # Skip localhost
            if remote_ip in ("127.0.0.1", "0.0.0.0", "::1", "[::1]", "*"):
                continue

            # Parse process info
            process = "?"
            pid = None
            proc_field = parts[-1] if parts else ""
            if "users:" in proc_field:
                try:
                    inner = proc_field.split("users:(")[1].rstrip(")")
                    for chunk in inner.split("),("):
                        chunk = chunk.strip("()")
                        elems = [e.strip('"') for e in chunk.split(",")]
                        if len(elems) >= 1:
                            process = elems[0]
                            for e in elems[1:]:
                                if "=" in e:
                                    kv = e.split("=", 1)
                                    if kv[0].strip() == "pid":
                                        try:
                                            pid = int(kv[1].strip())
                                        except ValueError:
                                            pass
                                        break
                            break
                except Exception:
                    pass

            if not pid:
                continue

            # Enrich with HTTP/TLS metadata from packet sniffer
            http_meta = {}
            with _http_metadata_lock:
                if src_port and src_port in _http_metadata:
                    m = _http_metadata[src_port]
                    if time.time() - m.get("_ts", 0) < _HTTP_METADATA_TTL:
                        http_meta = m

            connections.append({
                "process_name": process,
                "pid": pid,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "src_port": src_port,
                "timestamp": time.time(),
                "http_method": http_meta.get("method", ""),
                "http_path": http_meta.get("path", ""),
                "http_query": http_meta.get("query", ""),
                "tls_sni": http_meta.get("sni", ""),
                "user_agent": http_meta.get("ua", ""),
            })

            # Feed observed IPs/domains into threat intel
            if HAS_THREAT_INTEL:
                try:
                    threat_intel.record_observed_ip(
                        remote_ip, host=socket.gethostname(), port=remote_port,
                        protocol=http_meta.get("sni", "") or "tcp"
                    )
                    if http_meta.get("sni"):
                        resolved = remote_ip if not remote_ip.startswith("192.") else ""
                        threat_intel.record_observed_domain(
                            http_meta["sni"], host=socket.gethostname(),
                            resolved_ip=resolved
                        )
                except Exception:
                    pass
    except Exception as e:
        pass

    return connections


# ═══════════════════════════════════════════
# Packet Sniffer — HTTP/TLS metadata from outbound connections
# ═══════════════════════════════════════════

def _start_packet_sniffer():
    """Start background thread that captures HTTP/TLS metadata from outbound traffic."""
    t = threading.Thread(target=_packet_sniffer_loop, daemon=True, name="pkt-sniff")
    t.start()
    _log("packet_sniffer thread started")


def _packet_sniffer_loop():
    """Capture HTTP request lines and TLS SNI from outbound connections via tcpdump."""
    global _http_metadata

    # Ports we inspect for HTTP/TLS
    target_ports = "80 or 443 or 8080 or 8443 or 3000 or 8000 or 8888 or 9090 or 7443"
    backoff = 10

    while True:
        proc = None
        try:
            # Check if tcpdump is available
            result = subprocess.run(
                ["/usr/bin/tcpdump", "--version"], capture_output=True, timeout=3
            )
            if result.returncode != 0:
                _log("packet_sniffer: tcpdump not available, sleeping 300s")
                time.sleep(300)
                continue

            # tcpdump: capture first 3KB of outbound TCP data packets, ASCII mode
            proc = subprocess.Popen(
                ["/usr/bin/tcpdump", "-i", "any", "-l", "-n", "-A", "-s", "3072",
                 "--immediate-mode", "-q",
                 f"tcp and (dst port ({target_ports})) and "
                 "not dst net 127.0.0.0/8 and not dst net 100.64.0.0/10"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
            )

            # Check for immediate permission errors on stderr
            time.sleep(0.5)
            if proc.poll() is not None:
                stderr_out = proc.stderr.read() if proc.stderr else ""
                if "permission" in stderr_out.lower() or "operation not permitted" in stderr_out.lower():
                    _log("packet_sniffer: tcpdump needs cap_net_raw — "
                         "run: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump")
                    _log("packet_sniffer: sleeping 300s (needs root intervention)")
                    time.sleep(300)
                    backoff = 300
                    continue
                else:
                    _log(f"packet_sniffer: tcpdump exited immediately: {stderr_out[:200]}")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 300)
                    continue

            backoff = 10  # reset backoff on success

            current_flow = None  # (src_ip, src_port, dst_ip, dst_port)
            payload_lines = []

            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line:
                    continue

                # Detect tcpdump header: "HH:MM:SS.micro IP src.ip.port > dst.ip.port: Flags [P.]..."
                m = re.match(
                    r"^(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(\S+)\.(\d+)\s+>\s+(\S+)\.(\d+):\s+Flags\s+\[(P[\.]*)\]",
                    line
                )
                if m:
                    # Flush previous flow if any
                    if current_flow and payload_lines:
                        _parse_flow_payload(current_flow, payload_lines)

                    src_ip = m.group(2)
                    src_port = int(m.group(3))
                    dst_ip = m.group(4)
                    dst_port = int(m.group(5))
                    current_flow = (src_ip, src_port, dst_ip, dst_port)
                    payload_lines = []
                    continue

                # Skip hex dump lines
                if line.startswith("\t") and re.match(r"^\t0x[0-9a-f]+:", line):
                    continue

                # Accumulate payload lines (ASCII portion)
                if current_flow:
                    payload_lines.append(line)

                # Flush after collecting enough
                if current_flow and len(payload_lines) >= 20:
                    _parse_flow_payload(current_flow, payload_lines)
                    current_flow = None
                    payload_lines = []

            _log("packet_sniffer: tcpdump process exited, restarting in 10s")

        except FileNotFoundError:
            _log("packet_sniffer: tcpdump not found, sleeping 300s")
            time.sleep(300)
        except Exception as e:
            _log(f"packet_sniffer error: {e}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
        finally:
            if proc:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except Exception:
                    pass


def _parse_flow_payload(flow, lines):
    """Parse accumulated TCP payload lines for HTTP request or TLS SNI."""
    if not flow or not lines:
        return

    src_ip, src_port, dst_ip, dst_port = flow
    payload = "".join(lines)

    meta = {"_ts": time.time()}

    # ── Parse HTTP request line ──
    http_match = re.match(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)\s+(\S+)\s+HTTP/\d",
        payload, re.IGNORECASE
    )
    if http_match:
        meta["method"] = http_match.group(1).upper()
        full_path = http_match.group(2)
        if "?" in full_path:
            meta["path"] = full_path.split("?")[0]
            meta["query"] = full_path.split("?", 1)[1]
        else:
            meta["path"] = full_path
            meta["query"] = ""

        # Extract Host header
        host_match = re.search(r"(?i)\r?\nHost:\s*(\S+)", payload)
        if host_match:
            meta["sni"] = host_match.group(1)
            # If path is absolute URL, Host header takes precedence for SNI

        # Extract User-Agent
        ua_match = re.search(r"(?i)\r?\nUser-Agent:\s*(.+?)\r?\n", payload)
        if ua_match:
            meta["ua"] = ua_match.group(1).strip()[:200]
    else:
        # ── Parse TLS ClientHello for SNI ──
        # TLS record: ContentType(1) Version(2) Length(2) ...
        # Handshake: Type(1) Length(3) ... ClientHello ...
        # We look for the SNI extension in the binary payload
        # Since we're capturing ASCII, we scan for readable hostname-like strings
        # in the TLS plaintext portions

        # TLS handshake starts with 0x16 (ContentType Handshake)
        # ClientHello starts with 0x01 (HandshakeType ClientHello)
        # SNI extension: extension_type=0x0000, then length, then ServerNameList
        # In ASCII dump we may see fragments; look for the SNI hostname pattern

        sni = _extract_tls_sni_from_ascii(payload, lines)
        if sni:
            meta["sni"] = sni
            meta["method"] = "TLS"

    # Only cache if we found something useful
    if len(meta) > 1:  # more than just _ts
        with _http_metadata_lock:
            _http_metadata[src_port] = meta

        # Prune stale entries
        now = time.time()
        with _http_metadata_lock:
            stale = [p for p, m in _http_metadata.items()
                     if now - m.get("_ts", 0) > _HTTP_METADATA_TTL * 3]
            for p in stale:
                del _http_metadata[p]


def _extract_tls_sni_from_ascii(payload, lines):
    """Extract SNI hostname from TLS ClientHello ASCII dump.

    TLS SNI extension appears in the ClientHello as:
    - Extension type 0x00 0x00 (server_name)
    - ServerNameList contains hostname in plaintext

    In ASCII dump, the SNI hostname is usually the only readable
    domain-like string near the start of the ClientHello payload.
    """
    # Look for patterns like "www.example.com" or "api.example.co.uk"
    # that appear in the first few lines of TLS handshake
    domain_re = re.compile(
        r'\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
        r'\.)+[a-zA-Z]{2,}(?::\d+)?\b'
    )

    # Scan only the first 500 chars of combined payload
    text = payload[:500]
    matches = domain_re.findall(text)

    # SNI typically appears after the TLS record header, ClientHello,
    # cipher suites, compression methods, then extensions
    # Filter out noise — real SNI is usually a clean domain
    for m in matches:
        m = m.rstrip(":")
        # Skip obvious non-domain strings (cipher suite names, etc.)
        low = m.lower()
        if low in ("http", "tls", "ssl", "www"):
            continue
        if not re.match(r'^[a-zA-Z0-9]', m):
            continue
        return m

    return None


def beaconing_collector():
    """Analyze outbound connection timing for C2 beaconing patterns."""
    _log("beaconing_collector started (interval={}s, window={}s)".format(
        INTERVAL_BEACONING, BEACONING_WINDOW_S))
    global _beacon_tracker

    while True:
        try:
            conns = _collect_outbound_connections()
            now = time.time()
            cutoff = now - BEACONING_WINDOW_S

            # Group connections by (process, remote_ip, remote_port, http_path)
            # Include http_path in key to distinguish different C2 endpoints
            for c in conns:
                path_key = c.get("http_path", "") or ""
                key = (c["process_name"], c["remote_ip"], c["remote_port"], path_key)
                meta = {
                    "http_method": c.get("http_method", ""),
                    "http_path": c.get("http_path", ""),
                    "http_query": c.get("http_query", ""),
                    "tls_sni": c.get("tls_sni", ""),
                    "user_agent": c.get("user_agent", ""),
                    "src_port": c.get("src_port", 0),
                }
                with _beacon_tracker_lock:
                    _beacon_tracker[key].append((c["timestamp"], c["pid"], meta))

            # Analyze each group
            with _beacon_tracker_lock:
                keys_to_remove = []
                for key, samples in _beacon_tracker.items():
                    # Prune old samples
                    samples[:] = [(ts, p, m) for ts, p, m in samples if ts > cutoff]
                    if len(samples) < BEACONING_MIN_SAMPLES:
                        if not samples:
                            keys_to_remove.append(key)
                        continue

                    timestamps = sorted([s[0] for s in samples])
                    pid = samples[0][1]

                    # Collect best HTTP/TLS metadata across samples
                    best_meta = {}
                    for _, _, m in samples:
                        for field in ("http_method", "http_path", "http_query",
                                      "tls_sni", "user_agent", "src_port"):
                            if m.get(field) and not best_meta.get(field):
                                best_meta[field] = m[field]

                    # Calculate deltas
                    deltas = []
                    for i in range(1, len(timestamps)):
                        deltas.append(timestamps[i] - timestamps[i - 1])

                    if not deltas:
                        continue

                    mean_delta = sum(deltas) / len(deltas)

                    # Skip if interval is too short or too long
                    if mean_delta < 10 or mean_delta > 3600:
                        continue

                    # Calculate variance and check for regularity
                    if len(deltas) < 2:
                        continue

                    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
                    stddev = math.sqrt(variance)

                    # Coefficient of variation
                    if mean_delta > 0:
                        cv = stddev / mean_delta
                    else:
                        cv = 0

                    if cv < BEACONING_VARIANCE_MAX:
                        confidence = 1.0 - cv
                        pname, rip, rport, path_key = key

                        # Prefer TLS SNI for host; fall back to DNS reverse lookup
                        tls_sni = best_meta.get("tls_sni", "")
                        remote_host = tls_sni
                        if not remote_host:
                            try:
                                remote_host = socket.gethostbyaddr(rip)[0]
                            except Exception:
                                remote_host = rip

                        http_method = best_meta.get("http_method", "")
                        http_path = best_meta.get("http_path", "")
                        http_query = best_meta.get("http_query", "")
                        user_agent = best_meta.get("user_agent", "")
                        src_port = best_meta.get("src_port", 0)

                        # Store in beaconing_events table
                        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        try:
                            conn = get_db()
                            conn.execute("""
                                INSERT INTO beaconing_events
                                (timestamp, process_name, pid, remote_ip, remote_host,
                                 remote_port, src_port, interval_seconds, confidence,
                                 sample_count, http_method, http_path, http_query,
                                 tls_sni, user_agent)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (now_ts, pname, pid, rip,
                                  remote_host if remote_host != rip else "",
                                  rport, src_port, round(mean_delta, 2),
                                  round(confidence, 3), len(timestamps),
                                  http_method, http_path, http_query,
                                  tls_sni, user_agent))
                            conn.commit()
                        except Exception as e:
                            _log(f"beaconing DB insert error: {e}")

                        evaluate_rules("beaconing", {
                            "process_name": pname,
                            "pid": pid,
                            "remote_ip": rip,
                            "remote_host": remote_host if remote_host != rip else "",
                            "remote_port": rport,
                            "interval_seconds": round(mean_delta, 2),
                            "confidence": round(confidence, 3),
                            "sample_count": len(timestamps),
                            "http_method": http_method,
                            "http_path": http_path,
                            "http_query": http_query,
                            "tls_sni": tls_sni,
                            "user_agent": user_agent,
                        })

                # Clean up empty trackers
                for key in keys_to_remove:
                    del _beacon_tracker[key]

        except Exception as e:
            _log(f"beaconing_collector error: {e}")

        time.sleep(INTERVAL_BEACONING)


# ═══════════════════════════════════════════
# Collector: Auth Monitor
# ═══════════════════════════════════════════

# Track SSH failures for brute force detection
_ssh_fail_tracker = defaultdict(list)  # ip -> [(timestamp,)]
_ssh_fail_lock = threading.Lock()
_auth_log_pos = 0  # track file position


def _parse_auth_line(line):
    """Parse a line from /var/log/auth.log and return event dict or None."""
    # Timestamp: 2026-05-14T20:24:00.123456-05:00
    line = line.strip()
    if not line:
        return None

    # Extract IP where possible
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
    source_ip = ip_match.group(1) if ip_match else ""

    # SSH
    if "Failed password" in line:
        user_match = re.search(r'Failed password for (\S+)', line)
        username = user_match.group(1) if user_match else "unknown"
        return {
            "event_type": "ssh_fail",
            "username": username,
            "source_ip": source_ip,
            "details": line[:400],
        }
    elif "Failed publickey" in line:
        user_match = re.search(r'Failed publickey for (\S+)', line)
        username = user_match.group(1) if user_match else "unknown"
        return {
            "event_type": "ssh_fail",
            "username": username,
            "source_ip": source_ip,
            "details": line[:400],
        }
    elif "Accepted password" in line:
        user_match = re.search(r'Accepted password for (\S+)', line)
        username = user_match.group(1) if user_match else "unknown"
        return {
            "event_type": "ssh_success",
            "username": username,
            "source_ip": source_ip,
            "details": line[:400],
        }
    elif "Accepted publickey" in line:
        user_match = re.search(r'Accepted publickey for (\S+)', line)
        username = user_match.group(1) if user_match else "unknown"
        return {
            "event_type": "ssh_success",
            "username": username,
            "source_ip": source_ip,
            "details": line[:400],
        }

    # Sudo
    elif "sudo:" in line:
        user_match = re.search(r'sudo:\s+(\S+)', line)
        username = user_match.group(1) if user_match else ""
        command_match = re.search(r'COMMAND=(.*)', line)
        command = command_match.group(1) if command_match else ""
        return {
            "event_type": "sudo",
            "username": username,
            "source_ip": source_ip,
            "details": command[:400],
        }

    # Su
    elif "su:" in line or "pam_unix(su:" in line:
        user_match = re.search(r'su:.*?(\S+)', line)
        username = user_match.group(1) if user_match else ""
        if "session opened" in line:
            return {
                "event_type": "su",
                "username": username,
                "source_ip": source_ip,
                "details": line[:400],
            }

    # User/group creation
    elif "useradd" in line or "new user" in line.lower():
        user_match = re.search(r"new user: name=(\S+)", line)
        username = user_match.group(1) if user_match else "?"
        return {
            "event_type": "useradd",
            "username": username,
            "source_ip": source_ip,
            "details": line[:400],
        }
    elif "groupadd" in line or "new group" in line.lower():
        group_match = re.search(r"new group: name=(\S+)", line)
        username = group_match.group(1) if group_match else "?"
        return {
            "event_type": "groupadd",
            "username": username,
            "source_ip": source_ip,
            "details": line[:400],
        }

    # Password changes
    elif "passwd" in line and ("password changed" in line.lower() or "password for" in line.lower()):
        return {
            "event_type": "passwd",
            "username": "",
            "source_ip": source_ip,
            "details": line[:400],
        }

    return None


def auth_monitor():
    """Monitor /var/log/auth.log for authentication events."""
    _log("auth_monitor started (interval={}s)".format(INTERVAL_AUTH_MONITOR))
    AUTH_LOG = "/var/log/auth.log"

    # Check access
    if not os.access(AUTH_LOG, os.R_OK):
        _log(f"auth_monitor: cannot read {AUTH_LOG} — skipping")
        return

    global _ssh_fail_tracker, _auth_log_pos

    while True:
        try:
            # Read new lines from auth.log (tail the last 200 lines each iteration)
            with open(AUTH_LOG) as f:
                f.seek(0, 2)  # end
                file_size = f.tell()
                # Read last ~200 lines or from last position
                start_pos = max(0, file_size - 32768)  # ~32KB
                f.seek(start_pos)
                lines = f.readlines()

            new_events = []
            for line in lines:
                event = _parse_auth_line(line)
                if event:
                    new_events.append(event)

            # Process SSH failures for brute force detection
            now = time.time()
            with _ssh_fail_lock:
                for evt in new_events:
                    if evt["event_type"] == "ssh_fail" and evt["source_ip"]:
                        ip = evt["source_ip"]
                        _ssh_fail_tracker[ip].append(now)
                        # Prune old entries
                        _ssh_fail_tracker[ip] = [
                            t for t in _ssh_fail_tracker[ip]
                            if now - t < SSH_BRUTE_FORCE_WINDOW_S
                        ]
                        count = len(_ssh_fail_tracker[ip])
                        if count > SSH_BRUTE_FORCE_COUNT:
                            evaluate_rules("ssh_brute_force", {
                                "source_ip": ip,
                                "count": count,
                            })

                # Prune empty trackers
                empty = [ip for ip, ts in _ssh_fail_tracker.items() if not ts]
                for ip in empty:
                    del _ssh_fail_tracker[ip]

            # Store auth events in DB
            if new_events:
                now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    conn = get_db()
                    for evt in new_events:
                        # Compute count_window_10s for ssh_fail
                        count_10s = 1
                        if evt["event_type"] == "ssh_fail" and evt["source_ip"]:
                            with _ssh_fail_lock:
                                count_10s = len(_ssh_fail_tracker.get(evt["source_ip"], []))

                        conn.execute("""
                            INSERT INTO auth_events
                            (timestamp, event_type, username, source_ip, details, count_window_10s)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (now_ts, evt["event_type"], evt["username"],
                              evt["source_ip"], evt["details"], count_10s))
                    conn.commit()
                except Exception as e:
                    _log(f"auth_monitor DB insert error: {e}")

        except Exception as e:
            _log(f"auth_monitor error: {e}")

        time.sleep(INTERVAL_AUTH_MONITOR)


# ═══════════════════════════════════════════
# Collector: DNS Monitor
# ═══════════════════════════════════════════

def dns_collector():
    """Monitor DNS activity via systemd-resolved statistics and syslog."""
    _log("dns_collector started (interval={}s)".format(INTERVAL_DNS))

    # DGA-like TLDs (common in algorithmically generated domains)
    _dga_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
                 ".pw", ".cc", ".su", ".ws", ".info", ".biz", ".work", ".date"}

    while True:
        try:
            # Method 1: resolvectl statistics (may need privileges)
            try:
                out = subprocess.check_output(
                    ["resolvectl", "statistics"],
                    stderr=subprocess.DEVNULL, text=True, timeout=5,
                )
                # Parse DNS stats
                cache_size = 0
                queries = 0
                for line in out.split("\n"):
                    if "Current Cache Size" in line:
                        cache_size = int(line.split(":")[1].strip())
                    if "Transactions" in line or "Total Queries" in line:
                        try:
                            queries = int(line.split(":")[1].strip().split()[0])
                        except Exception:
                            pass
            except Exception:
                pass

            # Method 2: Grep syslog for resolved DNS queries
            try:
                out = subprocess.check_output(
                    ["grep", "-a", "systemd-resolved.*question.*IN", "/var/log/syslog"],
                    text=True, timeout=10, stderr=subprocess.DEVNULL,
                )
                # only last 100 lines
                lines = out.strip().split("\n")[-100:]
                domains_seen = set()
                for line in lines:
                    # Try to extract domain name
                    domain_match = re.search(r'question.*?IN\s+(\S+)', line)
                    if not domain_match:
                        domain_match = re.search(r'(\S+\.\S{2,})\s', line)
                    if domain_match:
                        domain = domain_match.group(1).rstrip(".").lower()
                        if domain and domain not in domains_seen and len(domain) > 3:
                            domains_seen.add(domain)

                            # Calculate entropy
                            # Get the domain without TLD for entropy
                            bare_domain = domain.rsplit(".", 1)[0] if "." in domain else domain
                            entropy = normalized_entropy(bare_domain)

                            # Check for DGA indicators
                            is_dga = 0
                            if entropy > DGA_ENTROPY_THRESHOLD:
                                is_dga = 1

                            # Also check label count (many labels = DGA indicator)
                            labels = bare_domain.split(".")
                            if len(labels) > 4:
                                is_dga = 1

                            # Check for suspicious TLDs
                            _, _, tld = domain.rpartition(".")
                            if f".{tld}" in _dga_tlds:
                                is_dga = 1

                            # Store in DB
                            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            try:
                                conn = get_db()
                                conn.execute("""
                                    INSERT INTO dns_events
                                    (timestamp, domain, process_name, pid, entropy_score, is_dga)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                """, (now_ts, domain, "", None, round(entropy, 3), is_dga))
                                conn.commit()
                            except Exception:
                                pass

                            # Fire alert if DGA
                            if is_dga and entropy > DGA_ALERT_THRESHOLD:
                                evaluate_rules("dga", {
                                    "domain": domain,
                                    "entropy_score": round(entropy, 3),
                                    "pid": None,
                                    "process_name": "",
                                })
            except subprocess.CalledProcessError:
                pass  # no matches in grep
            except Exception:
                pass

        except Exception as e:
            _log(f"dns_collector error: {e}")

        time.sleep(INTERVAL_DNS)


# ═══════════════════════════════════════════
# Collector: File Integrity
# ═══════════════════════════════════════════

# Track file modification times for polling fallback
_file_mtimes = {}
_file_mtimes_lock = threading.Lock()
WATCH_TMP_DIR = "/tmp"


def file_integrity_collector():
    """Watch sensitive files for modification using inotify (or polling fallback)."""
    _log("file_integrity_collector started")

    if HAS_INOTIFY:
        _file_integrity_inotify()
    else:
        _file_integrity_polling()


def _file_integrity_polling():
    """Poll mtime for sensitive files every 2 seconds."""
    _log("file_integrity: using polling fallback (inotify_simple not available)")
    global _file_mtimes

    # Seed mtimes
    poll_files = [f for f in SENSITIVE_FILES if not f.endswith("/")]
    with _file_mtimes_lock:
        for f in poll_files:
            try:
                _file_mtimes[f] = os.stat(f).st_mtime
            except Exception:
                _file_mtimes[f] = 0

    while True:
        try:
            with _file_mtimes_lock:
                for f in poll_files:
                    try:
                        mtime = os.stat(f).st_mtime
                        prev = _file_mtimes.get(f, mtime)
                        if mtime > prev:
                            _file_mtimes[f] = mtime
                            # Determine event type
                            evt_type = "modified"
                            if not _file_mtimes.get(f):
                                evt_type = "created"

                            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            try:
                                conn = get_db()
                                conn.execute("""
                                    INSERT INTO file_events (timestamp, event_type, path)
                                    VALUES (?, ?, ?)
                                """, (now_ts, evt_type, f))
                                conn.commit()
                            except Exception:
                                pass

                            _log(f"file_integrity: {evt_type} detected → {f}")
                            evaluate_rules("file_integrity", {
                                "path": f,
                                "event_type": evt_type,
                            })
                    except Exception:
                        pass

            # Also scan /tmp for new executables
            _scan_tmp_executables()

        except Exception as e:
            _log(f"file_integrity error: {e}")

        time.sleep(2)


def _file_integrity_inotify():
    """Use inotify_simple to watch files in real time."""
    _log("file_integrity: using inotify_simple")
    inotify = INotify()
    wd_to_path = {}

    # Watch individual files
    watch_mask = in_flags.MODIFY | in_flags.CLOSE_WRITE | in_flags.MOVED_TO | in_flags.CREATE
    for f in SENSITIVE_FILES:
        if f.endswith("/"):
            # Directory
            try:
                wd = inotify.add_watch(f.rstrip("/"), watch_mask)
                wd_to_path[wd] = f.rstrip("/")
                _log(f"inotify watching dir: {f}")
            except Exception as e:
                _log(f"inotify cannot watch {f}: {e}")
        else:
            # File — watch parent dir for the file name
            try:
                parent = os.path.dirname(f)
                if parent and os.path.isdir(parent):
                    wd = inotify.add_watch(parent, watch_mask)
                    wd_to_path[wd] = parent
                    _log(f"inotify watching: {f} (via {parent})")
            except Exception as e:
                _log(f"inotify cannot watch {f}: {e}")

    while True:
        try:
            # Block with timeout so we can loop
            events = inotify.read(timeout=2000)
            for evt in events:
                watched_dir = wd_to_path.get(evt.wd, "unknown")
                event_path = os.path.join(watched_dir, evt.name) if evt.name else watched_dir

                # Check if this is one of our sensitive files
                is_sensitive = False
                for sf in SENSITIVE_FILES:
                    if sf.endswith("/"):
                        if event_path.startswith(sf.rstrip("/")):
                            is_sensitive = True
                            break
                    elif event_path == sf or event_path.endswith("/" + os.path.basename(sf)):
                        is_sensitive = True
                        break

                if not is_sensitive:
                    continue

                # Map inotify flags to event type
                flag_names = []
                for attr in dir(in_flags):
                    if not attr.startswith("_") and getattr(in_flags, attr) & evt.flags:
                        flag_names.append(attr)
                _log(f"inotify: {event_path} flags={','.join(flag_names)}")

                if "CREATE" in flag_names or "MOVED_TO" in flag_names:
                    evt_type = "created"
                elif "MODIFY" in flag_names or "CLOSE_WRITE" in flag_names:
                    evt_type = "modified"
                elif "DELETE" in flag_names or "MOVED_FROM" in flag_names:
                    evt_type = "deleted"
                else:
                    evt_type = "modified"

                now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                try:
                    conn = get_db()
                    conn.execute("""
                        INSERT INTO file_events (timestamp, event_type, path)
                        VALUES (?, ?, ?)
                    """, (now_ts, evt_type, event_path))
                    conn.commit()
                except Exception:
                    pass

                _log(f"file_integrity: {evt_type} → {event_path}")

                # Alert based on path
                if "sudoers" in event_path:
                    evaluate_rules("sudoers_change", {"path": event_path})
                elif "authorized_keys" in event_path:
                    evaluate_rules("authorized_keys_change", {"path": event_path})
                else:
                    evaluate_rules("file_integrity", {
                        "path": event_path,
                        "event_type": evt_type,
                    })

        except Exception as e:
            _log(f"file_integrity inotify error: {e}")
            time.sleep(2)

    # Also scan /tmp periodically
    _scan_tmp_executables()


def _scan_tmp_executables():
    """Check /tmp for new executable files."""
    try:
        for fname in os.listdir(WATCH_TMP_DIR):
            fpath = os.path.join(WATCH_TMP_DIR, fname)
            try:
                if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                    # Check if it's a known executable type (ELF, script)
                    with open(fpath, "rb") as f:
                        header = f.read(4)
                    if header[:4] == b"\x7fELF" or header[:2] == b"#!":
                        global _file_mtimes
                        mtime = os.stat(fpath).st_mtime
                        prev = _file_mtimes.get(fpath)
                        if prev is None:
                            _file_mtimes[fpath] = mtime
                            _log(f"file_integrity: new executable in /tmp → {fpath}")
                            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            try:
                                conn = get_db()
                                conn.execute("""
                                    INSERT INTO file_events (timestamp, event_type, path)
                                    VALUES (?, ?, ?)
                                """, (now_ts, "created", fpath))
                                conn.commit()
                            except Exception:
                                pass
                            evaluate_rules("file_integrity", {
                                "path": fpath,
                                "event_type": "created",
                            })
            except Exception:
                pass
    except Exception:
        pass


# ═══════════════════════════════════════════
# API helper functions (used by server.py routes)
# ═══════════════════════════════════════════

def get_alerts(hours=24, severity=None, acknowledged=None, limit=200):
    """Query recent alerts with optional filters."""
    try:
        conn = get_db()
        q = "SELECT * FROM alerts WHERE timestamp >= datetime('now', ?) "
        params = [f"-{hours} hours"]
        if severity and severity != "all":
            q += "AND severity = ? "
            params.append(severity)
        if acknowledged is not None:
            q += "AND acknowledged = ? "
            params.append(1 if acknowledged else 0)
        q += "ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        _log(f"get_alerts error: {e}")
        return []


def get_beaconing(hours=3, limit=100):
    """Query recent beaconing events."""
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT * FROM beaconing_events
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp DESC LIMIT ?
        """, (f"-{hours} hours", limit)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        _log(f"get_beaconing error: {e}")
        return []


def get_auth_events(hours=1, event_type=None, limit=200):
    """Query recent auth events with optional type filter."""
    try:
        conn = get_db()
        q = "SELECT * FROM auth_events WHERE timestamp >= datetime('now', ?) "
        params = [f"-{hours} hours"]
        if event_type and event_type != "all":
            q += "AND event_type = ? "
            params.append(event_type)
        q += "ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        _log(f"get_auth_events error: {e}")
        return []


def get_file_events(hours=24, limit=200):
    """Query recent file integrity events."""
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT * FROM file_events
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp DESC LIMIT ?
        """, (f"-{hours} hours", limit)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        _log(f"get_file_events error: {e}")
        return []


# ── Syslog event accessors (delegate to syslog_ingest) ──

def get_syslog_events(host=None, facility=None, limit=100):
    """Query syslog events with optional filters."""
    if not HAS_SYSLOG:
        return []
    try:
        return syslog_ingest.get_events(host=host, facility=facility, limit=limit)
    except Exception as e:
        _log(f"get_syslog_events error: {e}")
        return []


def get_syslog_hosts():
    """Return distinct syslog hosts."""
    if not HAS_SYSLOG:
        return []
    try:
        return syslog_ingest.get_distinct_hosts()
    except Exception as e:
        _log(f"get_syslog_hosts error: {e}")
        return []


def get_syslog_facilities():
    """Return distinct syslog facilities."""
    if not HAS_SYSLOG:
        return []
    try:
        return syslog_ingest.get_distinct_facilities()
    except Exception as e:
        _log(f"get_syslog_facilities error: {e}")
        return []


def get_security_summary():
    """Aggregated security summary for the dashboard."""
    try:
        conn = get_db()

        # Alert counts by severity (last 24h, unacknowledged)
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE acknowledged = 0 AND timestamp >= datetime('now', '-24 hours')
            GROUP BY severity
        """).fetchall()
        severity_counts = {r["severity"]: r["count"] for r in sev_rows}

        # Active beaconing processes (last 3h, confidence > 0.5)
        beacon_rows = conn.execute("""
            SELECT * FROM beaconing_events
            WHERE timestamp >= datetime('now', '-3 hours') AND confidence >= 0.5
            ORDER BY confidence DESC LIMIT 10
        """).fetchall()

        # Recent auth failures (last 1h)
        auth_fail_count = conn.execute("""
            SELECT COUNT(*) as count FROM auth_events
            WHERE timestamp >= datetime('now', '-1 hours') AND event_type = 'ssh_fail'
        """).fetchone()["count"]

        auth_success_count = conn.execute("""
            SELECT COUNT(*) as count FROM auth_events
            WHERE timestamp >= datetime('now', '-1 hours') AND event_type = 'ssh_success'
        """).fetchone()["count"]

        # Recent auth events for display
        recent_auth = conn.execute("""
            SELECT * FROM auth_events
            WHERE timestamp >= datetime('now', '-1 hours')
            ORDER BY timestamp DESC LIMIT 20
        """).fetchall()

        # File events in last hour
        file_event_count = conn.execute("""
            SELECT COUNT(*) as count FROM file_events
            WHERE timestamp >= datetime('now', '-1 hours')
        """).fetchone()["count"]

        recent_file_events = conn.execute("""
            SELECT * FROM file_events
            WHERE timestamp >= datetime('now', '-1 hours')
            ORDER BY timestamp DESC LIMIT 10
        """).fetchall()

        # Top brute force source IPs
        top_ips = conn.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM auth_events
            WHERE timestamp >= datetime('now', '-1 hours') AND event_type = 'ssh_fail'
            GROUP BY source_ip
            HAVING COUNT(*) > 1
            ORDER BY count DESC LIMIT 5
        """).fetchall()

        # Syslog event count (last 1h)
        syslog_count_1h = 0
        if HAS_SYSLOG:
            try:
                syslog_count_1h = syslog_ingest.get_event_count(hours=1)
            except Exception:
                pass

        return {
            "active_alerts": severity_counts,
            "total_active_alerts": sum(severity_counts.values()),
            "beaconing_processes": [dict(r) for r in beacon_rows],
            "auth": {
                "failures_1h": auth_fail_count,
                "successes_1h": auth_success_count,
                "recent_events": [dict(r) for r in recent_auth],
                "top_source_ips": [dict(r) for r in top_ips],
            },
            "file_integrity": {
                "events_1h": file_event_count,
                "recent": [dict(r) for r in recent_file_events],
            },
            "syslog": {
                "events_1h": syslog_count_1h,
            },
            "summary_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    except Exception as e:
        _log(f"get_security_summary error: {e}")
        return {
            "active_alerts": {},
            "total_active_alerts": 0,
            "beaconing_processes": [],
            "auth": {"failures_1h": 0, "successes_1h": 0, "recent_events": [], "top_source_ips": []},
            "file_integrity": {"events_1h": 0, "recent": []},
            "syslog": {"events_1h": 0},
            "summary_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged."""
    try:
        conn = get_db()
        conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        conn.commit()
        return True
    except Exception as e:
        _log(f"acknowledge_alert error: {e}")
        return False


def get_alert_stats(hours=24):
    """Return alert counts grouped by severity and category."""
    try:
        conn = get_db()
        by_severity = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?)
            GROUP BY severity
        """, (f"-{hours} hours",)).fetchall()

        by_category = conn.execute("""
            SELECT category, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?)
            GROUP BY category
        """, (f"-{hours} hours",)).fetchall()

        total = conn.execute("""
            SELECT COUNT(*) as count FROM alerts
            WHERE timestamp >= datetime('now', ?)
        """, (f"-{hours} hours",)).fetchone()["count"]

        return {
            "total": total,
            "by_severity": {r["severity"]: r["count"] for r in by_severity},
            "by_category": {r["category"]: r["count"] for r in by_category},
            "hours": hours,
        }
    except Exception as e:
        _log(f"get_alert_stats error: {e}")
        return {"total": 0, "by_severity": {}, "by_category": {}, "hours": hours}


# ═══════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════

_collector_threads = []
_collectors_running = False


def start_collectors():
    """Start all background collector threads."""
    global _collector_threads, _collectors_running
    if _collectors_running:
        _log("Collectors already running, skipping")
        return

    _collectors_running = True
    _log("═══ DeepSight Detection Engine Starting ═══")
    _log(f"Database: {DB_PATH}")
    _log(f"HAS_INOTIFY: {HAS_INOTIFY}")
    _log(f"HAS_PSUTIL: {HAS_PSUTIL}")

    # Initialize DB (creates tables)
    get_db()

    # Rebuild FTS5 search indexes from existing data
    rebuild_fts_indexes()

    # Start packet sniffer for HTTP/TLS metadata (runs independently)
    _start_packet_sniffer()

    # Start syslog ingestion if available
    if HAS_SYSLOG:
        try:
            syslog_ingest.start_server()
            _log(f"Syslog ingestion started (port: {syslog_ingest.DEFAULT_PORT})")
        except Exception as e:
            _log(f"Syslog ingestion failed to start: {e}")

    # Start threat intel integration if available
    if HAS_THREAT_INTEL:
        try:
            threat_intel.start_collector()
            _log("Threat intel collector started")
        except Exception as e:
            _log(f"Threat intel collector failed to start: {e}")

    collectors = [
        ("process_audit", process_audit_collector),
        ("beaconing", beaconing_collector),
        ("auth_monitor", auth_monitor),
        ("dns", dns_collector),
        ("file_integrity", file_integrity_collector),
    ]

    for name, func in collectors:
        t = threading.Thread(target=func, name=f"deepsight-{name}", daemon=True)
        t.start()
        _collector_threads.append(t)
        _log(f"Started collector: {name}")

    _log("═══ DeepSight Detection Engine Running ═══")


def stop_collectors():
    """Signal collectors to stop (daemon threads will exit on process termination)."""
    global _collectors_running
    _collectors_running = False
    if HAS_SYSLOG:
        try:
            syslog_ingest.stop_server()
        except Exception:
            pass
    _log("Collectors stopping (daemon threads will exit)")


# ═══════════════════════════════════════════
# Standalone test
# ═══════════════════════════════════════════

if __name__ == "__main__":
    print("═══ DeepSight Detection Engine — Standalone Test ═══")
    print(f"Database: {DB_PATH}")
    print(f"HAS_INOTIFY: {HAS_INOTIFY}")
    print(f"HAS_PSUTIL: {HAS_PSUTIL}")

    # Init DB
    conn = get_db()
    print("Database initialized successfully")

    # Test alert creation
    a = create_alert("high", "test", "Test alert — standalone run",
                     description="This is a test alert to verify the module loads correctly",
                     source_ip="127.0.0.1",
                     mitre_tactic="Execution",
                     mitre_technique="T1203",
                     process_pid=9999,
                     process_name="test_process")
    if a:
        print(f"Test alert created: id={a['id']}")
    else:
        print("Test alert duplicate (already exists within 5min)")

    # Test queries
    alerts = get_alerts(hours=1)
    print(f"Alerts in last hour: {len(alerts)}")

    summary = get_security_summary()
    print(f"Security summary: {json.dumps(summary, indent=2, default=str)}")

    stats = get_alert_stats()
    print(f"Alert stats: {json.dumps(stats, indent=2)}")

    # Test entropy calc
    test_domains = ["google.com", "a7fx9k3m2p.xyz", "www.facebook.com"]
    for d in test_domains:
        e = normalized_entropy(d.rsplit(".", 1)[0])
        print(f"Entropy of '{d}': {e:.3f}")

    print("\n═══ Module loaded successfully ═══")
    print("Run server.py to start collectors and API endpoints.")
