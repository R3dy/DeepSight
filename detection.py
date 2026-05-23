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

# ── Sigma rule engine ──
try:
    from sigma_engine import evaluate_sigma, get_sigma_engine
    from routes.v2.detection import update_collector_health as _update_collector_health
    HAS_SIGMA = True
except ImportError:
    HAS_SIGMA = False

    def evaluate_sigma(event):
        return []

    def get_sigma_engine():
        return None

    def _update_collector_health(*args, **kwargs):
        pass

# ── Optional imports ──
HAS_PSUTIL = True
DETECTION_AVAILABLE = True  # set to False by server.py if import fails

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

# ── Alert Grouping Configuration ──
GROUPING_WINDOW_SECONDS = 300       # default grouping window: 5 minutes
AUTO_GROUP_ENABLED = True           # whether auto-grouping is active

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
# MITRE ATT&CK Framework — Tactics & Techniques
# ═══════════════════════════════════════════

# Comprehensive MITRE ATT&CK Enterprise matrix (v15.1).
# Only the most commonly detected techniques are listed here for coverage analysis;
# the full framework has 200+ techniques but this covers the detection-relevant subset.

MITRE_ATTACK_FRAMEWORK = {
    "Reconnaissance": {
        "id": "TA0043",
        "techniques": [
            ("T1595", "Active Scanning"),
            ("T1592", "Gather Victim Host Information"),
            ("T1589", "Gather Victim Identity Information"),
            ("T1590", "Gather Victim Network Information"),
            ("T1591", "Gather Victim Org Information"),
            ("T1598", "Phishing for Information"),
            ("T1597", "Search Closed Sources"),
            ("T1596", "Search Open Technical Databases"),
            ("T1593", "Search Open Websites/Domains"),
            ("T1594", "Search Victim-Owned Websites"),
        ],
    },
    "Resource Development": {
        "id": "TA0042",
        "techniques": [
            ("T1583", "Acquire Infrastructure"),
            ("T1586", "Compromise Accounts"),
            ("T1584", "Compromise Infrastructure"),
            ("T1587", "Develop Capabilities"),
            ("T1585", "Establish Accounts"),
            ("T1588", "Obtain Capabilities"),
            ("T1608", "Stage Capabilities"),
        ],
    },
    "Initial Access": {
        "id": "TA0001",
        "techniques": [
            ("T1189", "Drive-by Compromise"),
            ("T1190", "Exploit Public-Facing Application"),
            ("T1133", "External Remote Services"),
            ("T1200", "Hardware Additions"),
            ("T1566", "Phishing"),
            ("T1091", "Replication Through Removable Media"),
            ("T1195", "Supply Chain Compromise"),
            ("T1199", "Trusted Relationship"),
            ("T1078", "Valid Accounts"),
        ],
    },
    "Execution": {
        "id": "TA0002",
        "techniques": [
            ("T1059", "Command and Scripting Interpreter"),
            ("T1559", "Inter-Process Communication"),
            ("T1204", "User Execution"),
            ("T1047", "Windows Management Instrumentation"),
            ("T1609", "Container Administration Command"),
            ("T1610", "Deploy Container"),
            ("T1053", "Scheduled Task/Job"),
            ("T1129", "Shared Modules"),
        ],
    },
    "Persistence": {
        "id": "TA0003",
        "techniques": [
            ("T1547", "Boot or Logon Autostart Execution"),
            ("T1136", "Create Account"),
            ("T1543", "Create or Modify System Process"),
            ("T1505", "Server Software Component"),
            ("T1053", "Scheduled Task/Job"),
            ("T1078", "Valid Accounts"),
            ("T1525", "Implant Internal Image"),
        ],
    },
    "Privilege Escalation": {
        "id": "TA0004",
        "techniques": [
            ("T1548", "Abuse Elevation Control Mechanism"),
            ("T1134", "Access Token Manipulation"),
            ("T1547", "Boot or Logon Autostart Execution"),
            ("T1053", "Scheduled Task/Job"),
            ("T1068", "Exploitation for Privilege Escalation"),
            ("T1078", "Valid Accounts"),
        ],
    },
    "Defense Evasion": {
        "id": "TA0005",
        "techniques": [
            ("T1548", "Abuse Elevation Control Mechanism"),
            ("T1140", "Deobfuscate/Decode Files or Information"),
            ("T1222", "File and Directory Permissions Modification"),
            ("T1564", "Hide Artifacts"),
            ("T1070", "Indicator Removal"),
            ("T1036", "Masquerading"),
            ("T1556", "Modify Authentication Process"),
            ("T1027", "Obfuscated Files or Information"),
            ("T1055", "Process Injection"),
            ("T1218", "System Binary Proxy Execution"),
            ("T1202", "Indirect Command Execution"),
        ],
    },
    "Credential Access": {
        "id": "TA0006",
        "techniques": [
            ("T1110", "Brute Force"),
            ("T1555", "Credentials from Password Stores"),
            ("T1212", "Exploitation for Credential Access"),
            ("T1056", "Input Capture"),
            ("T1557", "Man-in-the-Middle"),
            ("T1040", "Network Sniffing"),
            ("T1003", "OS Credential Dumping"),
            ("T1528", "Steal Application Access Token"),
            ("T1539", "Steal Web Session Cookie"),
            ("T1111", "Multi-Factor Authentication Interception"),
        ],
    },
    "Discovery": {
        "id": "TA0007",
        "techniques": [
            ("T1087", "Account Discovery"),
            ("T1010", "Application Window Discovery"),
            ("T1083", "File and Directory Discovery"),
            ("T1046", "Network Service Discovery"),
            ("T1135", "Network Share Discovery"),
            ("T1069", "Permission Groups Discovery"),
            ("T1057", "Process Discovery"),
            ("T1018", "Remote System Discovery"),
            ("T1518", "Software Discovery"),
            ("T1082", "System Information Discovery"),
            ("T1016", "System Network Configuration Discovery"),
            ("T1049", "System Network Connections Discovery"),
            ("T1033", "System Owner/User Discovery"),
            ("T1124", "System Time Discovery"),
        ],
    },
    "Lateral Movement": {
        "id": "TA0008",
        "techniques": [
            ("T1210", "Exploitation of Remote Services"),
            ("T1534", "Internal Spearphishing"),
            ("T1021", "Remote Services"),
            ("T1091", "Replication Through Removable Media"),
            ("T1080", "Taint Shared Content"),
            ("T1550", "Use Alternate Authentication Material"),
        ],
    },
    "Collection": {
        "id": "TA0009",
        "techniques": [
            ("T1560", "Archive Collected Data"),
            ("T1119", "Automated Collection"),
            ("T1005", "Data from Local System"),
            ("T1039", "Data from Network Shared Drive"),
            ("T1025", "Data from Removable Media"),
            ("T1074", "Data Staged"),
            ("T1114", "Email Collection"),
            ("T1056", "Input Capture"),
            ("T1213", "Data from Information Repositories"),
        ],
    },
    "Command and Control": {
        "id": "TA0011",
        "techniques": [
            ("T1071", "Application Layer Protocol"),
            ("T1092", "Communication Through Removable Media"),
            ("T1132", "Data Encoding"),
            ("T1001", "Data Obfuscation"),
            ("T1568", "Dynamic Resolution"),
            ("T1573", "Encrypted Channel"),
            ("T1008", "Fallback Channels"),
            ("T1105", "Ingress Tool Transfer"),
            ("T1104", "Multi-Stage Channels"),
            ("T1095", "Non-Application Layer Protocol"),
            ("T1571", "Non-Standard Port"),
            ("T1572", "Protocol Tunneling"),
            ("T1090", "Proxy"),
            ("T1219", "Remote Access Software"),
            ("T1205", "Traffic Signaling"),
            ("T1102", "Web Service"),
        ],
    },
    "Exfiltration": {
        "id": "TA0010",
        "techniques": [
            ("T1020", "Automated Exfiltration"),
            ("T1030", "Data Transfer Size Limits"),
            ("T1048", "Exfiltration Over Alternative Protocol"),
            ("T1041", "Exfiltration Over C2 Channel"),
            ("T1011", "Exfiltration Over Other Network Medium"),
            ("T1052", "Exfiltration Over Physical Medium"),
            ("T1567", "Exfiltration Over Web Service"),
            ("T1029", "Scheduled Transfer"),
        ],
    },
    "Impact": {
        "id": "TA0040",
        "techniques": [
            ("T1531", "Account Access Removal"),
            ("T1485", "Data Destruction"),
            ("T1486", "Data Encrypted for Impact"),
            ("T1565", "Data Manipulation"),
            ("T1491", "Defacement"),
            ("T1561", "Disk Wipe"),
            ("T1499", "Endpoint Denial of Service"),
            ("T1495", "Firmware Corruption"),
            ("T1490", "Inhibit System Recovery"),
            ("T1498", "Network Denial of Service"),
            ("T1496", "Resource Hijacking"),
            ("T1489", "Service Stop"),
            ("T1529", "System Shutdown/Reboot"),
        ],
    },
}


def _collect_mitre_techniques_from_rules():
    """Collect all MITRE technique IDs referenced by enabled detection rules.

    Sources:
    1. Sigma rules (from sigma_engine) — primary detection rule source
    2. Historical alerts — techniques that have generated alerts
    3. Known built-in rule techniques — extracted from detection.py code patterns
    """
    covered = {}  # technique_id -> {"rules": [rule_names], "tactic": tactic_name}

    # Helper: parse technique ID from various formats
    def parse_tech_id(raw):
        """Extract technique ID like T1059 from formats like 'T1059', 'T1059.001', 'T1059 (Command...)'."""
        if not raw:
            return None
        m = re.match(r'(T\d{4})(?:\.\d{3})?', str(raw).strip())
        return m.group(1) if m else None

    # ── Sigma rules (primary source) ──
    try:
        if HAS_SIGMA:
            engine = get_sigma_engine()
            for rule in engine.get_all_rules():
                if not rule.get("enabled", True):
                    continue
                rule_name = rule.get("title", rule.get("id", "unknown"))
                rule_tactics = rule.get("mitre_tactics", [])
                for tech_raw in rule.get("mitre_techniques", []):
                    tech = parse_tech_id(tech_raw)
                    if tech:
                        if tech not in covered:
                            covered[tech] = {"rules": [], "tactic": rule_tactics[0] if rule_tactics else "Unknown"}
                        if rule_name not in covered[tech]["rules"]:
                            covered[tech]["rules"].append(rule_name)
    except Exception as e:
        _log(f"MITRE coverage: error collecting sigma techniques: {e}")

    # ── Historical alerts (shows which techniques have actually fired) ──
    try:
        conn = get_db()
        rows = conn.execute("""
            SELECT DISTINCT mitre_technique, mitre_tactic
            FROM alerts
            WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
            LIMIT 500
        """).fetchall()
        for row in rows:
            tech = parse_tech_id(row["mitre_technique"])
            if tech and tech not in covered:
                covered[tech] = {
                    "rules": ["built-in detection rule"],
                    "tactic": row["mitre_tactic"] or "Unknown",
                }
    except Exception as e:
        _log(f"MITRE coverage: error collecting alert techniques: {e}")

    return covered


def get_attack_coverage():
    """Return MITRE ATT&CK coverage data: all techniques, coverage status,
    percentages per tactic, rule mappings, and gap analysis.

    Returns a dict suitable for the /api/attack-coverage endpoint.
    """
    try:
        covered = _collect_mitre_techniques_from_rules()

        tactics = []
        total_techniques = 0
        total_covered = 0

        for tactic_name, tactic_data in MITRE_ATTACK_FRAMEWORK.items():
            techniques = []
            tactic_covered = 0
            for tech_id, tech_name in tactic_data["techniques"]:
                is_covered = tech_id in covered
                rules = covered.get(tech_id, {}).get("rules", [])
                if is_covered:
                    tactic_covered += 1
                techniques.append({
                    "id": tech_id,
                    "name": tech_name,
                    "covered": is_covered,
                    "rules": rules,
                })

            technique_count = len(techniques)
            coverage_pct = round(tactic_covered / technique_count * 100, 1) if technique_count > 0 else 0
            total_techniques += technique_count
            total_covered += tactic_covered

            tactics.append({
                "tactic": tactic_name,
                "tactic_id": tactic_data["id"],
                "techniques": techniques,
                "technique_count": technique_count,
                "covered_count": tactic_covered,
                "uncovered_count": technique_count - tactic_covered,
                "coverage_pct": coverage_pct,
            })

        overall_pct = round(total_covered / total_techniques * 100, 1) if total_techniques > 0 else 0

        # ── Gap Analysis: uncovered techniques with recommendations ──
        gaps = []
        for tactic in tactics:
            for t in tactic["techniques"]:
                if not t["covered"]:
                    gaps.append({
                        "technique_id": t["id"],
                        "technique_name": t["name"],
                        "tactic": tactic["tactic"],
                        "tactic_id": tactic["tactic_id"],
                        "recommendation": _get_coverage_recommendation(t["id"], t["name"], tactic["tactic"]),
                    })

        return {
            "tactics": tactics,
            "gaps": gaps,
            "overall_coverage_pct": overall_pct,
            "total_techniques": total_techniques,
            "total_covered": total_covered,
            "total_uncovered": total_techniques - total_covered,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    except Exception as e:
        _log(f"get_attack_coverage error: {e}")
        return {
            "tactics": [],
            "gaps": [],
            "overall_coverage_pct": 0,
            "total_techniques": 0,
            "total_covered": 0,
            "total_uncovered": 0,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


def _get_coverage_recommendation(tech_id, tech_name, tactic):
    """Get a human-readable recommendation for covering an un-covered technique."""
    recs = {
        "T1595": "Deploy network scanning detection rules to alert on port scans and service enumeration.",
        "T1592": "Monitor for commands that enumerate system information (hostname, uname, /proc/cpuinfo reads).",
        "T1190": "Ensure web server logs are monitored for exploit attempts; enable WAF rules in Sigma format.",
        "T1566": "Deploy email gateway logs to the SIEM; create Sigma rules for suspicious attachment types.",
        "T1078": "Monitor for unusual login patterns: off-hours access, impossible travel, new IPs per user.",
        "T1548": "Track sudo usage and privilege escalation attempts via auth logs.",
        "T1055": "Enable auditd monitoring for ptrace and process injection syscalls.",
        "T1027": "Deploy file entropy analysis to detect obfuscated/packed binaries.",
        "T1555": "Monitor access to shadow files, password stores, and credential files.",
        "T1003": "Watch for access to /etc/shadow, memory dump tools, and mimikatz-like behavior.",
        "T1040": "Monitor for promiscuous mode interfaces; detect tcpdump/wireshark execution.",
        "T1210": "Monitor for lateral movement via SSH, WinRM, or SMB connection patterns.",
        "T1021": "Track SSH/RDP connection chains; alert on unusual lateral movement patterns.",
        "T1485": "Monitor for mass file deletion, shred/wipe commands, and filesystem destruction.",
        "T1486": "Detect ransomware-like behavior: rapid file encryption, ransom note creation.",
        "T1498": "Monitor for volumetric network traffic anomalies and DDoS patterns.",
        "T1496": "Detect cryptominer processes via CPU usage patterns and known mining pools.",
    }
    if tech_id in recs:
        return recs[tech_id]

    # Generic recommendation by tactic
    tactic_recs = {
        "Reconnaissance": f"Create Sigma rules to detect {tech_name} ({tech_id}) activity via network and host telemetry.",
        "Resource Development": f"Monitor for infrastructure staging indicators related to {tech_name} ({tech_id}).",
        "Initial Access": f"Deploy detection rules for {tech_name} ({tech_id}) — review auth and web server logs.",
        "Execution": f"Monitor process creation events for {tech_name} ({tech_id}) patterns using auditd or eBPF.",
        "Persistence": f"Watch for {tech_name} ({tech_id}) by monitoring startup scripts, crontabs, and systemd units.",
        "Privilege Escalation": f"Track {tech_name} ({tech_id}) via sudo logs, kernel audit, and setuid binary monitoring.",
        "Defense Evasion": f"Detect {tech_name} ({tech_id}) via file integrity monitoring and syscall auditing.",
        "Credential Access": f"Monitor access to credential stores and auth subsystems for {tech_name} ({tech_id}).",
        "Discovery": f"Alert on {tech_name} ({tech_id}) reconnaissance commands via process monitoring.",
        "Lateral Movement": f"Track {tech_name} ({tech_id}) by analyzing SSH/RDP connection graphs and timing patterns.",
        "Collection": f"Monitor for {tech_name} ({tech_id}) data staging and collection activity on sensitive hosts.",
        "Command and Control": f"Deploy network-based detection for {tech_name} ({tech_id}) C2 patterns and beaconing.",
        "Exfiltration": f"Monitor outbound network traffic volume and destinations for {tech_name} ({tech_id}).",
        "Impact": f"Create detection rules for {tech_name} ({tech_id}) destructive behavior and impact indicators.",
    }
    return tactic_recs.get(tactic, f"Consider adding detection coverage for {tech_name} ({tech_id}).")


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
    _migrate_correlation_schema(conn)
    _migrate_incident_schema(conn)
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


def _migrate_correlation_schema(conn):
    """Create correlation_matches table if it doesn't exist (safe migration)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS correlation_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id TEXT NOT NULL,
            chain_name TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT NOT NULL DEFAULT (datetime('now')),
            steps_json TEXT DEFAULT '[]',
            severity TEXT NOT NULL DEFAULT 'high'
        );

        CREATE INDEX IF NOT EXISTS idx_correlation_timestamp
            ON correlation_matches(completed_at);
        CREATE INDEX IF NOT EXISTS idx_correlation_host
            ON correlation_matches(host);
        CREATE INDEX IF NOT EXISTS idx_correlation_chain
            ON correlation_matches(chain_id);
    """)


def _migrate_incident_schema(conn):
    """Create incidents and incident_alerts tables for alert grouping (safe migration)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium'
                CHECK(severity IN ('critical','high','medium','low')),
            status TEXT NOT NULL DEFAULT 'new'
                CHECK(status IN ('new','investigating','escalated','resolved','closed')),
            source_host TEXT DEFAULT '',
            mitre_technique TEXT DEFAULT '',
            grouping_window_s INTEGER DEFAULT 300,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            resolved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS incident_alerts (
            incident_id INTEGER NOT NULL,
            alert_id INTEGER NOT NULL,
            added_at TEXT NOT NULL DEFAULT (datetime('now')),
            auto_grouped INTEGER DEFAULT 0,
            PRIMARY KEY (incident_id, alert_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_status
            ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_host
            ON incidents(source_host);
        CREATE INDEX IF NOT EXISTS idx_incidents_created
            ON incidents(created_at);
        CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident
            ON incident_alerts(incident_id);
        CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert
            ON incident_alerts(alert_id);
    """)


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
            for proc in _psutil.process_iter(["pid", "name", "cmdline", "username", "memory_info"]):
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


# ── SocketIO callback (set by server.py after import) ──
_socketio = None


def set_socketio(sio):
    """Register a SocketIO instance for real-time event emission."""
    global _socketio
    _socketio = sio


def _emit_alert_socketio(alert_dict):
    """Emit a new_alert event via SocketIO if available."""
    if _socketio is None:
        return
    try:
        _socketio.emit('new_alert', alert_dict)
    except Exception:
        pass  # best-effort; don't break alert creation


def _correlate_alert(alert_dict):
    """Feed a newly created alert into the correlation engine if available."""
    try:
        engine = get_correlation_engine()
        engine.process_alert(alert_dict)
    except Exception:
        pass  # correlation is best-effort, don't break alert creation


def _group_alert(alert_dict):
    """Feed a newly created alert into the alert grouper if available and auto-group is enabled."""
    if not AUTO_GROUP_ENABLED:
        return
    try:
        grouper = get_alert_grouper()
        grouper.process_alert(alert_dict)
    except Exception:
        pass  # grouping is best-effort, don't break alert creation


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
        # Feed to correlation engine (non-blocking, thread-safe)
        _correlate_alert(alert_dict)
        # Feed to alert grouper for incident grouping
        _group_alert(alert_dict)
        # Emit via SocketIO for real-time frontend updates
        _emit_alert_socketio(alert_dict)
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

    # ── Run Sigma rule evaluation against this event ──
    if HAS_SIGMA:
        try:
            # Normalize event field names for Sigma compatibility
            sigma_event = dict(data)
            # Map common field name variations
            _FIELD_ALIASES = {
                'cmdline': 'CommandLine',
                'process_name': 'Image',
                'exe_path': 'Image',
                'image': 'Image',
                'command_line': 'CommandLine',
            }
            for src, dst in _FIELD_ALIASES.items():
                if src in sigma_event and dst not in sigma_event:
                    sigma_event[dst] = sigma_event[src]
            # Ensure event_type is set for logsource filtering
            if 'event_type' not in sigma_event:
                sigma_event['event_type'] = event_type
            sigma_matches = evaluate_sigma(sigma_event)
            for match in sigma_matches:
                a = create_alert(
                    severity=match.get('severity', 'medium'),
                    category=match.get('category', 'sigma'),
                    title=match.get('title', 'Sigma Rule Match'),
                    description=match.get('description', ''),
                    source_ip=data.get('source_ip', ''),
                    source_host=data.get('source_host', ''),
                    mitre_tactic=match.get('mitre_tactic', ''),
                    mitre_technique=match.get('mitre_technique', ''),
                    process_pid=data.get('pid'),
                    process_name=data.get('process_name', ''),
                    raw_data=match.get('raw_data', {}),
                )
                if a:
                    alerts.append(a)
        except Exception:
            pass  # Sigma evaluation is best-effort

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
    if HAS_SIGMA:
        _update_collector_health('process_audit', 'running')

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
    except Exception:
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
    if HAS_SIGMA:
        _update_collector_health('beaconing', 'running')

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
    if HAS_SIGMA:
        _update_collector_health('auth_monitor', 'running')
    AUTH_LOG = "/var/log/auth.log"

    # Check access
    if not os.access(AUTH_LOG, os.R_OK):
        _log(f"auth_monitor: cannot read {AUTH_LOG} — skipping")
        return

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
    if HAS_SIGMA:
        _update_collector_health('dns', 'running')

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
                for line in out.split("\n"):
                    if "Current Cache Size" in line:
                        pass
                    if "Transactions" in line or "Total Queries" in line:
                        try:
                            pass
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
    if HAS_SIGMA:
        _update_collector_health('file_integrity', 'running')

    if HAS_INOTIFY:
        _file_integrity_inotify()
    else:
        _file_integrity_polling()


def _file_integrity_polling():
    """Poll mtime for sensitive files every 2 seconds."""
    _log("file_integrity: using polling fallback (inotify_simple not available)")

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

def get_alerts(hours=24, severity=None, acknowledged=None, host=None,
               category=None, since=None, limit=200):
    """Query recent alerts with optional filters.

    Parameters:
        hours: lookback in hours (ignored if since is provided)
        severity: filter by severity level
        acknowledged: None=all, True=ack'd, False=unack'd
        host: filter by source_host or source_ip
        category: filter by alert category
        since: ISO timestamp string for absolute time-range start
        limit: max results
    """
    try:
        conn = get_db()
        q = "SELECT * FROM alerts WHERE 1=1 "
        params = []

        if since:
            q += "AND timestamp >= ? "
            params.append(since)
        else:
            q += "AND timestamp >= datetime('now', ?) "
            params.append(f"-{hours} hours")

        if severity and severity != "all":
            q += "AND severity = ? "
            params.append(severity)
        if acknowledged is not None:
            q += "AND acknowledged = ? "
            params.append(1 if acknowledged else 0)
        if host:
            q += "AND (source_host = ? OR source_ip = ?) "
            params.extend([host, host])
        if category:
            q += "AND category = ? "
            params.append(category)
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


def get_auth_events(hours=1, event_type=None, since=None, limit=200):
    """Query recent auth events with optional type filter and time range."""
    try:
        conn = get_db()
        q = "SELECT * FROM auth_events WHERE 1=1 "
        params = []
        if since:
            q += "AND timestamp >= ? "
            params.append(since)
        else:
            q += "AND timestamp >= datetime('now', ?) "
            params.append(f"-{hours} hours")
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


def get_file_events(hours=24, path=None, limit=200):
    """Query recent file integrity events with optional path filter."""
    try:
        conn = get_db()
        q = "SELECT * FROM file_events WHERE timestamp >= datetime('now', ?) "
        params = [f"-{hours} hours"]
        if path:
            q += "AND path LIKE ? "
            params.append(f"%{path}%")
        q += "ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
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


def get_dashboard_data(hours=24):
    """Return aggregated data for security dashboard Chart.js panels.

    Returns 6 data sets:
      - alert_timeline: hourly alert counts by severity for line chart
      - top_source_ips: most frequent source IPs for horizontal bar chart
      - mitre_tactics: MITRE ATT&CK tactic counts for radar chart
      - alert_severity: severity distribution for doughnut chart
      - event_type_distribution: breakdown by event type for bar chart
      - agent_health: placeholder — filled by server.py from HOSTS
    """
    try:
        conn = get_db()

        # ── Alert Timeline (hourly buckets, last N hours) ──
        timeline_rows = conn.execute("""
            SELECT
                strftime('%H', timestamp) as hour_bucket,
                strftime('%Y-%m-%d %H', timestamp) as hour_label,
                severity,
                COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?)
            GROUP BY hour_label, severity
            ORDER BY hour_label ASC
        """, (f"-{hours} hours",)).fetchall()

        # Build timeline: {hour_label: {severity: count}}
        timeline = {}
        for r in timeline_rows:
            label = r["hour_label"]
            if label not in timeline:
                timeline[label] = {}
            timeline[label][r["severity"]] = r["count"]

        sorted_labels = sorted(timeline.keys())
        alert_timeline = {
            "labels": sorted_labels,
            "critical": [timeline.get(h, {}).get("critical", 0) for h in sorted_labels],
            "high": [timeline.get(h, {}).get("high", 0) for h in sorted_labels],
            "medium": [timeline.get(h, {}).get("medium", 0) for h in sorted_labels],
            "low": [timeline.get(h, {}).get("low", 0) for h in sorted_labels],
            "info": [timeline.get(h, {}).get("info", 0) for h in sorted_labels],
            "total": sum(
                timeline.get(h, {}).get(sev, 0)
                for h in sorted_labels
                for sev in ("critical", "high", "medium", "low", "info")
            ),
        }

        # ── Top Source IPs (across auth_events and alerts) ──
        # From auth_events
        auth_ips = conn.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM auth_events
            WHERE timestamp >= datetime('now', ?) AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
        """, (f"-{hours} hours",)).fetchall()

        # From alerts
        alert_ips = conn.execute("""
            SELECT source_ip, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?) AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip
        """, (f"-{hours} hours",)).fetchall()

        # Merge IP counts
        ip_counts = {}
        for r in auth_ips:
            ip = r["source_ip"]
            ip_counts[ip] = ip_counts.get(ip, 0) + r["count"]
        for r in alert_ips:
            ip = r["source_ip"]
            ip_counts[ip] = ip_counts.get(ip, 0) + r["count"]

        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_source_ips = {
            "labels": [ip for ip, _ in top_ips],
            "counts": [count for _, count in top_ips],
            "total": sum(count for _, count in top_ips),
        }

        # ── MITRE ATT&CK Tactic Distribution ──
        mitre_rows = conn.execute("""
            SELECT mitre_tactic, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?)
              AND mitre_tactic IS NOT NULL AND mitre_tactic != ''
            GROUP BY mitre_tactic
            ORDER BY count DESC
        """, (f"-{hours} hours",)).fetchall()

        mitre_labels = [r["mitre_tactic"] for r in mitre_rows]
        mitre_counts = [r["count"] for r in mitre_rows]
        mitre_tactics = {
            "labels": mitre_labels,
            "counts": mitre_counts,
            "total": sum(mitre_counts),
        }

        # ── Alert Severity Distribution ──
        sev_rows = conn.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?)
            GROUP BY severity
        """, (f"-{hours} hours",)).fetchall()

        sev_labels = [r["severity"] for r in sev_rows]
        sev_counts_list = [r["count"] for r in sev_rows]
        alert_severity = {
            "labels": sev_labels,
            "counts": sev_counts_list,
            "total": sum(sev_counts_list),
        }

        # ── Event Type Distribution ──
        event_counts = {}

        # Alert types by category
        cat_rows = conn.execute("""
            SELECT category, COUNT(*) as count
            FROM alerts
            WHERE timestamp >= datetime('now', ?)
            GROUP BY category
        """, (f"-{hours} hours",)).fetchall()
        for r in cat_rows:
            event_counts[f"Alert: {r['category'] or 'uncategorized'}"] = r["count"]

        # Auth event counts
        auth_total = conn.execute("""
            SELECT COUNT(*) as count FROM auth_events
            WHERE timestamp >= datetime('now', ?)
        """, (f"-{hours} hours",)).fetchone()["count"]
        if auth_total > 0:
            event_counts["Auth Events"] = auth_total

        # File event counts
        file_total = conn.execute("""
            SELECT COUNT(*) as count FROM file_events
            WHERE timestamp >= datetime('now', ?)
        """, (f"-{hours} hours",)).fetchone()["count"]
        if file_total > 0:
            event_counts["File Events"] = file_total

        # Beaconing count
        beacon_total = conn.execute("""
            SELECT COUNT(*) as count FROM beaconing_events
            WHERE timestamp >= datetime('now', ?)
        """, (f"-{hours} hours",)).fetchone()["count"]
        if beacon_total > 0:
            event_counts["Beaconing"] = beacon_total

        event_type_distribution = {
            "labels": list(event_counts.keys()),
            "counts": list(event_counts.values()),
            "total": sum(event_counts.values()),
        }

        return {
            "alert_timeline": alert_timeline,
            "top_source_ips": top_source_ips,
            "mitre_tactics": mitre_tactics,
            "alert_severity": alert_severity,
            "event_type_distribution": event_type_distribution,
            "agent_health": None,  # filled by server.py
            "hours": hours,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    except Exception as e:
        _log(f"get_dashboard_data error: {e}")
        return {
            "alert_timeline": {"labels": [], "critical": [], "high": [], "medium": [], "low": [], "info": [], "total": 0},
            "top_source_ips": {"labels": [], "counts": [], "total": 0},
            "mitre_tactics": {"labels": [], "counts": [], "total": 0},
            "alert_severity": {"labels": [], "counts": [], "total": 0},
            "event_type_distribution": {"labels": [], "counts": [], "total": 0},
            "agent_health": None,
            "hours": hours,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


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
# UEBA — User & Entity Behavior Analytics
# ═══════════════════════════════════════════

BASELINE_WINDOW_SECONDS = 3600   # 1 hour rolling window
BASELINE_LEARNING_SAMPLES = 30   # no alerts until N samples collected
BASELINE_COLLECT_INTERVAL = 30   # seconds between baseline samples
BASELINE_Z_THRESHOLD = 3.0       # default z-score alert threshold

# Per-metric thresholds (some metrics are naturally more volatile)
BASELINE_Z_THRESHOLDS = {
    "cpu_percent": 3.0,
    "ram_used_gb": 3.5,
    "disk_read_kbps": 4.0,
    "disk_write_kbps": 4.0,
    "network_connections": 3.5,
    "process_count": 3.0,
}

# Human-readable metric labels
BASELINE_METRIC_LABELS = {
    "cpu_percent": "CPU %",
    "ram_used_gb": "RAM Used (GB)",
    "disk_read_kbps": "Disk Read (KB/s)",
    "disk_write_kbps": "Disk Write (KB/s)",
    "network_connections": "Network Connections",
    "process_count": "Process Count",
}

# Tracked metrics — list of (key, description) for the collector
BASELINE_METRICS = [
    "cpu_percent",
    "ram_used_gb",
    "disk_read_kbps",
    "disk_write_kbps",
    "network_connections",
    "process_count",
]


class BaselineEngine:
    """Rolling z-score statistical baselining via batch recomputation.

    Maintains per-host rolling statistics for key system metrics.
    Uses a deque of recent samples (pruned to BASELINE_WINDOW_SECONDS)
    to compute mean and standard deviation on each update.
    """

    def __init__(self, db_conn):
        self.db = db_conn
        # samples[host][metric] = [(timestamp, value), ...]
        self.samples = defaultdict(lambda: defaultdict(list))
        self.lock = threading.Lock()
        self._create_tables()
        self._prune_old_anomalies()

    def _create_tables(self):
        """Create baselines and anomalies tables."""
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS baselines (
                host TEXT NOT NULL,
                metric TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                mean REAL DEFAULT 0.0,
                variance REAL DEFAULT 0.0,
                stddev REAL DEFAULT 0.0,
                last_value REAL DEFAULT 0.0,
                is_learning INTEGER DEFAULT 1,
                last_updated TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (host, metric)
            );

            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                host TEXT NOT NULL,
                metric TEXT NOT NULL,
                z_score REAL NOT NULL,
                current_value REAL NOT NULL,
                mean REAL NOT NULL,
                stddev REAL NOT NULL,
                severity TEXT DEFAULT 'medium'
            );

            CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp
                ON anomalies(timestamp);
            CREATE INDEX IF NOT EXISTS idx_anomalies_host
                ON anomalies(host);
            CREATE INDEX IF NOT EXISTS idx_baselines_host
                ON baselines(host);
        """)
        self.db.commit()

    def _prune_old_anomalies(self):
        """Remove anomalies older than 7 days."""
        try:
            self.db.execute(
                "DELETE FROM anomalies WHERE timestamp < datetime('now', '-7 days')"
            )
            self.db.commit()
        except Exception:
            pass

    def update(self, host, metric, value, timestamp=None):
        """Add a sample and return (z_score, mean, stddev, is_learning).

        Returns None if insufficient data (< 2 samples in window).
        """
        if timestamp is None:
            timestamp = time.time()

        with self.lock:
            samples = self.samples[host][metric]
            samples.append((timestamp, float(value)))

            # Prune samples outside the rolling window
            cutoff = timestamp - BASELINE_WINDOW_SECONDS
            samples[:] = [(ts, v) for ts, v in samples if ts > cutoff]

            count = len(samples)
            if count < 2:
                self._save_state(host, metric, count, value, 0, 0, value, timestamp, True)
                return None

            # Compute mean and stddev from window samples
            vals = [v for _, v in samples]
            mean = sum(vals) / count
            variance = sum((v - mean) ** 2 for v in vals) / count

            # Guard on variance (not stddev) to avoid false positives on stable data.
            # When variance is near-zero, there is no real deviation — force z=0.
            if variance > 1e-9:
                stddev = math.sqrt(variance)
                z_score = (float(value) - mean) / stddev
            else:
                stddev = 0.0
                z_score = 0.0

            is_learning = count < BASELINE_LEARNING_SAMPLES

            # Persist to DB
            self._save_state(host, metric, count, mean, variance, stddev, value,
                             timestamp, is_learning)

            return (z_score, mean, stddev, is_learning)

    def _save_state(self, host, metric, count, mean, variance, stddev, last_value,
                    timestamp, is_learning):
        """Persist baseline state to SQLite (idempotent upsert)."""
        try:
            now_ts = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            self.db.execute("""
                INSERT INTO baselines (host, metric, count, mean, variance, stddev,
                                       last_value, is_learning, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host, metric) DO UPDATE SET
                    count = excluded.count,
                    mean = excluded.mean,
                    variance = excluded.variance,
                    stddev = excluded.stddev,
                    last_value = excluded.last_value,
                    is_learning = excluded.is_learning,
                    last_updated = excluded.last_updated
            """, (host, metric, count, mean, variance, stddev,
                  last_value, 1 if is_learning else 0, now_ts))
            self.db.commit()
        except Exception as e:
            _log(f"BaselineEngine _save_state error: {e}")

    def check_and_alert(self, host, metric, z_score, current_value, mean, stddev,
                        is_learning):
        """Fire an alert if z-score exceeds threshold and not in learning period."""
        if is_learning or z_score is None:
            return None

        threshold = BASELINE_Z_THRESHOLDS.get(metric, BASELINE_Z_THRESHOLD)
        if abs(z_score) < threshold:
            return None

        label = BASELINE_METRIC_LABELS.get(metric, metric)
        direction = "spike" if z_score > 0 else "drop"
        severity = "high" if abs(z_score) > 5.0 else ("medium" if abs(z_score) > 4.0 else "low")

        # Store anomaly in DB
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self.db.execute("""
                INSERT INTO anomalies (timestamp, host, metric, z_score,
                                       current_value, mean, stddev, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (now_ts, host, metric, round(z_score, 3),
                  round(current_value, 2), round(mean, 2),
                  round(stddev, 2), severity))
            self.db.commit()
        except Exception as e:
            _log(f"BaselineEngine anomaly insert error: {e}")

        # Create alert via existing alert pipeline
        alert = create_alert(
            severity=severity,
            category="ueba",
            title=f"Anomaly [{direction}]: {label} on {host} (z={z_score:.2f})",
            description=(
                f"Statistical anomaly detected for {label} on {host}.\n"
                f"Current: {current_value:.2f} | Baseline mean: {mean:.2f} | "
                f"StdDev: {stddev:.2f} | Z-score: {z_score:.2f}\n"
                f"Direction: {direction} — threshold: {threshold}"
            ),
            source_host=host,
            mitre_tactic="Discovery",
            mitre_technique="T1082 (System Information Discovery)",
            raw_data={
                "metric": metric,
                "metric_label": label,
                "z_score": round(z_score, 3),
                "current_value": round(current_value, 2),
                "baseline_mean": round(mean, 2),
                "baseline_stddev": round(stddev, 2),
                "direction": direction,
            },
        )
        return alert

    def get_baselines(self, host=None):
        """Return current baseline state for one or all hosts."""
        results = []
        mem_keys = set()

        with self.lock:
            for h, metrics in self.samples.items():
                if host and h != host:
                    continue
                for metric, samples in metrics.items():
                    if not samples:
                        continue
                    vals = [v for _, v in samples]
                    count = len(vals)
                    if count < 2:
                        continue
                    mean = sum(vals) / count
                    variance = sum((v - mean) ** 2 for v in vals) / count
                    stddev = math.sqrt(variance) if variance > 1e-9 else 0.0
                    last_val = vals[-1]
                    is_learning = count < BASELINE_LEARNING_SAMPLES
                    z = (last_val - mean) / stddev if stddev > 1e-9 else 0.0

                    mem_keys.add((h, metric))
                    results.append({
                        "host": h,
                        "metric": metric,
                        "label": BASELINE_METRIC_LABELS.get(metric, metric),
                        "count": count,
                        "mean": round(mean, 2),
                        "stddev": round(stddev, 2),
                        "current_value": round(last_val, 2),
                        "z_score": round(z, 3),
                        "is_learning": is_learning,
                        "threshold": BASELINE_Z_THRESHOLDS.get(metric, BASELINE_Z_THRESHOLD),
                    })

        # Also include persisted baselines that might not be in memory yet.
        # Lock is released before DB queries to avoid holding it during I/O.
        try:
            rows = self.db.execute(
                "SELECT * FROM baselines ORDER BY host, metric"
            ).fetchall()
            for r in rows:
                if (r["host"], r["metric"]) not in mem_keys:
                    # Compute z-score from persisted values instead of hardcoding 0.0
                    r_mean = r["mean"]
                    r_stddev = r["stddev"]
                    r_last = r["last_value"]
                    is_learning = bool(r["is_learning"])
                    if r_stddev > 1e-9 and not is_learning:
                        z_db = (r_last - r_mean) / r_stddev
                    else:
                        z_db = 0.0

                    results.append({
                        "host": r["host"],
                        "metric": r["metric"],
                        "label": BASELINE_METRIC_LABELS.get(r["metric"], r["metric"]),
                        "count": r["count"],
                        "mean": round(r_mean, 2),
                        "stddev": round(r_stddev, 2),
                        "current_value": round(r_last, 2),
                        "z_score": round(z_db, 3),
                        "is_learning": is_learning,
                        "threshold": BASELINE_Z_THRESHOLDS.get(r["metric"], BASELINE_Z_THRESHOLD),
                    })
        except Exception:
            pass

        results.sort(key=lambda x: (x["host"], x["metric"]))
        return results

    def get_anomalies(self, host=None, limit=100, hours=24):
        """Return recent anomalies from DB."""
        try:
            if host:
                rows = self.db.execute("""
                    SELECT * FROM anomalies
                    WHERE host = ? AND timestamp >= datetime('now', ?)
                    ORDER BY timestamp DESC LIMIT ?
                """, (host, f"-{hours} hours", limit)).fetchall()
            else:
                rows = self.db.execute("""
                    SELECT * FROM anomalies
                    WHERE timestamp >= datetime('now', ?)
                    ORDER BY timestamp DESC LIMIT ?
                """, (f"-{hours} hours", limit)).fetchall()

            return [{
                "id": r["id"],
                "timestamp": r["timestamp"],
                "host": r["host"],
                "metric": r["metric"],
                "label": BASELINE_METRIC_LABELS.get(r["metric"], r["metric"]),
                "z_score": r["z_score"],
                "current_value": r["current_value"],
                "mean": r["mean"],
                "stddev": r["stddev"],
                "severity": r["severity"],
            } for r in rows]
        except Exception as e:
            _log(f"get_anomalies error: {e}")
            return []

    def get_zscore_history(self, host, metric, hours=1):
        """Return z-score history for charting (from anomalies table)."""
        try:
            rows = self.db.execute("""
                SELECT timestamp, z_score, current_value, mean
                FROM anomalies
                WHERE host = ? AND metric = ?
                  AND timestamp >= datetime('now', ?)
                ORDER BY timestamp ASC
            """, (host, metric, f"-{hours} hours")).fetchall()
            return [{
                "timestamp": r["timestamp"],
                "z_score": r["z_score"],
                "current_value": r["current_value"],
                "mean": r["mean"],
            } for r in rows]
        except Exception:
            return []


# ── Singleton instance ──
_baseline_engine = None
_baseline_lock = threading.Lock()


def get_baseline_engine():
    """Return the singleton BaselineEngine, creating it if needed."""
    global _baseline_engine
    if _baseline_engine is None:
        with _baseline_lock:
            if _baseline_engine is None:
                _baseline_engine = BaselineEngine(get_db())
                _log("UEBA BaselineEngine initialized")
    return _baseline_engine


# ═══════════════════════════════════════════
# ML Anomaly Detection — IsolationForest
# ═══════════════════════════════════════════

# Optional scikit-learn import
try:
    from sklearn.ensemble import IsolationForest as _IsolationForest
    import pickle as _pickle
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

ML_MODEL_MIN_SAMPLES = 100  # minimum samples before training IF model
ML_MODEL_CONTAMINATION = 0.1  # expected proportion of outliers
ML_MODEL_PATH = os.path.join(DATA_DIR, "isolation_forest_model.pkl")

# Feature order for the ML model (must match _build_feature_vector)
ML_FEATURE_METRICS = [
    "cpu_percent",
    "ram_used_gb",
    "disk_read_kbps",
    "disk_write_kbps",
    "network_connections",
    "process_count",
]


class AnomalyDetector:
    """IsolationForest-based multivariate anomaly detector.

    Collects feature vectors from baseline metrics, trains an IsolationForest
    model once enough samples are available, and scores new samples in real-time.
    Supports model persistence (save/load via pickle).

    The model detects multivariate anomalies that univariate z-score may miss
    (e.g., a combination of moderate CPU + normal RAM + high disk IO that is
     anomalous when considered together).
    """

    def __init__(self, contamination=ML_MODEL_CONTAMINATION,
                 min_samples=ML_MODEL_MIN_SAMPLES,
                 model_path=None):
        self.contamination = contamination
        self.min_samples = min_samples
        self.model_path = model_path or ML_MODEL_PATH
        self.model = None
        self._samples = []  # list of feature vectors
        self._lock = threading.Lock()
        self._trained_at = None
        self._error_message = None
        self._feature_count = len(ML_FEATURE_METRICS)

        # Attempt to load existing model on init
        if HAS_SKLEARN:
            self._try_load_model()
        else:
            self._error_message = "scikit-learn not installed"

    @property
    def training_samples(self):
        with self._lock:
            return len(self._samples)

    @property
    def is_trained(self):
        with self._lock:
            return self.model is not None

    @property
    def status(self):
        """Return current status string for API consumption."""
        if not HAS_SKLEARN:
            return "error"
        if self.is_trained:
            return "ready"
        if self.training_samples < self.min_samples:
            return "insufficient_data"
        return "ready_to_train"

    def _try_load_model(self):
        """Attempt to load a previously saved model from disk."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    data = _pickle.load(f)
                if isinstance(data, dict) and "model" in data:
                    self.model = data["model"]
                    self._samples = data.get("samples", [])
                    self._trained_at = data.get("trained_at")
                    _log(f"AnomalyDetector: loaded model from {self.model_path} "
                         f"({len(self._samples)} samples, trained {self._trained_at})")
                else:
                    _log("AnomalyDetector: invalid saved model format, starting fresh")
            except Exception as e:
                _log(f"AnomalyDetector: failed to load model: {e}, starting fresh")
                self.model = None

    def add_sample(self, features):
        """Add a feature vector to the training buffer.

        Args:
            features: list of float values, one per ML_FEATURE_METRICS

        Returns:
            dict with prediction result if model is trained, otherwise None
        """
        if not HAS_SKLEARN:
            return None

        with self._lock:
            self._samples.append(list(features))

        # Auto-trigger training if we just crossed the threshold
        if self.training_samples >= self.min_samples and not self.is_trained:
            self.train()

        # If model is trained, predict on this sample
        if self.is_trained:
            return self.predict(features)

        return None

    def train(self):
        """Train the IsolationForest model on collected samples."""
        if not HAS_SKLEARN:
            return False
        if len(self._samples) < self.min_samples:
            return False

        try:
            with self._lock:
                import numpy as np
                X = np.array(self._samples)
                model = _IsolationForest(
                    contamination=self.contamination,
                    random_state=42,
                    n_estimators=100,
                )
                model.fit(X)
                self.model = model
                self._trained_at = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")
                self._error_message = None

            _log(f"AnomalyDetector: trained IsolationForest on "
                 f"{len(self._samples)} samples, {self._feature_count} features")

            # Auto-save after training
            self.save(self.model_path)
            return True

        except Exception as e:
            self._error_message = str(e)
            _log(f"AnomalyDetector: training failed: {e}")
            return False

    def predict(self, features):
        """Score a feature vector with the trained model.

        Args:
            features: list of float values

        Returns:
            dict with keys: score (float), is_anomaly (bool),
            anomaly_score (float 0-1 normalized), or None if model not trained
        """
        if not HAS_SKLEARN or not self.is_trained:
            return None

        try:
            import numpy as np

            X = np.array([features])
            # IsolationForest returns -1 for outliers, 1 for inliers
            raw_pred = self.model.predict(X)[0]
            # decision_function returns negative scores for anomalies
            decision = self.model.decision_function(X)[0]

            # Normalize score to 0-1 range where higher = more anomalous
            # decision_function typically in range [-0.5, 0.5]
            anomaly_score = max(0.0, min(1.0, 0.5 - decision))

            is_anomaly = bool(raw_pred == -1)

            return {
                "score": round(float(decision), 4),
                "anomaly_score": round(float(anomaly_score), 4),
                "is_anomaly": is_anomaly,
                "raw_prediction": int(raw_pred),
            }

        except Exception as e:
            _log(f"AnomalyDetector: prediction failed: {e}")
            return None

    def save(self, path=None):
        """Persist the trained model and samples to disk."""
        if path is None:
            path = self.model_path
        if not self.is_trained:
            return False

        try:
            with self._lock:
                data = {
                    "model": self.model,
                    "samples": self._samples,
                    "trained_at": self._trained_at,
                    "contamination": self.contamination,
                    "feature_count": self._feature_count,
                }
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f:
                    _pickle.dump(data, f)
            _log(f"AnomalyDetector: model saved to {path}")
            return True
        except Exception as e:
            _log(f"AnomalyDetector: save failed: {e}")
            return False

    def load(self, path=None):
        """Load a previously saved model from disk."""
        if path is None:
            path = self.model_path
        if not os.path.exists(path):
            _log(f"AnomalyDetector: no saved model at {path}")
            return False

        try:
            with open(path, "rb") as f:
                data = _pickle.load(f)
            if isinstance(data, dict) and "model" in data:
                with self._lock:
                    self.model = data["model"]
                    self._samples = data.get("samples", [])
                    self._trained_at = data.get("trained_at")
                    self._error_message = None
                _log(f"AnomalyDetector: model loaded from {path}")
                return True
            return False
        except Exception as e:
            _log(f"AnomalyDetector: load failed: {e}")
            self._error_message = str(e)
            return False

    def get_status(self):
        """Return current status for UI consumption.

        Returns:
            dict with status, samples_collected, samples_required, is_trained
        """
        return {
            "status": self.status,
            "samples_collected": self.training_samples,
            "samples_required": self.min_samples,
            "is_trained": self.is_trained,
            "error_message": self._error_message,
        }

    def get_health(self):
        """Return detailed model health metrics for API consumption.

        Returns:
            dict with model health metrics
        """
        return {
            "status": self.status,
            "is_trained": self.is_trained,
            "samples_collected": self.training_samples,
            "min_samples_required": self.min_samples,
            "feature_count": self._feature_count,
            "feature_metrics": ML_FEATURE_METRICS,
            "contamination": self.contamination,
            "model_trained_at": self._trained_at,
            "error_message": self._error_message,
            "model_path": self.model_path,
            "sklearn_available": HAS_SKLEARN,
        }

    def _build_feature_vector(self, metrics):
        """Convert a metrics dict to a feature vector matching ML_FEATURE_METRICS.

        Args:
            metrics: dict like {"cpu_percent": 45.0, ...}

        Returns:
            list of float values in order of ML_FEATURE_METRICS
        """
        return [float(metrics.get(m, 0.0)) for m in ML_FEATURE_METRICS]


# ── Singleton ──
_anomaly_detector = None
_anomaly_detector_lock = threading.Lock()


def get_anomaly_detector():
    """Return the singleton AnomalyDetector, creating it if needed."""
    global _anomaly_detector
    if _anomaly_detector is None:
        with _anomaly_detector_lock:
            if _anomaly_detector is None:
                _anomaly_detector = AnomalyDetector()
                _log("UEBA AnomalyDetector initialized")
    return _anomaly_detector


def get_ueba_health():
    """Return UEBA health metrics for the /api/v2/ueba/health endpoint.

    Aggregates data from both BaselineEngine and AnomalyDetector to give
    a complete picture of UEBA system health.

    Returns:
        dict with model_status, entities_monitored, baselines_active,
        anomalies_24h, model_trained_at, and other health metrics.
    """
    detector = get_anomaly_detector()
    ml_health = detector.get_health()

    # Get engine metrics
    engine = get_baseline_engine()
    baselines = engine.get_baselines()
    anomalies_24h = engine.get_anomalies(hours=24)

    # Count entities and active baselines
    hosts = set()
    active_baselines = 0
    for b in baselines:
        hosts.add(b.get("host", ""))
        if not b.get("is_learning", True):
            active_baselines += 1

    # Anomalies in last 24h
    anomaly_count_24h = len(anomalies_24h)

    # Calculate average anomaly score from recent anomalies
    scores = [a.get("z_score", 0) for a in anomalies_24h if a.get("z_score")]
    avg_z_score = round(sum(scores) / len(scores), 3) if scores else 0.0

    return {
        "model_status": ml_health["status"],
        "is_trained": ml_health["is_trained"],
        "entities_monitored": len(hosts),
        "baselines_active": active_baselines,
        "baselines_total": len(baselines),
        "anomalies_24h": anomaly_count_24h,
        "anomaly_score_mean": avg_z_score,
        "model_trained_at": ml_health["model_trained_at"],
        "feature_count": ml_health["feature_count"],
        "samples_collected": ml_health["samples_collected"],
        "min_samples_required": ml_health["min_samples_required"],
        "contamination": ml_health["contamination"],
        "sklearn_available": ml_health["sklearn_available"],
        "error_message": ml_health["error_message"],
        "config": {
            "window_seconds": BASELINE_WINDOW_SECONDS,
            "learning_samples": BASELINE_LEARNING_SAMPLES,
            "default_z_threshold": BASELINE_Z_THRESHOLD,
            "ml_contamination": ML_MODEL_CONTAMINATION,
            "ml_min_samples": ML_MODEL_MIN_SAMPLES,
        },
    }


# ═══════════════════════════════════════════
# Real-Time Event Correlation Engine
# ═══════════════════════════════════════════

# ── Chain pattern definitions ──
# Each pattern maps a sequence of alert categories to a MITRE ATT&CK tactic chain.
# The mitre_chain is a list of (tactic, technique) tuples, one per step.
CHAIN_PATTERNS = [
    {
        "id": "portscan_sshbrute",
        "name": "Port Scan → SSH Brute Force",
        "severity": "critical",
        "description": "Port scan followed by SSH brute force from same IP within 5 minutes",
        "steps": [
            {"category": "port_scan", "min_count": 1, "max_gap_seconds": 300},
            {"category": "brute_force", "min_count": 1, "max_gap_seconds": 300},
        ],
        "mitre_chain": [
            ("Reconnaissance", "T1046 (Network Service Discovery)"),
            ("Credential Access", "T1110 (Brute Force)"),
        ],
    },
    {
        "id": "auth_spike_login_newip",
        "name": "Failed Auth Spike → Successful Login from New IP",
        "severity": "high",
        "description": "Spike in failed authentications followed by successful login from a new IP within 3 minutes",
        "steps": [
            {"category": "auth_failure", "min_count": 3, "max_gap_seconds": 180},
            {"category": "auth_success", "min_count": 1, "max_gap_seconds": 180},
        ],
        "mitre_chain": [
            ("Credential Access", "T1110 (Brute Force)"),
            ("Initial Access", "T1078 (Valid Accounts)"),
        ],
    },
    {
        "id": "dga_beaconing",
        "name": "DNS DGA → Beaconing Detection",
        "severity": "critical",
        "description": "DGA-like DNS activity followed by C2 beaconing detection within 10 minutes",
        "steps": [
            {"category": "dga", "min_count": 2, "max_gap_seconds": 600},
            {"category": "beaconing", "min_count": 1, "max_gap_seconds": 600},
        ],
        "mitre_chain": [
            ("Command and Control", "T1568 (Dynamic Resolution)"),
            ("Command and Control", "T1071 (Application Layer Protocol)"),
        ],
    },
    {
        "id": "fim_process_outbound",
        "name": "File Integrity → New Process → Outbound Connection",
        "severity": "high",
        "description": "File integrity alert followed by new process spawning an outbound connection within 2 minutes",
        "steps": [
            {"category": "file_integrity", "min_count": 1, "max_gap_seconds": 120},
            {"category": "new_process", "min_count": 1, "max_gap_seconds": 120},
            {"category": "outbound_connection", "min_count": 1, "max_gap_seconds": 120},
        ],
        "mitre_chain": [
            ("Persistence", "T1098 (Account Manipulation)"),
            ("Execution", "T1204 (User Execution)"),
            ("Command and Control", "T1071 (Application Layer Protocol)"),
        ],
    },
    {
        "id": "threatintel_alertspike",
        "name": "Threat Intel Hit → Alert Spike",
        "severity": "high",
        "description": "Threat intel match followed by a spike in security alerts within 1 minute",
        "steps": [
            {"category": "threat_intel", "min_count": 1, "max_gap_seconds": 60},
            {"category": "alert", "min_count": 3, "max_gap_seconds": 60},
        ],
        "mitre_chain": [
            ("Reconnaissance", "T1595 (Active Scanning)"),
            ("Impact", "T1499 (Endpoint Denial of Service)"),
        ],
    },
    # ── Additional M2 patterns ──
    {
        "id": "priv_esc_beacon",
        "name": "Privilege Escalation → New C2 Beacon",
        "severity": "critical",
        "description": "Privilege escalation event (sudo/su) followed by a new outbound C2 beacon within 5 minutes",
        "steps": [
            {"category": "privilege_escalation", "min_count": 1, "max_gap_seconds": 300},
            {"category": "beaconing", "min_count": 1, "max_gap_seconds": 300},
        ],
        "mitre_chain": [
            ("Privilege Escalation", "T1548 (Abuse Elevation Control Mechanism)"),
            ("Command and Control", "T1071 (Application Layer Protocol)"),
        ],
    },
    {
        "id": "lateral_movement_chain",
        "name": "Lateral Movement via SSH → Persistence",
        "severity": "critical",
        "description": "SSH success from one host followed by SSH outbound to peer and file modification within 10 minutes",
        "steps": [
            {"category": "auth_success", "min_count": 1, "max_gap_seconds": 600},
            {"category": "new_process", "min_count": 1, "max_gap_seconds": 600},
            {"category": "file_integrity", "min_count": 1, "max_gap_seconds": 600},
        ],
        "mitre_chain": [
            ("Lateral Movement", "T1021 (Remote Services)"),
            ("Execution", "T1059 (Command and Scripting Interpreter)"),
            ("Persistence", "T1098 (Account Manipulation)"),
        ],
    },
    {
        "id": "exfil_beacon",
        "name": "C2 Beaconing → Data Exfiltration",
        "severity": "critical",
        "description": "Established C2 beacon followed by large outbound connection suggesting data exfiltration within 10 minutes",
        "steps": [
            {"category": "beaconing", "min_count": 1, "max_gap_seconds": 600},
            {"category": "outbound_connection", "min_count": 3, "max_gap_seconds": 600},
        ],
        "mitre_chain": [
            ("Command and Control", "T1071 (Application Layer Protocol)"),
            ("Exfiltration", "T1041 (Exfiltration Over C2 Channel)"),
        ],
    },
]

EXPIRY_INTERVAL_SECONDS = 60  # how often stale pending matches are cleaned
EVALUATION_INTERVAL_SECONDS = 10  # periodic evaluation cycle (runs every 10s)
EVENT_BUFFER_WINDOW_SECONDS = 300  # sliding window for buffered events
EVENT_BUFFER_MAX_SIZE = 10000  # max events before trimming oldest


class CorrelationEngine:
    """Real-time event correlation engine.

    Detects multi-stage attack chains by matching sequences of individual alerts
    against predefined CHAIN_PATTERNS. Tracks partial matches per (host, chain_id)
    and creates correlation alerts when all steps are satisfied.

    Maintains a sliding-window event buffer (default 300s) for batch evaluation
    via a periodic evaluation thread (default 10s interval). Each pattern maps to
    a MITRE ATT&CK tactic chain for accurate threat intelligence attribution.
    """

    def __init__(self, db_conn):
        self.db = db_conn
        self.patterns = CHAIN_PATTERNS
        # _pending: {(host, chain_id): {step_index, started_at, last_match_at, step_counts}}
        self._pending = {}
        self._pending_lock = threading.RLock()
        # Sliding window event buffer: list of (timestamp, alert_dict)
        self._event_buffer = []
        self._event_buffer_lock = threading.Lock()
        self._eval_thread = None
        self._expiry_thread = None
        self._running = False

    def start(self):
        """Start the background expiry and evaluation threads if not already running."""
        if self._running:
            return
        self._running = True
        self._expiry_thread = threading.Thread(
            target=self._expire_loop, name="correlation-expiry", daemon=True
        )
        self._expiry_thread.start()
        self._eval_thread = threading.Thread(
            target=self._evaluate_loop, name="correlation-eval", daemon=True
        )
        self._eval_thread.start()
        _log("CorrelationEngine started (expiry + eval threads running)")

    def stop(self):
        """Signal background threads to stop."""
        self._running = False

    def process_alert(self, alert):
        """Called after an alert is created. Tracks partial chain matches.

        Parameters:
            alert: dict with keys id, severity, category, title, source_host,
                   source_ip, timestamp, etc.
        """
        if not alert:
            return

        # ── Buffer event in sliding window for periodic evaluation ──
        self._buffer_event(alert)

        host = alert.get("source_host", "") or alert.get("source_ip", "")
        if not host:
            return

        category = alert.get("category", "")
        now = time.time()

        with self._pending_lock:
            # ── Pass 1: advance or complete existing pending chains ──
            advanced = False
            for pattern in self.patterns:
                chain_id = pattern["id"]
                key = (host, chain_id)

                if key in self._pending:
                    p = self._pending[key]
                    needed_step = pattern["steps"][p["step_index"]]

                    if needed_step["category"] == category:
                        p["step_counts"][category] = p["step_counts"].get(category, 0) + 1
                        p["last_match_at"] = now

                        if p["step_counts"][category] >= needed_step["min_count"]:
                            p["step_index"] += 1

                        if p["step_index"] >= len(pattern["steps"]):
                            self._check_completion(key, pattern, p)
                        advanced = True
                    else:
                        # Wrong step — check if we're still within gap for current step
                        time_since_last = now - p["last_match_at"]
                        if time_since_last > needed_step["max_gap_seconds"]:
                            # Expired — remove stale pending
                            del self._pending[key]

            # ── Pass 2: start new chains only if nothing was advanced ──
            if not advanced:
                for pattern in self.patterns:
                    chain_id = pattern["id"]
                    key = (host, chain_id)

                    # Skip if already tracked
                    if key in self._pending:
                        continue

                    if pattern["steps"][0]["category"] == category:
                        self._pending[key] = {
                            "step_index": 0,
                            "started_at": now,
                            "last_match_at": now,
                            "step_counts": {category: 1},
                        }
                        first_step = pattern["steps"][0]
                        if first_step["min_count"] <= 1:
                            self._pending[key]["step_index"] = 1
                            if self._pending[key]["step_index"] >= len(pattern["steps"]):
                                self._check_completion(key, pattern, self._pending[key])

    def _buffer_event(self, alert):
        """Add an alert to the sliding window event buffer, pruning stale entries."""
        now = time.time()
        cutoff = now - EVENT_BUFFER_WINDOW_SECONDS
        with self._event_buffer_lock:
            self._event_buffer.append((now, alert))
            # Prune events outside the window
            self._event_buffer[:] = [
                (ts, a) for ts, a in self._event_buffer if ts > cutoff
            ]
            # Trim to max size to prevent unbounded growth
            if len(self._event_buffer) > EVENT_BUFFER_MAX_SIZE:
                self._event_buffer = self._event_buffer[-EVENT_BUFFER_MAX_SIZE:]

    def _check_completion(self, key, pattern, pending):
        """All steps matched — persist the chain and create a correlation alert."""
        host, chain_id = key
        completed_at = time.time()
        started_at = pending["started_at"]

        # Persist to DB
        steps_json = json.dumps(list(pending["step_counts"].items()))
        started_ts = datetime.fromtimestamp(started_at, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        completed_ts = datetime.fromtimestamp(completed_at, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        try:
            self.db.execute(
                """INSERT INTO correlation_matches
                   (chain_id, chain_name, host, started_at, completed_at,
                    steps_json, severity)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    chain_id,
                    pattern["name"],
                    host,
                    started_ts,
                    completed_ts,
                    steps_json,
                    pattern["severity"],
                ),
            )
            self.db.commit()
            _log(
                f"🔗 CORRELATION MATCH [{pattern['severity'].upper()}] "
                f"{pattern['name']} on {host}"
            )
        except Exception as e:
            _log(f"CorrelationEngine _check_completion DB error: {e}")

        # Build MITRE ATT&CK tactic chain from pattern
        mitre_chain = pattern.get("mitre_chain", [])
        mitre_tactics = ", ".join(t[0] for t in mitre_chain) if mitre_chain else "Command and Control"
        mitre_techniques = ", ".join(t[1] for t in mitre_chain) if mitre_chain else "T1071 (Application Layer Protocol)"

        # Build rich description with attack chain detail
        chain_description = pattern.get("description", "")
        if mitre_chain:
            tactic_steps = " → ".join(t[0] for t in mitre_chain)
            chain_description += f"\nMITRE ATT&CK Chain: {tactic_steps}"
            chain_description += f"\nTechniques: {mitre_techniques}"

        # Create a correlation alert with pattern-specific MITRE mappings
        create_alert(
            severity=pattern["severity"],
            category="correlation",
            title=f"Attack Chain: {pattern['name']}",
            description=chain_description,
            source_host=host,
            mitre_tactic=mitre_tactics,
            mitre_technique=mitre_techniques,
            raw_data={
                "chain_id": chain_id,
                "host": host,
                "started_at": started_ts,
                "completed_at": completed_ts,
                "steps": pending["step_counts"],
                "mitre_chain": mitre_chain,
            },
        )

        # Clear pending (if it exists — may not when called from eval thread)
        self._pending.pop(key, None)

    def _expire_pending(self):
        """Remove stale partial matches whose last step gap has expired."""
        now = time.time()
        with self._pending_lock:
            expired = []
            for key, p in self._pending.items():
                _, chain_id = key
                # Find the pattern
                pattern = next(
                    (pat for pat in self.patterns if pat["id"] == chain_id), None
                )
                if pattern is None:
                    expired.append(key)
                    continue
                current_step_idx = p["step_index"]
                if current_step_idx < len(pattern["steps"]):
                    gap = pattern["steps"][current_step_idx]["max_gap_seconds"]
                    if now - p["last_match_at"] > gap:
                        expired.append(key)
            for key in expired:
                del self._pending[key]

    def _expire_loop(self):
        """Background thread: periodically expire stale partial matches."""
        while self._running:
            try:
                self._expire_pending()
            except Exception as e:
                _log(f"CorrelationEngine expiry error: {e}")
            time.sleep(EXPIRY_INTERVAL_SECONDS)

    def _evaluate_loop(self):
        """Background thread: periodically evaluate buffered events every 10s.

        Replays buffered events against all chain patterns to catch chains that
        may have been missed in the event-driven path (e.g., due to race conditions
        or out-of-order delivery). Run interval: EVALUATION_INTERVAL_SECONDS (10s).
        """
        _log(f"CorrelationEngine: evaluation loop started (interval={EVALUATION_INTERVAL_SECONDS}s, "
             f"buffer_window={EVENT_BUFFER_WINDOW_SECONDS}s)")
        while self._running:
            try:
                self._evaluate_buffered_events()
            except Exception as e:
                _log(f"CorrelationEngine evaluation error: {e}")
            time.sleep(EVALUATION_INTERVAL_SECONDS)

    def _evaluate_buffered_events(self):
        """Re-evaluate all buffered events against chain patterns.

        This is a batch evaluation that re-processes events in the sliding window
        against all chain patterns. It complements the event-driven path (process_alert)
        by catching chains that may have been missed due to timing or ordering issues.
        """
        with self._event_buffer_lock:
            # Get a snapshot of buffered events, sorted by time
            events = sorted(self._event_buffer, key=lambda x: x[0])

        if not events:
            return

        now = time.time()
        cutoff = now - EVENT_BUFFER_WINDOW_SECONDS

        # Only process events within the window
        window_events = [a for ts, a in events if ts > cutoff]
        if not window_events:
            return

        # For each pattern, look for a complete sequence in the buffered events
        # Pre-compute dedup set before acquiring lock to avoid holding
        # _pending_lock across DB queries (important for non-WAL backends).
        completed_keys = set()
        if self.db:
            try:
                rows = self.db.execute(
                    """SELECT host, chain_id FROM correlation_matches
                       WHERE completed_at >= datetime('now', ?)""",
                    (f'-{EVENT_BUFFER_WINDOW_SECONDS} seconds',),
                ).fetchall()
                completed_keys = {(r[0], r[1]) for r in rows}
            except Exception:
                pass  # DB check is best-effort

        with self._pending_lock:
            for pattern in self.patterns:
                chain_id = pattern["id"]
                steps = pattern["steps"]

                # Group events by host
                host_events = {}
                for alert in window_events:
                    host = alert.get("source_host", "") or alert.get("source_ip", "")
                    if not host:
                        continue
                    if host not in host_events:
                        host_events[host] = []
                    host_events[host].append(alert)

                for host, alerts in host_events.items():
                    key = (host, chain_id)

                    # Skip if this chain is already completed (dedup set) or actively tracked
                    if key in completed_keys or key in self._pending:
                        continue

                    # Try to match the full sequence from scratch
                    si = 0  # step index
                    step_counts = {}
                    last_ts = None

                    for alert in alerts:
                        category = alert.get("category", "")
                        if si >= len(steps):
                            break

                        needed = steps[si]
                        if needed["category"] == category:
                            step_counts[category] = step_counts.get(category, 0) + 1
                            last_ts = now  # fallback

                            if step_counts[category] >= needed["min_count"]:
                                si += 1

                    if si >= len(steps) and last_ts is not None:
                        # Full chain matched from buffered events
                        pending = {
                            "step_index": si,
                            "started_at": last_ts,
                            "last_match_at": last_ts,
                            "step_counts": step_counts,
                        }
                        # Guard against pending-leak: if _check_completion raises,
                        # ensure the key is removed so subsequent cycles can retry.
                        self._pending[key] = pending
                        try:
                            self._check_completion(key, pattern, pending)
                        finally:
                            self._pending.pop(key, None)

    def get_buffered_events(self, host=None, category=None, limit=100):
        """Return events currently in the sliding window buffer.

        Parameters:
            host: optional filter by source_host or source_ip
            category: optional filter by alert category
            limit: max results to return

        Returns:
            list of alert dicts with an added `buffered_at` timestamp
        """
        with self._event_buffer_lock:
            result = []
            for ts, alert in self._event_buffer:
                if host:
                    ah = alert.get("source_host", "") or alert.get("source_ip", "")
                    if ah != host:
                        continue
                if category and alert.get("category") != category:
                    continue
                alert_copy = dict(alert)
                alert_copy["buffered_at"] = ts
                result.append(alert_copy)
                if len(result) >= limit:
                    break
            return result

    def get_active_chains(self, host=None):
        """Return list of in-progress chain matches.

        Parameters:
            host: optional filter by host

        Returns:
            list of dicts with chain_id, chain_name, host, started_at,
            step_index, total_steps, last_match_at, step_counts
        """
        now = time.time()
        with self._pending_lock:
            result = []
            for (h, chain_id), p in self._pending.items():
                if host and h != host:
                    continue
                pattern = next(
                    (pat for pat in self.patterns if pat["id"] == chain_id), None
                )
                if pattern is None:
                    continue
                result.append(
                    {
                        "chain_id": chain_id,
                        "chain_name": pattern["name"],
                        "host": h,
                        "started_at": datetime.fromtimestamp(
                            p["started_at"], timezone.utc
                        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "step_index": p["step_index"],
                        "total_steps": len(pattern["steps"]),
                        "step_names": [
                            s["category"] for s in pattern["steps"]
                        ],
                        "step_counts": p["step_counts"],
                        "last_match_at": p["last_match_at"],
                        "severity": pattern["severity"],
                        "age_seconds": round(now - p["started_at"], 1),
                    }
                )
            return result

    def get_completed_chains(self, host=None, limit=50):
        """Return recently completed chain matches from the database.

        Parameters:
            host: optional filter by host
            limit: max results

        Returns:
            list of dicts
        """
        try:
            if host:
                rows = self.db.execute(
                    """SELECT * FROM correlation_matches
                       WHERE host = ?
                       ORDER BY completed_at DESC LIMIT ?""",
                    (host, limit),
                )
            else:
                rows = self.db.execute(
                    """SELECT * FROM correlation_matches
                       ORDER BY completed_at DESC LIMIT ?""",
                    (limit,),
                )
            return [dict(r) for r in rows]
        except Exception as e:
            _log(f"CorrelationEngine get_completed_chains error: {e}")
            return []


_correlation_engine = None
_correlation_lock = threading.Lock()


def get_correlation_engine():
    """Return the singleton CorrelationEngine, creating it if needed."""
    global _correlation_engine
    if _correlation_engine is None:
        with _correlation_lock:
            if _correlation_engine is None:
                _correlation_engine = CorrelationEngine(get_db())
                _log("CorrelationEngine initialized")
    return _correlation_engine


# ═══════════════════════════════════════════
# Alert Grouper — Intelligent Alert-to-Incident Grouping
# ═══════════════════════════════════════════

class AlertGrouper:
    """Intelligent alert grouping engine that correlates related alerts into incidents.

    Groups alerts based on:
      - Same source host (or source_ip if host is empty)
      - Same MITRE ATT&CK technique (attack pattern)
      - Overlapping time windows (configurable via GROUPING_WINDOW_SECONDS)

    When a new alert arrives:
      1. Find open incidents matching the alert's host and MITRE technique
         within the configured grouping window.
      2. If a matching incident exists, add the alert to it and update metadata.
      3. If no matching incident exists, create a new incident from the alert.

    Supports manual group/ungroup operations via API.
    """

    def __init__(self, db_conn):
        self.db = db_conn
        self._lock = threading.RLock()

    @property
    def grouping_window_s(self):
        return GROUPING_WINDOW_SECONDS

    def set_grouping_window(self, seconds: int):
        """Update the grouping window configuration at runtime."""
        global GROUPING_WINDOW_SECONDS
        if seconds < 60:
            seconds = 60  # minimum 1 minute
        if seconds > 86400:
            seconds = 86400  # maximum 24 hours
        GROUPING_WINDOW_SECONDS = seconds
        _log(f"AlertGrouper: grouping window set to {seconds}s")

    def get_config(self) -> dict:
        """Return current grouping configuration."""
        return {
            "grouping_window_seconds": GROUPING_WINDOW_SECONDS,
            "auto_group_enabled": AUTO_GROUP_ENABLED,
        }

    def set_auto_group(self, enabled: bool):
        """Enable or disable automatic alert grouping."""
        global AUTO_GROUP_ENABLED
        AUTO_GROUP_ENABLED = enabled
        _log(f"AlertGrouper: auto-group {'enabled' if enabled else 'disabled'}")

    def process_alert(self, alert: dict):
        """Process a newly created alert for incident grouping.

        Called from _group_alert() after create_alert().

        Parameters:
            alert: dict with keys id, severity, category, title, source_host,
                   source_ip, mitre_technique, timestamp, etc.
        """
        if not alert or not alert.get("id"):
            return

        alert_id = alert["id"]
        host = alert.get("source_host", "") or alert.get("source_ip", "")
        mitre_technique = alert.get("mitre_technique", "") or alert.get("mitre_tactic", "")

        # Extract primary technique ID (e.g., "T1110" from "T1110 (Brute Force)")
        tech_id = self._extract_technique_id(mitre_technique)

        if not host:
            # Fall back to category-based matching only
            host = "__no_host__"

        with self._lock:
            try:
                # Build search criteria — find open incidents that match
                window_expr = f"-{GROUPING_WINDOW_SECONDS} seconds"

                # Find open incidents matching host + technique within the window
                if tech_id:
                    rows = self.db.execute(
                        """SELECT id FROM incidents
                           WHERE status IN ('new', 'investigating')
                           AND source_host = ?
                           AND mitre_technique LIKE ?
                           AND updated_at >= datetime('now', ?)
                           ORDER BY updated_at DESC LIMIT 1""",
                        (host, f"%{tech_id}%", window_expr),
                    ).fetchall()
                else:
                    # No MITRE technique — match on host only
                    rows = self.db.execute(
                        """SELECT id FROM incidents
                           WHERE status IN ('new', 'investigating')
                           AND source_host = ?
                           AND updated_at >= datetime('now', ?)
                           ORDER BY updated_at DESC LIMIT 1""",
                        (host, window_expr),
                    ).fetchall()

                if rows:
                    # Add to existing incident
                    incident_id = rows[0]["id"]
                    self._add_alert_to_incident(incident_id, alert_id, auto_grouped=True)
                    self._update_incident_metadata(incident_id, alert)
                else:
                    # Create a new incident
                    self._create_incident_from_alert(alert, tech_id)

            except Exception as e:
                _log(f"AlertGrouper process_alert error: {e}")

    def _extract_technique_id(self, mitre_text: str) -> str:
        """Extract MITRE technique ID like 'T1110' from text like 'T1110 (Brute Force)'."""
        if not mitre_text:
            return ""
        m = re.match(r'(T\d{4})', mitre_text.strip())
        return m.group(1) if m else ""

    def _create_incident_from_alert(self, alert: dict, tech_id: str):
        """Create a new incident from a single alert's data."""
        host = alert.get("source_host", "") or alert.get("source_ip", "")
        severity = alert.get("severity", "medium")
        category = alert.get("category", "")
        title = alert.get("title", "")
        description = alert.get("description", "")
        mitre_technique = alert.get("mitre_technique", "")
        mitre_tactic = alert.get("mitre_tactic", "")

        incident_title = f"[{severity.upper()}] {category}: {title[:100]}"
        incident_desc = (
            f"Auto-created from alert #{alert['id']}\n"
            f"Host: {host}\n"
            f"MITRE: {mitre_technique or 'N/A'}\n"
            f"Original: {description[:200]}"
        )

        mitre_label = mitre_technique or mitre_tactic or ""

        cur = self.db.execute(
            """INSERT INTO incidents
               (title, description, severity, status, source_host, mitre_technique)
               VALUES (?, ?, ?, 'new', ?, ?)""",
            (incident_title, incident_desc, severity, host, mitre_label),
        )
        self.db.commit()
        incident_id = cur.lastrowid
        self._add_alert_to_incident(incident_id, alert["id"], auto_grouped=True)
        _log(
            f"📋 INCIDENT CREATED [{severity.upper()}] '{incident_title}' "
            f"(id={incident_id}, host={host})"
        )

    def _add_alert_to_incident(self, incident_id: int, alert_id: int, auto_grouped: bool = False):
        """Link an alert to an incident in the junction table (idempotent)."""
        try:
            self.db.execute(
                """INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, auto_grouped)
                   VALUES (?, ?, ?)""",
                (incident_id, alert_id, 1 if auto_grouped else 0),
            )
            self.db.commit()
        except Exception as e:
            _log(f"AlertGrouper _add_alert_to_incident error: {e}")

    def _update_incident_metadata(self, incident_id: int, alert: dict):
        """Update incident's metadata: severity escalation, alert count, updated_at."""
        try:
            severity = alert.get("severity", "medium")

            # Count alerts in incident
            # Escalate incident severity if alert severity is higher
            sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            existing = self.db.execute(
                "SELECT severity FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            current_sev = existing["severity"] if existing else "medium"

            new_sev = current_sev
            if sev_order.get(severity, 1) > sev_order.get(current_sev, 1):
                new_sev = severity

            self.db.execute(
                """UPDATE incidents
                   SET updated_at = datetime('now'), severity = ?
                   WHERE id = ?""",
                (new_sev, incident_id),
            )
            self.db.commit()
        except Exception as e:
            _log(f"AlertGrouper _update_incident_metadata error: {e}")

    # ── Query methods ──

    def get_incidents(self, status=None, host=None, limit=100, offset=0) -> list[dict]:
        """List incidents with optional filters."""
        try:
            q = "SELECT * FROM incidents WHERE 1=1 "
            params = []
            if status:
                q += "AND status = ? "
                params.append(status)
            if host:
                q += "AND source_host = ? "
                params.append(host)
            q += "ORDER BY updated_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = self.db.execute(q, params).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                # Add alert count
                cnt = self.db.execute(
                    "SELECT COUNT(*) as cnt FROM incident_alerts WHERE incident_id = ?",
                    (d["id"],),
                ).fetchone()
                d["alert_count"] = cnt["cnt"] if cnt else 0
                results.append(d)
            return results
        except Exception as e:
            _log(f"AlertGrouper get_incidents error: {e}")
            return []

    def get_incident(self, incident_id: int) -> dict | None:
        """Get a single incident with full details including linked alerts."""
        try:
            row = self.db.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            if not row:
                return None
            incident = dict(row)

            # Get linked alert IDs
            alert_rows = self.db.execute(
                """SELECT a.*, ia.added_at as linked_at, ia.auto_grouped
                   FROM incident_alerts ia
                   JOIN alerts a ON ia.alert_id = a.id
                   WHERE ia.incident_id = ?
                   ORDER BY a.timestamp DESC""",
                (incident_id,),
            ).fetchall()
            incident["alerts"] = [dict(ar) for ar in alert_rows]
            incident["alert_count"] = len(alert_rows)
            return incident
        except Exception as e:
            _log(f"AlertGrouper get_incident error: {e}")
            return None

    def create_incident(self, title: str, alert_ids: list[int] | None = None,
                        severity: str = "medium", description: str = "",
                        source_host: str = "", mitre_technique: str = "") -> dict | None:
        """Manually create a new incident and optionally link alerts."""
        try:
            cur = self.db.execute(
                """INSERT INTO incidents
                   (title, description, severity, status, source_host, mitre_technique)
                   VALUES (?, ?, ?, 'new', ?, ?)""",
                (title, description, severity, source_host, mitre_technique),
            )
            self.db.commit()
            incident_id = cur.lastrowid

            if alert_ids:
                for aid in alert_ids:
                    self._add_alert_to_incident(incident_id, aid, auto_grouped=False)

            _log(f"📋 INCIDENT CREATED (manual): '{title}' (id={incident_id})")
            return self.get_incident(incident_id)
        except Exception as e:
            _log(f"AlertGrouper create_incident error: {e}")
            return None

    def add_alerts_to_incident(self, incident_id: int, alert_ids: list[int]) -> bool:
        """Manually group alerts into an incident (add alerts to existing incident)."""
        try:
            with self._lock:
                # Verify incident exists
                existing = self.db.execute(
                    "SELECT id FROM incidents WHERE id = ?", (incident_id,)
                ).fetchone()
                if not existing:
                    return False

                for aid in alert_ids:
                    self._add_alert_to_incident(incident_id, aid, auto_grouped=False)

                self.db.execute(
                    "UPDATE incidents SET updated_at = datetime('now') WHERE id = ?",
                    (incident_id,),
                )
                self.db.commit()
                _log(f"📋 INCIDENT: {len(alert_ids)} alerts added to incident #{incident_id}")
                return True
        except Exception as e:
            _log(f"AlertGrouper add_alerts_to_incident error: {e}")
            return False

    def remove_alert_from_incident(self, incident_id: int, alert_id: int) -> bool:
        """Manually ungroup an alert from an incident."""
        try:
            with self._lock:
                self.db.execute(
                    "DELETE FROM incident_alerts WHERE incident_id = ? AND alert_id = ?",
                    (incident_id, alert_id),
                )
                self.db.execute(
                    "UPDATE incidents SET updated_at = datetime('now') WHERE id = ?",
                    (incident_id,),
                )
                self.db.commit()
                _log(f"📋 INCIDENT: alert #{alert_id} removed from incident #{incident_id}")
                return True
        except Exception as e:
            _log(f"AlertGrouper remove_alert_from_incident error: {e}")
            return False

    def update_incident_status(self, incident_id: int, status: str) -> bool:
        """Update incident status and set resolved_at if resolved/closed."""
        valid_statuses = ("new", "investigating", "escalated", "resolved", "closed")
        if status not in valid_statuses:
            return False

        try:
            if status in ("resolved", "closed"):
                self.db.execute(
                    """UPDATE incidents
                       SET status = ?, resolved_at = datetime('now'), updated_at = datetime('now')
                       WHERE id = ?""",
                    (status, incident_id),
                )
            else:
                self.db.execute(
                    "UPDATE incidents SET status = ?, updated_at = datetime('now') WHERE id = ?",
                    (status, incident_id),
                )
            self.db.commit()
            _log(f"📋 INCIDENT #{incident_id}: status → {status}")
            return True
        except Exception as e:
            _log(f"AlertGrouper update_incident_status error: {e}")
            return False

    def get_suggested_groups(self, host=None, lookback_minutes=30) -> list[dict]:
        """Return suggested alert groupings based on recent ungrouped alerts.

        This is the 'suggestion' path (VAL-CROSS-001) — analyst reviews and confirms.

        Returns:
            list of {reason, alert_ids, host, mitre_technique, match_score}
        """
        try:
            lookback_expr = f"-{lookback_minutes} minutes"
            # Find ungrouped alerts (not in any incident)
            rows = self.db.execute(
                """SELECT a.* FROM alerts a
                   WHERE a.timestamp >= datetime('now', ?)
                   AND a.id NOT IN (SELECT alert_id FROM incident_alerts)
                   ORDER BY a.timestamp DESC""",
                (lookback_expr,),
            ).fetchall()

            alerts = [dict(r) for r in rows]
            suggestions = []

            # Group by host
            by_host = {}
            for a in alerts:
                h = a.get("source_host", "") or a.get("source_ip", "")
                if not h:
                    continue
                if h not in by_host:
                    by_host[h] = []
                by_host[h].append(a)

            for h, host_alerts in by_host.items():
                if len(host_alerts) < 2:
                    continue
                # Group by MITRE technique within this host
                by_tech = {}
                for a in host_alerts:
                    tech = a.get("mitre_technique", "") or a.get("mitre_tactic", "")
                    tid = self._extract_technique_id(tech)
                    if not tid:
                        continue
                    if tid not in by_tech:
                        by_tech[tid] = []
                    by_tech[tid].append(a)

                for tid, tech_alerts in by_tech.items():
                    if len(tech_alerts) < 2:
                        continue
                    alert_ids = [a["id"] for a in tech_alerts[:10]]
                    match_score = min(100, len(tech_alerts) * 20)
                    suggestions.append({
                        "reason": f"Same host ({h}) + MITRE technique ({tid})",
                        "host": h,
                        "mitre_technique": tid,
                        "alert_ids": alert_ids,
                        "alert_count": len(tech_alerts),
                        "match_score": match_score,
                    })

            # Sort by match_score descending
            suggestions.sort(key=lambda s: s["match_score"], reverse=True)
            return suggestions[:10]

        except Exception as e:
            _log(f"AlertGrouper get_suggested_groups error: {e}")
            return []

    def get_incident_count(self, status=None) -> int:
        """Return total incident count, optionally filtered by status."""
        try:
            if status:
                row = self.db.execute(
                    "SELECT COUNT(*) as cnt FROM incidents WHERE status = ?", (status,)
                ).fetchone()
            else:
                row = self.db.execute("SELECT COUNT(*) as cnt FROM incidents").fetchone()
            return row["cnt"] if row else 0
        except Exception:
            return 0

    def get_incident_stats(self) -> dict:
        """Return incident statistics: counts by status."""
        try:
            rows = self.db.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM incidents GROUP BY status"""
            ).fetchall()
            stats = {"total": 0}
            for r in rows:
                stats[r["status"]] = r["cnt"]
                stats["total"] += r["cnt"]
            return stats
        except Exception:
            return {"total": 0}


# ── Alert Grouper singleton ──
_alert_grouper = None
_alert_grouper_lock = threading.Lock()


def get_alert_grouper():
    """Return the singleton AlertGrouper, creating it if needed."""
    global _alert_grouper
    if _alert_grouper is None:
        with _alert_grouper_lock:
            if _alert_grouper is None:
                _alert_grouper = AlertGrouper(get_db())
                _log("AlertGrouper initialized")
    return _alert_grouper


# ── Alert export function ──
def export_alerts(export_format="json", hours=24, severity=None, host=None,
                  category=None, limit=1000):
    """Export alerts in JSON or CSV format.

    Returns:
        tuple of (data_str, content_type, filename)
    """
    alerts = get_alerts(hours=hours, severity=severity, limit=limit)

    # Apply post-query filters (host, category) since get_alerts doesn't support them yet
    if host:
        alerts = [a for a in alerts
                  if (a.get("source_host", "") == host or a.get("source_ip", "") == host)]
    if category:
        alerts = [a for a in alerts if a.get("category", "") == category]

    if export_format == "csv":
        import csv
        import io
        output = io.StringIO()
        if alerts:
            fieldnames = list(alerts[0].keys())
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(alerts)
        csv_data = output.getvalue()
        return csv_data, "text/csv", "alerts_export.csv"

    # Default: JSON
    return json.dumps(alerts, indent=2, default=str), "application/json", "alerts_export.json"


# ── Bulk alert acknowledgment ──
def acknowledge_alerts_bulk(alert_ids: list[int]) -> dict:
    """Bulk-acknowledge multiple alerts at once.

    Returns:
        dict with acknowledged_count and failed_ids
    """
    acknowledged = 0
    failed = []
    try:
        conn = get_db()
        for aid in alert_ids:
            try:
                conn.execute(
                    "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (aid,)
                )
                acknowledged += 1
            except Exception:
                failed.append(aid)
        conn.commit()
    except Exception as e:
        _log(f"acknowledge_alerts_bulk error: {e}")
        return {"acknowledged_count": 0, "failed_ids": alert_ids}

    return {
        "acknowledged_count": acknowledged,
        "failed_ids": failed,
    }


def _collect_local_metrics():
    """Collect baseline metrics from the local host."""
    metrics = {}
    try:
        import psutil as _psutil

        # CPU percent
        metrics["cpu_percent"] = round(_psutil.cpu_percent(interval=0.1), 1)

        # RAM used GB
        mem = _psutil.virtual_memory()
        metrics["ram_used_gb"] = round(mem.used / 1024**3, 1)

        # Process count
        metrics["process_count"] = len(list(_psutil.process_iter()))

        # Network connections
        try:
            out = subprocess.check_output(
                ["ss", "-tn", "state", "established"],
                text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            metrics["network_connections"] = len(
                [line for line in out.strip().split("\n")
                 if line and not line.startswith("State")]
            )
        except Exception:
            metrics["network_connections"] = 0

        # Disk IO (need delta from previous call)
        try:
            io = _psutil.disk_io_counters()
            metrics["_disk_read_bytes"] = io.read_bytes
            metrics["_disk_write_bytes"] = io.write_bytes
            # Deltas computed by the collector
        except Exception:
            metrics["_disk_read_bytes"] = 0
            metrics["_disk_write_bytes"] = 0

    except Exception as e:
        _log(f"_collect_local_metrics error: {e}")

    return metrics


# Track previous disk IO for delta calculation
_prev_disk_io = {"read_bytes": 0, "write_bytes": 0, "ts": 0}
_prev_disk_lock = threading.Lock()


def baseline_collector():
    """Background thread: collect metrics every BASELINE_COLLECT_INTERVAL seconds,
    update baselines, and fire anomaly alerts.

    Feeds both the classic BaselineEngine (per-host, univariate) and the
    EnhancedUEBAEngine (per-entity, peer groups, composite risk scoring).
    """
    global _prev_disk_io
    if HAS_SIGMA:
        _update_collector_health('baseline', 'running')
    _log(f"baseline_collector started (interval={BASELINE_COLLECT_INTERVAL}s, "
         f"window={BASELINE_WINDOW_SECONDS}s, learning={BASELINE_LEARNING_SAMPLES})")

    host = socket.gethostname()
    engine = get_baseline_engine()
    ml_detector = get_anomaly_detector() if HAS_SKLEARN else None

    # ── Enhanced UEBA engine (per-entity baselines, peer groups, risk scoring) ──
    try:
        import ueba_engine
        enh_engine = ueba_engine.get_enhanced_ueba_engine()
        pgm = ueba_engine.get_peer_group_manager()
        scorer = ueba_engine.get_risk_scorer()
        _has_enhanced_ueba = True
    except ImportError:
        enh_engine = None
        pgm = None
        scorer = None
        _has_enhanced_ueba = False

    # Auto-assign host to peer group on first run
    if _has_enhanced_ueba and pgm:
        try:
            pgm.auto_assign_group(host, "host")
        except Exception:
            pass

    while True:
        try:
            metrics = _collect_local_metrics()
            now = time.time()

            # Compute disk IO deltas
            disk_read_kbps = 0.0
            disk_write_kbps = 0.0
            with _prev_disk_lock:
                if _prev_disk_io["ts"] > 0:
                    dt = now - _prev_disk_io["ts"]
                    if dt > 0.5:
                        dr = metrics.get("_disk_read_bytes", 0)
                        dw = metrics.get("_disk_write_bytes", 0)
                        disk_read_kbps = round(
                            (dr - _prev_disk_io["read_bytes"]) / dt / 1024, 1)
                        disk_write_kbps = round(
                            (dw - _prev_disk_io["write_bytes"]) / dt / 1024, 1)
                _prev_disk_io = {
                    "read_bytes": metrics.pop("_disk_read_bytes", 0),
                    "write_bytes": metrics.pop("_disk_write_bytes", 0),
                    "ts": now,
                }

            # Add disk IO deltas to metrics
            metrics["disk_read_kbps"] = max(0, disk_read_kbps)
            metrics["disk_write_kbps"] = max(0, disk_write_kbps)

            # Update baselines for each metric (univariate z-score)
            for metric_key in BASELINE_METRICS:
                value = metrics.get(metric_key)
                if value is None:
                    continue

                result = engine.update(host, metric_key, value, now)
                if result:
                    z_score, mean, stddev, is_learning = result
                    engine.check_and_alert(
                        host, metric_key, z_score, value, mean, stddev, is_learning
                    )

                # ── Also feed to enhanced UEBA engine ──
                if _has_enhanced_ueba and enh_engine:
                    enh_result = enh_engine.update_entity("host", host, metric_key, value, now)
                    if enh_result:
                        enh_z, enh_mean, enh_stddev, enh_learning = enh_result
                        threshold = enh_engine._get_threshold(metric_key)
                        if not enh_learning and abs(enh_z) >= threshold:
                            severity = "high" if abs(enh_z) > 5.0 else (
                                "medium" if abs(enh_z) > 4.0 else "low")
                            anomaly_type = "spike" if enh_z > 0 else "drop"
                            enh_engine.record_anomaly(
                                "host", host, metric_key, enh_z, value,
                                enh_mean, enh_stddev, severity, anomaly_type
                            )
                            # Add risk signal
                            if scorer:
                                risk_value = min(100.0, abs(enh_z) * 10)
                                scorer.add_signal("host", host, "behavioral_deviation", risk_value)

            # ── Feed to ML anomaly detector (multivariate IsolationForest) ──
            if ml_detector is not None:
                feature_vector = ml_detector._build_feature_vector(metrics)
                ml_result = ml_detector.add_sample(feature_vector)

                if ml_result and ml_result.get("is_anomaly"):
                    anomaly_score = ml_result.get("anomaly_score", 0.0)
                    severity = "high" if anomaly_score > 0.7 else (
                        "medium" if anomaly_score > 0.4 else "low")

                    create_alert(
                        severity=severity,
                        category="ueba_ml",
                        title=f"ML Anomaly Detected on {host} (score={anomaly_score:.2f})",
                        description=(
                            f"IsolationForest detected multivariate anomaly on {host}.\n"
                            f"Anomaly score: {anomaly_score:.2f}\n"
                            f"Features: CPU={metrics.get('cpu_percent')}%, "
                            f"RAM={metrics.get('ram_used_gb')}GB, "
                            f"Disk R/W={metrics.get('disk_read_kbps')}/{metrics.get('disk_write_kbps')} KB/s, "
                            f"NetConns={metrics.get('network_connections')}, "
                            f"Procs={metrics.get('process_count')}"
                        ),
                        source_host=host,
                        mitre_tactic="Discovery",
                        mitre_technique="T1082 (System Information Discovery)",
                        raw_data={
                            "anomaly_score": anomaly_score,
                            "feature_vector": feature_vector,
                            "feature_labels": ML_FEATURE_METRICS,
                            "ml_model": "IsolationForest",
                        },
                    )

                    # Add ML risk signal
                    if _has_enhanced_ueba and scorer:
                        scorer.add_signal("host", host, "behavioral_deviation",
                                          min(100.0, anomaly_score * 100))

        except Exception as e:
            _log(f"baseline_collector error: {e}")

        time.sleep(BASELINE_COLLECT_INTERVAL)


# ═══════════════════════════════════════════
# Startup
# ═══════════════════════════════════════════

_collector_threads = []
_collectors_running = False


def start_collectors():
    """Start all background collector threads."""
    global _collectors_running
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

    # Initialize baseline engine early (creates tables)
    get_baseline_engine()

    # Initialize enhanced UEBA engine (per-entity baselines, peer groups, risk scoring)
    try:
        import ueba_engine
        ueba_engine.get_enhanced_ueba_engine()
        ueba_engine.get_peer_group_manager()
        ueba_engine.get_risk_scorer()
        _log("Enhanced UEBA Engine initialized (per-entity baselines, peer groups, risk scoring)")
    except ImportError as e:
        _log(f"Enhanced UEBA Engine not available: {e}")

    # Initialize ML anomaly detector (creates model if saved, otherwise collects samples)
    get_anomaly_detector()

    # Initialize Sigma engine
    if HAS_SIGMA:
        try:
            get_sigma_engine()
            _update_collector_health('packet_sniffer', 'running')
            _log('SigmaEngine initialized successfully')
        except Exception as e:
            _log(f'SigmaEngine init error: {e}')

    # Initialize and start correlation engine
    correl = get_correlation_engine()
    correl.start()
    if HAS_SIGMA:
        _update_collector_health('correlation', 'running')

    collectors = [
        ("process_audit", process_audit_collector),
        ("beaconing", beaconing_collector),
        ("auth_monitor", auth_monitor),
        ("dns", dns_collector),
        ("file_integrity", file_integrity_collector),
        ("baseline", baseline_collector),
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
    if _correlation_engine is not None:
        try:
            _correlation_engine.stop()
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
