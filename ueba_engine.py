#!/usr/bin/env python3
"""
Enhanced UEBA Engine — Per-entity baselines, peer groups, composite risk scoring.

Extends the original BaselineEngine with:
- Per-entity baselines (per user, per host)
- Peer group assignment and comparison
- Composite risk scoring with exponential decay
- UEBA anomaly management (acknowledge, promote, false positive)
"""

import re
import time
import math
import threading
from collections import defaultdict
from datetime import datetime, timezone


# ── Shared _log helper ──
def _log(msg):
    """Timestamped log to stdout."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ueba-engine {ts}] {msg}", flush=True)


# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════

UEBA_WINDOW_SECONDS = 3600       # 1 hour rolling window
UEBA_LEARNING_SAMPLES = 30       # no alerts until N samples
UEBA_Z_THRESHOLD = 3.0           # default z-score threshold
UEBA_COLLECT_INTERVAL = 30       # seconds between samples

# Per-metric z-score thresholds
UEBA_Z_THRESHOLDS = {
    "cpu_percent": 3.0,
    "ram_used_gb": 3.5,
    "disk_read_kbps": 4.0,
    "disk_write_kbps": 4.0,
    "network_connections": 3.5,
    "process_count": 3.0,
    "login_count_per_hour": 3.5,
    "commands_per_hour": 3.0,
    "sudo_count_per_hour": 4.0,
    "failed_auth_per_hour": 3.0,
    "outbound_connections": 3.5,
    "disk_io_mbps": 4.0,
}

# Human-readable metric labels
UEBA_METRIC_LABELS = {
    "cpu_percent": "CPU %",
    "ram_used_gb": "RAM Used (GB)",
    "disk_read_kbps": "Disk Read (KB/s)",
    "disk_write_kbps": "Disk Write (KB/s)",
    "network_connections": "Network Connections",
    "process_count": "Process Count",
    "login_count_per_hour": "Logins / Hour",
    "commands_per_hour": "Commands / Hour",
    "sudo_count_per_hour": "Sudo / Hour",
    "failed_auth_per_hour": "Failed Auth / Hour",
    "outbound_connections": "Outbound Connections",
    "disk_io_mbps": "Disk I/O (MB/s)",
}

# Default thresholds for risk levels (upper bounds for classification)
DEFAULT_RISK_THRESHOLDS = {
    "critical": 80,   # >= 80 is critical
    "moderate": 60,   # >= 60 is moderate
    "elevated": 30,   # >= 30 is elevated
    # below 30 is normal
}

# Default risk score decay half-life in hours
DEFAULT_DECAY_HALF_LIFE_HOURS = 24.0

# Notification threshold for high-risk anomalies
DEFAULT_NOTIFICATION_THRESHOLD = 70.0

# ── Default peer group patterns for auto-assignment ──
_PEER_GROUP_PATTERNS = [
    (re.compile(r'(\w+)-web\d*', re.I), 'web_servers'),
    (re.compile(r'(\w+)-db\d*', re.I), 'database_servers'),
    (re.compile(r'(\w+)-app\d*', re.I), 'application_servers'),
    (re.compile(r'(\w+)-worker\d*', re.I), 'worker_nodes'),
    (re.compile(r'(\w+)-lb\d*', re.I), 'load_balancers'),
    (re.compile(r'(\w+)-cache\d*', re.I), 'cache_nodes'),
    (re.compile(r'(\w+)-mon\d*', re.I), 'monitoring_nodes'),
    (re.compile(r'prod-(\w+)', re.I), 'production'),
    (re.compile(r'staging-(\w+)', re.I), 'staging'),
    (re.compile(r'dev-(\w+)', re.I), 'development'),
    (re.compile(r'(\w+)-\d+', re.I), None),  # fallback: use prefix
]


# ═══════════════════════════════════════════
# Enhanced UEBA Engine — per-entity baselines
# ═══════════════════════════════════════════

class EnhancedUEBAEngine:
    """Per-entity (user + host) behavioral baseline engine.

    Maintains rolling z-score baselines for each entity × metric combination.
    Supports entity types: 'host', 'user', 'process'.

    Compared to BaselineEngine, this adds:
    - Entity type dimension (user vs host vs process)
    - Entity search and listing
    - Peer group integration
    - Anomaly management (acknowledge, promote, false positive)
    - Expanded anomaly timeline and deviation tables
    """

    def __init__(self, db_conn):
        self.db = db_conn
        # samples[(entity_type, entity_id)][metric] = [(timestamp, value), ...]
        self.samples = defaultdict(lambda: defaultdict(list))
        self.lock = threading.Lock()
        self._create_tables()
        self._prune_old_anomalies()

    def _create_tables(self):
        """Create UEBA tables."""
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS ueba_entity_baselines (
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                count INTEGER DEFAULT 0,
                mean REAL DEFAULT 0.0,
                variance REAL DEFAULT 0.0,
                stddev REAL DEFAULT 0.0,
                last_value REAL DEFAULT 0.0,
                is_learning INTEGER DEFAULT 1,
                last_updated TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (entity_type, entity_id, metric)
            );

            CREATE TABLE IF NOT EXISTS ueba_peer_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                entity_type TEXT NOT NULL DEFAULT 'host',
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ueba_peer_group_members (
                group_name TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_type TEXT NOT NULL DEFAULT 'host',
                auto_assigned INTEGER DEFAULT 1,
                assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_name, entity_id, entity_type),
                FOREIGN KEY (group_name) REFERENCES ueba_peer_groups(name)
            );

            CREATE TABLE IF NOT EXISTS ueba_anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                entity_type TEXT NOT NULL DEFAULT 'host',
                entity_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                z_score REAL NOT NULL,
                current_value REAL NOT NULL,
                mean REAL NOT NULL,
                stddev REAL NOT NULL,
                severity TEXT DEFAULT 'medium',
                anomaly_type TEXT DEFAULT 'spike',
                acknowledged INTEGER DEFAULT 0,
                is_false_positive INTEGER DEFAULT 0,
                false_positive_reason TEXT DEFAULT '',
                promoted_alert_id INTEGER,
                acknowledged_at TEXT,
                acknowledged_by TEXT
            );

            CREATE TABLE IF NOT EXISTS ueba_risk_scores (
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                risk_score REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'normal',
                behavioral_score REAL DEFAULT 0.0,
                threat_intel_score REAL DEFAULT 0.0,
                alert_score REAL DEFAULT 0.0,
                peer_outlier_score REAL DEFAULT 0.0,
                last_updated TEXT NOT NULL DEFAULT (datetime('now')),
                prev_risk_score REAL DEFAULT 0.0,
                prev_risk_level TEXT DEFAULT 'normal',
                PRIMARY KEY (entity_type, entity_id)
            );

            CREATE TABLE IF NOT EXISTS ueba_risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                old_score REAL,
                new_score REAL,
                old_level TEXT,
                new_level TEXT,
                trigger_type TEXT,
                trigger_detail TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_ts
                ON ueba_anomalies(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_entity
                ON ueba_anomalies(entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_type
                ON ueba_anomalies(entity_type);
            CREATE INDEX IF NOT EXISTS idx_ueba_anomalies_severity
                ON ueba_anomalies(severity);
            CREATE INDEX IF NOT EXISTS idx_ueba_risk_history_entity
                ON ueba_risk_history(entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_ueba_risk_history_ts
                ON ueba_risk_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ueba_baselines_entity
                ON ueba_entity_baselines(entity_type, entity_id);
        """)
        self.db.commit()

    def _prune_old_anomalies(self):
        """Remove anomalies older than 30 days."""
        try:
            self.db.execute(
                "DELETE FROM ueba_anomalies WHERE timestamp < datetime('now', '-30 days')"
            )
            self.db.commit()
        except Exception:
            pass

    # ── Entity Baseline Operations ──

    def update_entity(self, entity_type, entity_id, metric, value, timestamp=None):
        """Add a sample for an entity metric and return (z_score, mean, stddev, is_learning)."""
        if timestamp is None:
            timestamp = time.time()

        with self.lock:
            key = (entity_type, entity_id)
            samples = self.samples[key][metric]
            samples.append((timestamp, float(value)))

            # Prune old samples
            cutoff = timestamp - UEBA_WINDOW_SECONDS
            samples[:] = [(ts, v) for ts, v in samples if ts > cutoff]

            count = len(samples)
            if count < 2:
                self._save_entity_state(entity_type, entity_id, metric, count, value,
                                        0, 0, value, timestamp, True)
                return None

            vals = [v for _, v in samples]
            mean = sum(vals) / count
            variance = sum((v - mean) ** 2 for v in vals) / count

            if variance > 1e-9:
                stddev = math.sqrt(variance)
                z_score = (float(value) - mean) / stddev
            else:
                stddev = 0.0
                z_score = 0.0

            is_learning = count < UEBA_LEARNING_SAMPLES

            self._save_entity_state(entity_type, entity_id, metric, count, mean,
                                    variance, stddev, value, timestamp, is_learning)

            return (z_score, mean, stddev, is_learning)

    def _save_entity_state(self, entity_type, entity_id, metric, count, mean,
                           variance, stddev, last_value, timestamp, is_learning):
        """Persist entity baseline state to SQLite."""
        try:
            now_ts = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ")
            self.db.execute("""
                INSERT INTO ueba_entity_baselines
                (entity_type, entity_id, metric, count, mean, variance, stddev,
                 last_value, is_learning, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_type, entity_id, metric) DO UPDATE SET
                    count = excluded.count,
                    mean = excluded.mean,
                    variance = excluded.variance,
                    stddev = excluded.stddev,
                    last_value = excluded.last_value,
                    is_learning = excluded.is_learning,
                    last_updated = excluded.last_updated
            """, (entity_type, entity_id, metric, count, mean, variance, stddev,
                  last_value, 1 if is_learning else 0, now_ts))
            self.db.commit()
        except Exception as e:
            _log(f"EnhancedUEBAEngine _save_entity_state error: {e}")

    def record_anomaly(self, entity_type, entity_id, metric, z_score, current_value,
                       mean, stddev, severity="medium", anomaly_type="spike"):
        """Record an anomaly event in the database."""
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self.db.execute("""
                INSERT INTO ueba_anomalies
                (timestamp, entity_type, entity_id, metric, z_score,
                 current_value, mean, stddev, severity, anomaly_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now_ts, entity_type, entity_id, metric, round(z_score, 3),
                  round(current_value, 2), round(mean, 2),
                  round(stddev, 2), severity, anomaly_type))
            self.db.commit()
        except Exception as e:
            _log(f"record_anomaly error: {e}")

    # ── Query Methods ──

    def get_entity_baselines(self, entity_type=None, entity_id=None, metric=None):
        """Get entity baseline states with optional filtering."""
        results = []
        mem_keys = set()

        with self.lock:
            for (et, eid), metrics in self.samples.items():
                if entity_type and et != entity_type:
                    continue
                if entity_id and eid != entity_id:
                    continue
                for m, samples in metrics.items():
                    if metric and m != metric:
                        continue
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
                    is_learning = count < UEBA_LEARNING_SAMPLES
                    z = (last_val - mean) / stddev if stddev > 1e-9 else 0.0

                    mem_keys.add((et, eid, m))
                    results.append(self._format_baseline(et, eid, m, count, mean,
                                                         stddev, last_val, z, is_learning))

        # Add persisted baselines not in memory
        try:
            query = "SELECT * FROM ueba_entity_baselines WHERE 1=1"
            params = []
            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)
            if entity_id:
                query += " AND entity_id = ?"
                params.append(entity_id)
            if metric:
                query += " AND metric = ?"
                params.append(metric)
            query += " ORDER BY entity_type, entity_id, metric"

            rows = self.db.execute(query, params).fetchall()
            for r in rows:
                key = (r["entity_type"], r["entity_id"], r["metric"])
                if key not in mem_keys:
                    r_mean = r["mean"]
                    r_stddev = r["stddev"]
                    r_last = r["last_value"]
                    is_learning = bool(r["is_learning"])
                    z_db = ((r_last - r_mean) / r_stddev) if r_stddev > 1e-9 and not is_learning else 0.0
                    results.append(self._format_baseline(
                        r["entity_type"], r["entity_id"], r["metric"],
                        r["count"], r_mean, r_stddev, r_last, z_db, is_learning
                    ))
        except Exception:
            pass

        results.sort(key=lambda x: (x["entity_type"], x["entity_id"], x["metric"]))
        return results

    def _format_baseline(self, entity_type, entity_id, metric, count, mean,
                         stddev, last_val, z_score, is_learning):
        """Format a baseline entry for API response."""
        threshold = UEBA_Z_THRESHOLDS.get(metric, UEBA_Z_THRESHOLD)
        label = UEBA_METRIC_LABELS.get(metric, metric)

        # Compute risk score for this baseline (0-100)
        risk_score = 0.0
        if not is_learning and abs(z_score) > 0:
            risk_score = min(100.0, (abs(z_score) / threshold) * 50.0)

        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "metric": metric,
            "label": label,
            "count": count,
            "mean": round(mean, 2),
            "stddev": round(stddev, 2),
            "current_value": round(last_val, 2),
            "z_score": round(z_score, 3),
            "deviation_pct": round((last_val - mean) / mean * 100, 1) if mean > 1e-9 else 0.0,
            "is_learning": is_learning,
            "threshold": threshold,
            "risk_score": round(risk_score, 1),
            "risk_level": self._risk_level(risk_score),
        }

    def _risk_level(self, score):
        """Map numeric score to risk level."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "moderate"
        elif score >= 30:
            return "elevated"
        return "normal"

    def _get_threshold(self, metric):
        """Get the z-score threshold for a metric."""
        return UEBA_Z_THRESHOLDS.get(metric, UEBA_Z_THRESHOLD)

    def list_entities(self, entity_type=None):
        """List all tracked entities with their types and metric counts."""
        results = []
        try:
            query = """
                SELECT entity_type, entity_id, COUNT(*) as metric_count,
                       SUM(CASE WHEN is_learning=0 THEN 1 ELSE 0 END) as active_count,
                       MAX(last_updated) as last_updated
                FROM ueba_entity_baselines
                WHERE 1=1
            """
            params = []
            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)
            query += " GROUP BY entity_type, entity_id ORDER BY entity_type, entity_id"

            rows = self.db.execute(query, params).fetchall()
            for r in rows:
                # Get risk score for this entity
                risk = self.db.execute(
                    "SELECT risk_score, risk_level FROM ueba_risk_scores WHERE entity_type=? AND entity_id=?",
                    (r["entity_type"], r["entity_id"])
                ).fetchone()

                results.append({
                    "entity_type": r["entity_type"],
                    "entity_id": r["entity_id"],
                    "metric_count": r["metric_count"],
                    "active_baselines": r["active_count"],
                    "learning_baselines": r["metric_count"] - r["active_count"],
                    "last_updated": r["last_updated"],
                    "risk_score": round(risk["risk_score"], 1) if risk else 0.0,
                    "risk_level": risk["risk_level"] if risk else "normal",
                })
        except Exception as e:
            _log(f"list_entities error: {e}")
        return results

    def search_entities(self, query):
        """Search entities by name (partial match)."""
        try:
            rows = self.db.execute("""
                SELECT DISTINCT entity_type, entity_id
                FROM ueba_entity_baselines
                WHERE entity_id LIKE ?
                ORDER BY entity_type, entity_id
                LIMIT 50
            """, (f"%{query}%",)).fetchall()

            results = []
            for r in rows:
                risk = self.db.execute(
                    "SELECT risk_score, risk_level FROM ueba_risk_scores WHERE entity_type=? AND entity_id=?",
                    (r["entity_type"], r["entity_id"])
                ).fetchone()
                results.append({
                    "entity_type": r["entity_type"],
                    "entity_id": r["entity_id"],
                    "risk_score": round(risk["risk_score"], 1) if risk else 0.0,
                    "risk_level": risk["risk_level"] if risk else "normal",
                })
            return results
        except Exception as e:
            _log(f"search_entities error: {e}")
            return []

    def get_anomalies(self, entity_type=None, entity_id=None, metric=None,
                      severity=None, acknowledged=None, hours=24,
                      limit=100, offset=0, sort_by="timestamp", sort_order="desc"):
        """Query anomalies with comprehensive filtering and pagination."""
        try:
            query = "SELECT * FROM ueba_anomalies WHERE timestamp >= datetime('now', ?) "
            params = [f"-{hours} hours"]

            if entity_type:
                query += "AND entity_type = ? "
                params.append(entity_type)
            if entity_id:
                query += "AND entity_id = ? "
                params.append(entity_id)
            if metric:
                query += "AND metric = ? "
                params.append(metric)
            if severity:
                query += "AND severity = ? "
                params.append(severity)
            if acknowledged is not None:
                query += "AND acknowledged = ? "
                params.append(1 if acknowledged else 0)

            # Sanitize sort column
            allowed_sort = {"timestamp", "z_score", "severity", "entity_id", "entity_type"}
            sort_col = sort_by if sort_by in allowed_sort else "timestamp"
            sort_dir = "DESC" if sort_order.lower() == "desc" else "ASC"
            query += f"ORDER BY {sort_col} {sort_dir} LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = self.db.execute(query, params).fetchall()
            return [self._format_anomaly(r) for r in rows]
        except Exception as e:
            _log(f"get_anomalies error: {e}")
            return []

    def get_anomaly_count(self, entity_type=None, entity_id=None, hours=24):
        """Get total anomaly count for pagination."""
        try:
            query = "SELECT COUNT(*) as cnt FROM ueba_anomalies WHERE timestamp >= datetime('now', ?) "
            params = [f"-{hours} hours"]
            if entity_type:
                query += "AND entity_type = ? "
                params.append(entity_type)
            if entity_id:
                query += "AND entity_id = ? "
                params.append(entity_id)
            row = self.db.execute(query, params).fetchone()
            return row["cnt"] if row else 0
        except Exception:
            return 0

    def _format_anomaly(self, r):
        """Format an anomaly row for API response."""
        return {
            "id": r["id"],
            "timestamp": r["timestamp"],
            "entity_type": r["entity_type"],
            "entity_id": r["entity_id"],
            "metric": r["metric"],
            "label": UEBA_METRIC_LABELS.get(r["metric"], r["metric"]),
            "z_score": r["z_score"],
            "current_value": r["current_value"],
            "mean": r["mean"],
            "stddev": r["stddev"],
            "severity": r["severity"],
            "anomaly_type": r["anomaly_type"],
            "acknowledged": bool(r["acknowledged"]),
            "is_false_positive": bool(r["is_false_positive"]),
            "false_positive_reason": r["false_positive_reason"],
            "promoted_alert_id": r["promoted_alert_id"],
            "acknowledged_at": r["acknowledged_at"],
            "acknowledged_by": r["acknowledged_by"],
        }

    # ── Anomaly Actions ──

    def acknowledge_anomaly(self, anomaly_id, username=None):
        """Acknowledge a single anomaly."""
        try:
            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.db.execute("""
                UPDATE ueba_anomalies
                SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
                WHERE id = ? AND acknowledged = 0
            """, (now_ts, username, anomaly_id))
            self.db.commit()
            return self.db.total_changes > 0
        except Exception as e:
            _log(f"acknowledge_anomaly error: {e}")
            return False

    def acknowledge_anomalies_bulk(self, anomaly_ids, username=None):
        """Acknowledge multiple anomalies in bulk."""
        try:
            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            acknowledged = 0
            for aid in anomaly_ids:
                self.db.execute("""
                    UPDATE ueba_anomalies
                    SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ?
                    WHERE id = ? AND acknowledged = 0
                """, (now_ts, username, aid))
                if self.db.total_changes > acknowledged:
                    acknowledged += 1
            self.db.commit()
            return {"acknowledged": acknowledged, "total": len(anomaly_ids)}
        except Exception as e:
            _log(f"acknowledge_anomalies_bulk error: {e}")
            return {"acknowledged": 0, "total": len(anomaly_ids)}

    def promote_to_alert(self, anomaly_id):
        """Promote an anomaly to an alert (creates alert via detection.py pipeline)."""
        try:
            # Get anomaly details
            anomaly = self.db.execute(
                "SELECT * FROM ueba_anomalies WHERE id = ?", (anomaly_id,)
            ).fetchone()
            if not anomaly:
                return False

            # Import detection module to create alert
            try:
                import detection
                alert = detection.create_alert(
                    severity=anomaly["severity"],
                    category="ueba_promoted",
                    title=f"Promoted UEBA Anomaly: {anomaly['entity_id']} — {anomaly['metric']}",
                    description=(
                        f"UEBA anomaly promoted to alert.\n"
                        f"Entity: {anomaly['entity_type']}/{anomaly['entity_id']}\n"
                        f"Metric: {anomaly['metric']} (z={anomaly['z_score']:.2f})\n"
                        f"Current: {anomaly['current_value']:.2f} | "
                        f"Baseline: {anomaly['mean']:.2f} ± {anomaly['stddev']:.2f}"
                    ),
                    source_host=anomaly["entity_id"] if anomaly["entity_type"] == "host" else "",
                    mitre_tactic="Discovery",
                    mitre_technique="T1082 (System Information Discovery)",
                    raw_data={
                        "anomaly_id": anomaly_id,
                        "entity_type": anomaly["entity_type"],
                        "entity_id": anomaly["entity_id"],
                        "metric": anomaly["metric"],
                        "z_score": anomaly["z_score"],
                    },
                )
                alert_id = alert["id"] if alert else None
            except ImportError:
                alert_id = None

            # Mark anomaly as promoted
            self.db.execute("""
                UPDATE ueba_anomalies
                SET promoted_alert_id = ?
                WHERE id = ?
            """, (alert_id, anomaly_id))
            self.db.commit()
            return True
        except Exception as e:
            _log(f"promote_to_alert error: {e}")
            return False

    def mark_false_positive(self, anomaly_id, reason=""):
        """Mark an anomaly as a false positive."""
        try:
            self.db.execute("""
                UPDATE ueba_anomalies
                SET is_false_positive = 1, false_positive_reason = ?
                WHERE id = ?
            """, (reason[:500], anomaly_id))
            self.db.commit()
            return self.db.total_changes > 0
        except Exception as e:
            _log(f"mark_false_positive error: {e}")
            return False

    def reset_entity_baseline(self, entity_type, entity_id, metric=None):
        """Reset baselines for an entity (optionally per metric)."""
        try:
            if metric:
                self.db.execute("""
                    DELETE FROM ueba_entity_baselines
                    WHERE entity_type = ? AND entity_id = ? AND metric = ?
                """, (entity_type, entity_id, metric))
            else:
                # Reset all metrics: set is_learning=1, keep last_value
                self.db.execute("""
                    UPDATE ueba_entity_baselines
                    SET is_learning = 1, count = 0, mean = 0, variance = 0, stddev = 0
                    WHERE entity_type = ? AND entity_id = ?
                """, (entity_type, entity_id))

            # Also clear in-memory samples
            with self.lock:
                key = (entity_type, entity_id)
                if key in self.samples:
                    if metric and metric in self.samples[key]:
                        del self.samples[key][metric]
                    elif not metric:
                        del self.samples[key]

            self.db.commit()
            return True
        except Exception as e:
            _log(f"reset_entity_baseline error: {e}")
            return False

    # ── Peer Group Comparison ──

    def get_peer_comparison(self, entity_type, entity_id, group_name, metric):
        """Compare entity's metric against peer group statistics."""
        try:
            pgm = PeerGroupManager(self.db)
            members = pgm.get_group_members(group_name)
            peer_ids = [m["entity_id"] for m in members if m["entity_id"] != entity_id]

            if not peer_ids:
                return None

            # Get entity's current value
            entity_baseline = self.db.execute(
                "SELECT * FROM ueba_entity_baselines WHERE entity_type=? AND entity_id=? AND metric=?",
                (entity_type, entity_id, metric)
            ).fetchone()
            if not entity_baseline:
                return None

            entity_value = entity_baseline["last_value"]
            entity_mean = entity_baseline["mean"]

            # Get peer baselines
            placeholders = ",".join("?" * len(peer_ids))
            peer_rows = self.db.execute(
                f"""SELECT * FROM ueba_entity_baselines
                    WHERE entity_type=? AND metric=? AND entity_id IN ({placeholders})
                    AND is_learning = 0""",
                [entity_type, metric] + peer_ids
            ).fetchall()

            if len(peer_rows) < 2:
                return None

            peer_means = [r["mean"] for r in peer_rows]
            peer_values = [r["last_value"] for r in peer_rows]

            peer_mean = sum(peer_means) / len(peer_means)
            peer_stddev = math.sqrt(
                sum((m - peer_mean) ** 2 for m in peer_means) / len(peer_means)
            ) if len(peer_means) > 1 else 0.0

            # Percentile of entity value among peers
            all_values = sorted(peer_values + [entity_value])
            rank = all_values.index(entity_value)
            percentile = round(rank / (len(all_values) - 1) * 100, 1) if len(all_values) > 1 else 50.0

            return {
                "entity_value": round(entity_value, 2),
                "entity_mean": round(entity_mean, 2),
                "peer_mean": round(peer_mean, 2),
                "peer_stddev": round(peer_stddev, 2),
                "peer_count": len(peer_rows),
                "percentile": percentile,
                "deviation_from_peer": round(entity_value - peer_mean, 2),
                "z_vs_peers": round((entity_value - peer_mean) / peer_stddev, 3) if peer_stddev > 1e-9 else 0.0,
            }
        except Exception as e:
            _log(f"get_peer_comparison error: {e}")
            return None

    # ── Timeline and Deviations ──

    def get_anomaly_timeline(self, hours=24, entity_type=None, bucket_minutes=60):
        """Get anomaly timeline data bucketed by time for charting."""
        try:
            query = """
                SELECT
                    strftime('%Y-%m-%dT%H', timestamp) || ':' ||
                    printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / ?) * ?) as bucket,
                    severity, COUNT(*) as count
                FROM ueba_anomalies
                WHERE timestamp >= datetime('now', ?)
            """
            params = [bucket_minutes, bucket_minutes, f"-{hours} hours"]

            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)

            query += " GROUP BY bucket, severity ORDER BY bucket ASC"
            rows = self.db.execute(query, params).fetchall()

            # Build timeline structure
            buckets = {}
            for r in rows:
                b = r["bucket"]
                if b not in buckets:
                    buckets[b] = {}
                buckets[b][r["severity"]] = r["count"]

            sorted_buckets = sorted(buckets.keys())
            all_severities = ["critical", "high", "medium", "low"]

            timeline = {
                "labels": sorted_buckets,
                "total": sum(
                    buckets.get(b, {}).get(s, 0)
                    for b in sorted_buckets
                    for s in all_severities
                ),
            }
            for sev in all_severities:
                timeline[sev] = [buckets.get(b, {}).get(sev, 0) for b in sorted_buckets]

            timeline["counts"] = [
                sum(buckets.get(b, {}).get(s, 0) for s in all_severities)
                for b in sorted_buckets
            ]

            return timeline
        except Exception as e:
            _log(f"get_anomaly_timeline error: {e}")
            return {"labels": [], "counts": [], "total": 0,
                    "critical": [], "high": [], "medium": [], "low": []}

    def get_deviations(self, entity_type=None, sort_by="risk_score", sort_order="desc",
                       limit=100):
        """Get deviation table: entities sorted by risk/severity."""
        baselines = self.get_entity_baselines(entity_type=entity_type)

        # Filter out learning baselines
        active = [b for b in baselines if not b["is_learning"]]

        # Sort
        reverse = sort_order.lower() == "desc"
        if sort_by == "risk_score":
            active.sort(key=lambda x: x["risk_score"], reverse=reverse)
        elif sort_by == "z_score":
            active.sort(key=lambda x: abs(x["z_score"]), reverse=reverse)
        elif sort_by == "entity_id":
            active.sort(key=lambda x: x["entity_id"], reverse=reverse)
        elif sort_by == "deviation_pct":
            active.sort(key=lambda x: abs(x["deviation_pct"]), reverse=reverse)

        # Compute trend direction for each entity
        result = []
        for b in active[:limit]:
            # Get previous z-score for trend
            prev = self._get_previous_zscore(b["entity_type"], b["entity_id"], b["metric"])
            trend = "stable"
            if prev is not None:
                if abs(b["z_score"]) > abs(prev) + 0.3:
                    trend = "rising"
                elif abs(b["z_score"]) < abs(prev) - 0.3:
                    trend = "falling"

            result.append({**b, "trend": trend})

        return result

    def _get_previous_zscore(self, entity_type, entity_id, metric):
        """Get the previous z-score for trend calculation."""
        try:
            rows = self.db.execute(
                """SELECT z_score FROM ueba_anomalies
                   WHERE entity_type=? AND entity_id=? AND metric=?
                   ORDER BY timestamp DESC LIMIT 1""",
                (entity_type, entity_id, metric)
            ).fetchall()
            if rows:
                return rows[0]["z_score"]
            return None
        except Exception:
            return None

    # ── Health and Export ──

    def get_ueba_health(self):
        """Get comprehensive UEBA health metrics."""
        try:
            entities = self.list_entities()
            baselines = self.get_entity_baselines()
            anomalies_24h = self.get_anomalies(hours=24)
            anomaly_count_24h = len(anomalies_24h)

            # Active vs learning baselines
            active = sum(1 for b in baselines if not b["is_learning"])
            learning = sum(1 for b in baselines if b["is_learning"])

            # False positive rate
            fp_count = self.db.execute(
                "SELECT COUNT(*) as cnt FROM ueba_anomalies WHERE is_false_positive=1"
            ).fetchone()["cnt"]
            total_anomalies = self.db.execute(
                "SELECT COUNT(*) as cnt FROM ueba_anomalies"
            ).fetchone()["cnt"]
            fp_rate = round(fp_count / total_anomalies * 100, 1) if total_anomalies > 0 else 0.0

            # Entity type breakdown
            entity_type_counts = {}
            for e in entities:
                et = e["entity_type"]
                entity_type_counts[et] = entity_type_counts.get(et, 0) + 1

            # Average z-score
            scores = [a["z_score"] for a in anomalies_24h if a.get("z_score")]
            avg_z = round(sum(scores) / len(scores), 3) if scores else 0.0

            return {
                "entities_monitored": len(entities),
                "entity_type_breakdown": entity_type_counts,
                "baselines_total": len(baselines),
                "baselines_active": active,
                "baselines_learning": learning,
                "anomalies_24h": anomaly_count_24h,
                "anomaly_score_mean": avg_z,
                "false_positive_rate": fp_rate,
                "false_positives": fp_count,
                "risk_entities": {
                    "critical": sum(1 for e in entities if e.get("risk_level") == "critical"),
                    "moderate": sum(1 for e in entities if e.get("risk_level") == "moderate"),
                    "elevated": sum(1 for e in entities if e.get("risk_level") == "elevated"),
                    "normal": sum(1 for e in entities if e.get("risk_level") == "normal"),
                },
                "config": {
                    "window_seconds": UEBA_WINDOW_SECONDS,
                    "learning_samples": UEBA_LEARNING_SAMPLES,
                    "default_z_threshold": UEBA_Z_THRESHOLD,
                },
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        except Exception as e:
            _log(f"get_ueba_health error: {e}")
            return {"error": str(e)}

    def export_data(self, entity_type=None, format="json", hours=168):
        """Export UEBA data as JSON or CSV."""
        anomalies = self.get_anomalies(entity_type=entity_type, hours=hours, limit=10000)
        baselines = self.get_entity_baselines(entity_type=entity_type)

        if format == "csv":
            import csv
            import io
            output = io.StringIO()
            writer = csv.writer(output)

            # Header
            writer.writerow([
                "id", "timestamp", "entity_type", "entity_id", "metric",
                "z_score", "current_value", "mean", "stddev", "severity",
                "anomaly_type", "acknowledged", "is_false_positive"
            ])
            for a in anomalies:
                writer.writerow([
                    a["id"], a["timestamp"], a["entity_type"], a["entity_id"],
                    a["metric"], a["z_score"], a["current_value"], a["mean"],
                    a["stddev"], a["severity"], a["anomaly_type"],
                    a["acknowledged"], a["is_false_positive"]
                ])
            return output.getvalue()

        # JSON format
        return {
            "anomalies": anomalies,
            "baselines": baselines,
            "entity_count": len(self.list_entities(entity_type=entity_type)),
            "exported_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "hours": hours,
        }


# ═══════════════════════════════════════════
# Peer Group Manager
# ═══════════════════════════════════════════

class PeerGroupManager:
    """Manages peer groups for entity comparison.

    Supports:
    - Auto-assignment based on hostname patterns
    - Manual assignment
    - Group listing and membership queries
    """

    def __init__(self, db_conn):
        self.db = db_conn
        self._ensure_tables()

    def _ensure_tables(self):
        """Ensure peer group tables exist."""
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS ueba_peer_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                entity_type TEXT NOT NULL DEFAULT 'host',
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS ueba_peer_group_members (
                group_name TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_type TEXT NOT NULL DEFAULT 'host',
                auto_assigned INTEGER DEFAULT 1,
                assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (group_name, entity_id, entity_type)
            );
        """)
        self.db.commit()

    def auto_assign_group(self, entity_id, entity_type="host"):
        """Auto-assign entity to a peer group based on name patterns.

        Returns the group name or None if no pattern matches.
        """
        for pattern, group_name in _PEER_GROUP_PATTERNS:
            match = pattern.search(entity_id)
            if match:
                if group_name is None:
                    # Fallback: use the matched prefix
                    group_name = match.group(1).lower()
                self.assign_entity(entity_id, group_name, entity_type, auto=True)
                return group_name

        # No pattern matched, use entity_type as group
        fallback = f"ungrouped_{entity_type}s"
        self.assign_entity(entity_id, fallback, entity_type, auto=True)
        return fallback

    def assign_entity(self, entity_id, group_name, entity_type="host", auto=True):
        """Assign an entity to a peer group."""
        try:
            # Ensure group exists
            self.db.execute("""
                INSERT OR IGNORE INTO ueba_peer_groups (name, entity_type)
                VALUES (?, ?)
            """, (group_name, entity_type))

            # Assign entity
            self.db.execute("""
                INSERT OR REPLACE INTO ueba_peer_group_members
                (group_name, entity_id, entity_type, auto_assigned, assigned_at)
                VALUES (?, ?, ?, ?, datetime('now'))
            """, (group_name, entity_id, entity_type, 1 if auto else 0))
            self.db.commit()
        except Exception as e:
            _log(f"PeerGroupManager assign_entity error: {e}")

    def get_group_members(self, group_name):
        """Get all members of a peer group."""
        try:
            rows = self.db.execute(
                "SELECT * FROM ueba_peer_group_members WHERE group_name = ?",
                (group_name,)
            ).fetchall()
            return [{"entity_id": r["entity_id"], "entity_type": r["entity_type"],
                     "auto_assigned": bool(r["auto_assigned"]),
                     "assigned_at": r["assigned_at"]} for r in rows]
        except Exception as e:
            _log(f"get_group_members error: {e}")
            return []

    def get_entity_group(self, entity_id, entity_type="host"):
        """Get the peer group for an entity."""
        try:
            row = self.db.execute(
                "SELECT group_name FROM ueba_peer_group_members WHERE entity_id=? AND entity_type=?",
                (entity_id, entity_type)
            ).fetchone()
            return row["group_name"] if row else None
        except Exception:
            return None

    def list_groups(self, entity_type=None):
        """List all peer groups with member counts."""
        try:
            query = """
                SELECT g.name, g.entity_type, g.description, g.created_at,
                       COUNT(m.entity_id) as member_count
                FROM ueba_peer_groups g
                LEFT JOIN ueba_peer_group_members m ON g.name = m.group_name
            """
            params = []
            if entity_type:
                query += " WHERE g.entity_type = ?"
                params.append(entity_type)
            query += " GROUP BY g.name ORDER BY g.entity_type, g.name"

            rows = self.db.execute(query, params).fetchall()
            return [{
                "name": r["name"],
                "entity_type": r["entity_type"],
                "description": r["description"] or "",
                "created_at": r["created_at"],
                "member_count": r["member_count"],
            } for r in rows]
        except Exception as e:
            _log(f"list_groups error: {e}")
            return []


# ═══════════════════════════════════════════
# Composite Risk Scorer
# ═══════════════════════════════════════════

class RiskScorer:
    """Composite entity risk scoring with exponential decay.

    Aggregates multiple risk factors:
    - Behavioral deviation (z-score based)
    - Threat intelligence matches
    - Recent alert count
    - Peer group outlier status

    Scores decay exponentially over time with a configurable half-life.
    """

    def __init__(self, db_conn, decay_half_life_hours=DEFAULT_DECAY_HALF_LIFE_HOURS,
                 thresholds=None, notification_threshold=DEFAULT_NOTIFICATION_THRESHOLD):
        self.db = db_conn
        self.decay_half_life = decay_half_life_hours
        self.thresholds = thresholds or DEFAULT_RISK_THRESHOLDS
        self.notification_threshold = notification_threshold
        self._ensure_tables()

    def _ensure_tables(self):
        """Ensure risk score tables exist."""
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS ueba_risk_scores (
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                risk_score REAL DEFAULT 0.0,
                risk_level TEXT DEFAULT 'normal',
                behavioral_score REAL DEFAULT 0.0,
                threat_intel_score REAL DEFAULT 0.0,
                alert_score REAL DEFAULT 0.0,
                peer_outlier_score REAL DEFAULT 0.0,
                last_updated TEXT NOT NULL DEFAULT (datetime('now')),
                prev_risk_score REAL DEFAULT 0.0,
                prev_risk_level TEXT DEFAULT 'normal',
                PRIMARY KEY (entity_type, entity_id)
            );
            CREATE TABLE IF NOT EXISTS ueba_risk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                old_score REAL,
                new_score REAL,
                old_level TEXT,
                new_level TEXT,
                trigger_type TEXT,
                trigger_detail TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ueba_risk_history_entity
                ON ueba_risk_history(entity_type, entity_id);
            CREATE INDEX IF NOT EXISTS idx_ueba_risk_history_ts
                ON ueba_risk_history(timestamp);
        """)
        self.db.commit()

    def add_signal(self, entity_type, entity_id, signal_type, value):
        """Add a risk signal for an entity.

        signal_type: one of 'behavioral_deviation', 'threat_intel_match',
                     'alert_count', 'peer_outlier'
        value: 0-100 score for this signal (directly stored as factor contribution)
        """
        try:
            value = max(0.0, min(100.0, float(value)))

            # Get current state
            row = self.db.execute(
                "SELECT * FROM ueba_risk_scores WHERE entity_type=? AND entity_id=?",
                (entity_type, entity_id)
            ).fetchone()

            if row:
                # Update existing — use max to keep peak signal value
                behavioral = row["behavioral_score"]
                threat_intel = row["threat_intel_score"]
                alert_s = row["alert_score"]
                peer = row["peer_outlier_score"]

                if signal_type == "behavioral_deviation":
                    behavioral = max(behavioral, value)
                elif signal_type == "threat_intel_match":
                    threat_intel = max(threat_intel, value)
                elif signal_type == "alert_count":
                    alert_s = max(alert_s, value)
                elif signal_type == "peer_outlier":
                    peer = max(peer, value)
            else:
                # New entity
                behavioral = value if signal_type == "behavioral_deviation" else 0.0
                threat_intel = value if signal_type == "threat_intel_match" else 0.0
                alert_s = value if signal_type == "alert_count" else 0.0
                peer = value if signal_type == "peer_outlier" else 0.0

            # Composite score: weighted sum of all factor scores (0-100 scale).
            # Each factor is already a 0-100 score; weight them to get final composite.
            weights = {
                "behavioral": 0.40,
                "threat_intel": 0.25,
                "alerts": 0.20,
                "peer_outlier": 0.15,
            }
            composite = (
                behavioral * weights["behavioral"] +
                threat_intel * weights["threat_intel"] +
                alert_s * weights["alerts"] +
                peer * weights["peer_outlier"]
            )
            composite = max(0.0, min(100.0, composite))

            # Determine risk level
            level = self._compute_level(composite)

            # Save
            prev_score = row["risk_score"] if row else 0.0
            prev_level = row["risk_level"] if row else "normal"

            now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            self.db.execute("""
                INSERT INTO ueba_risk_scores
                (entity_type, entity_id, risk_score, risk_level,
                 behavioral_score, threat_intel_score, alert_score, peer_outlier_score,
                 last_updated, prev_risk_score, prev_risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(entity_type, entity_id) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    behavioral_score = excluded.behavioral_score,
                    threat_intel_score = excluded.threat_intel_score,
                    alert_score = excluded.alert_score,
                    peer_outlier_score = excluded.peer_outlier_score,
                    last_updated = excluded.last_updated,
                    prev_risk_score = excluded.prev_risk_score,
                    prev_risk_level = excluded.prev_risk_level
            """, (entity_type, entity_id, round(composite, 1), level,
                  round(behavioral, 1), round(threat_intel, 1),
                  round(alert_s, 1), round(peer, 1),
                  now_ts, round(prev_score, 1), prev_level))
            self.db.commit()

            # Record history if score changed significantly or level changed
            if abs(composite - prev_score) > 1.0 or level != prev_level:
                self._record_history(entity_type, entity_id, prev_score, composite,
                                     prev_level, level, signal_type,
                                     f"Signal: {signal_type}={value:.1f}")
        except Exception as e:
            _log(f"RiskScorer add_signal error: {e}")

    def _compute_level(self, score):
        """Compute risk level from score using configured thresholds."""
        for level in ["critical", "moderate", "elevated"]:
            threshold = self.thresholds.get(level, 80)
            if score >= threshold:
                return level
        return "normal"

    def get_risk_score(self, entity_type, entity_id):
        """Get current risk score for an entity with decay applied."""
        try:
            row = self.db.execute(
                "SELECT * FROM ueba_risk_scores WHERE entity_type=? AND entity_id=?",
                (entity_type, entity_id)
            ).fetchone()

            if not row:
                return {
                    "risk_score": 0.0,
                    "risk_level": "normal",
                    "factors": {
                        "behavioral": 0.0,
                        "threat_intel": 0.0,
                        "alerts": 0.0,
                        "peer_outlier": 0.0,
                    },
                    "decayed": False,
                    "notify": False,
                }

            # Apply time decay
            last_updated_str = row["last_updated"]
            try:
                # Try ISO format: 2026-05-23T06:49:33Z
                if "T" in last_updated_str:
                    last_updated = datetime.strptime(
                        last_updated_str.replace("Z", ""), "%Y-%m-%dT%H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                else:
                    # Try SQLite format: 2026-05-23 06:49:33
                    last_updated = datetime.strptime(
                        last_updated_str, "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                elapsed_hours = (datetime.now(timezone.utc) - last_updated).total_seconds() / 3600
            except (ValueError, TypeError):
                elapsed_hours = 0

            # Exponential decay: score * (1/2)^(elapsed / half_life)
            if elapsed_hours > 0 and self.decay_half_life > 0:
                decay_factor = 0.5 ** (elapsed_hours / self.decay_half_life)
                decayed_score = round(row["risk_score"] * decay_factor, 1)
                decayed = decayed_score < row["risk_score"]
            else:
                decayed_score = round(row["risk_score"], 1)
                decayed = False

            # Decay individual factors
            def _decay(val):
                if elapsed_hours > 0 and self.decay_half_life > 0:
                    return round(val * (0.5 ** (elapsed_hours / self.decay_half_life)), 1)
                return round(val, 1)

            level = self._compute_level(decayed_score)

            result = {
                "risk_score": decayed_score,
                "risk_level": level,
                "factors": {
                    "behavioral": _decay(row["behavioral_score"]),
                    "threat_intel": _decay(row["threat_intel_score"]),
                    "alerts": _decay(row["alert_score"]),
                    "peer_outlier": _decay(row["peer_outlier_score"]),
                },
                "decayed": decayed,
                "last_updated": row["last_updated"],
                "notify": decayed_score >= self.notification_threshold,
            }

            # Update stored score if decay changed it significantly
            if abs(decayed_score - row["risk_score"]) > 1.0:
                self.db.execute("""
                    UPDATE ueba_risk_scores
                    SET risk_score = ?, risk_level = ?, last_updated = datetime('now'),
                        prev_risk_score = ?, prev_risk_level = ?
                    WHERE entity_type=? AND entity_id=?
                """, (decayed_score, level, row["risk_score"], row["risk_level"],
                      entity_type, entity_id))
                self.db.commit()

            return result
        except Exception as e:
            _log(f"RiskScorer get_risk_score error: {e}")
            return {"risk_score": 0.0, "risk_level": "normal",
                    "factors": {}, "decayed": False, "notify": False}

    def get_risk_trend(self, entity_type, entity_id, hours=24):
        """Get risk score trend with direction indicator."""
        try:
            current = self.get_risk_score(entity_type, entity_id)

            # Get previous score from history
            hist_row = self.db.execute("""
                SELECT old_score FROM ueba_risk_history
                WHERE entity_type=? AND entity_id=?
                ORDER BY timestamp DESC LIMIT 1
            """, (entity_type, entity_id)).fetchone()

            previous = round(hist_row["old_score"], 1) if hist_row else current["risk_score"]

            if current["risk_score"] > previous + 2:
                direction = "rising"
            elif current["risk_score"] < previous - 2:
                direction = "falling"
            else:
                direction = "stable"

            # Get history points for sparkline
            history = self.get_risk_history(entity_type, entity_id, hours=hours)

            return {
                "current": current["risk_score"],
                "previous": previous,
                "direction": direction,
                "current_level": current["risk_level"],
                "history": [{"timestamp": h["timestamp"], "score": h["new_score"]}
                            for h in history[-48:]],  # last 48 points
            }
        except Exception as e:
            _log(f"get_risk_trend error: {e}")
            return {"current": 0.0, "previous": 0.0, "direction": "stable",
                    "current_level": "normal", "history": []}

    def get_risk_history(self, entity_type, entity_id, hours=24):
        """Get risk score change history."""
        try:
            rows = self.db.execute("""
                SELECT * FROM ueba_risk_history
                WHERE entity_type=? AND entity_id=?
                  AND timestamp >= datetime('now', ?)
                ORDER BY timestamp DESC LIMIT 200
            """, (entity_type, entity_id, f"-{hours} hours")).fetchall()

            return [{
                "id": r["id"],
                "timestamp": r["timestamp"],
                "entity_type": r["entity_type"],
                "entity_id": r["entity_id"],
                "old_score": r["old_score"],
                "new_score": r["new_score"],
                "old_level": r["old_level"],
                "new_level": r["new_level"],
                "trigger_type": r["trigger_type"],
                "trigger_detail": r["trigger_detail"],
            } for r in rows]
        except Exception as e:
            _log(f"get_risk_history error: {e}")
            return []

    def _record_history(self, entity_type, entity_id, old_score, new_score,
                        old_level, new_level, trigger_type, trigger_detail):
        """Record a risk score change in history."""
        try:
            self.db.execute("""
                INSERT INTO ueba_risk_history
                (timestamp, entity_type, entity_id, old_score, new_score,
                 old_level, new_level, trigger_type, trigger_detail)
                VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?)
            """, (entity_type, entity_id, round(old_score, 1), round(new_score, 1),
                  old_level, new_level, trigger_type, trigger_detail[:500]))
            self.db.commit()
        except Exception as e:
            _log(f"_record_history error: {e}")

    def list_all_scores(self, entity_type=None, sort_by="risk_score", sort_order="desc",
                        limit=100):
        """List risk scores for all entities."""
        try:
            query = "SELECT * FROM ueba_risk_scores WHERE risk_score > 0"
            params = []
            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)
            query += f" ORDER BY {sort_by} {sort_order} LIMIT ?"
            params.append(limit)

            rows = self.db.execute(query, params).fetchall()
            results = []
            for r in rows:
                # Apply decay
                score = self.get_risk_score(r["entity_type"], r["entity_id"])
                results.append({
                    "entity_type": r["entity_type"],
                    "entity_id": r["entity_id"],
                    "risk_score": score["risk_score"],
                    "risk_level": score["risk_level"],
                    "factors": score["factors"],
                    "decayed": score["decayed"],
                    "notify": score["notify"],
                    "last_updated": r["last_updated"],
                })
            return results
        except Exception as e:
            _log(f"list_all_scores error: {e}")
            return []


# ═══════════════════════════════════════════
# Singleton access
# ═══════════════════════════════════════════

_enhanced_ueba_engine = None
_peer_group_manager = None
_risk_scorer = None
_ueba_lock = threading.Lock()


def get_enhanced_ueba_engine(db_conn=None):
    """Get or create the singleton EnhancedUEBAEngine."""
    global _enhanced_ueba_engine
    if _enhanced_ueba_engine is None:
        with _ueba_lock:
            if _enhanced_ueba_engine is None:
                if db_conn is None:
                    import detection
                    db_conn = detection.get_db()
                _enhanced_ueba_engine = EnhancedUEBAEngine(db_conn)
                _log("EnhancedUEBAEngine initialized")
    return _enhanced_ueba_engine


def get_peer_group_manager(db_conn=None):
    """Get or create the singleton PeerGroupManager."""
    global _peer_group_manager
    if _peer_group_manager is None:
        with _ueba_lock:
            if _peer_group_manager is None:
                if db_conn is None:
                    import detection
                    db_conn = detection.get_db()
                _peer_group_manager = PeerGroupManager(db_conn)
                _log("PeerGroupManager initialized")
    return _peer_group_manager


def get_risk_scorer(db_conn=None):
    """Get or create the singleton RiskScorer."""
    global _risk_scorer
    if _risk_scorer is None:
        with _ueba_lock:
            if _risk_scorer is None:
                if db_conn is None:
                    import detection
                    db_conn = detection.get_db()
                _risk_scorer = RiskScorer(db_conn)
                _log("RiskScorer initialized")
    return _risk_scorer
