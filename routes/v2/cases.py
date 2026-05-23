"""
API v2 Case Management Routes — Full incident lifecycle management.

Routes:
  POST   /api/v2/cases                         — create a case
  GET    /api/v2/cases                         — list cases with filters
  GET    /api/v2/cases/metrics                 — time-to-resolution metrics
  GET    /api/v2/cases/:id                     — get case detail
  PATCH  /api/v2/cases/:id                     — update case (status, assignment, tags, etc.)
  PATCH  /api/v2/cases/bulk                    — bulk status change / assignment
  POST   /api/v2/cases/:id/notes               — add investigation note
  GET    /api/v2/cases/:id/notes               — list notes for a case
  POST   /api/v2/cases/:id/assign              — assign case to analyst
  POST   /api/v2/cases/:id/alerts              — add alerts to case
  DELETE /api/v2/cases/:id/alerts/:alert_id     — remove alert from case
  POST   /api/v2/cases/:id/merge               — merge another case into this one

Status workflow:
  New → Investigating → Escalated → Resolved → Closed
  Reopen: Resolved → Investigating, Closed → Investigating

SLA deadlines by severity:
  Critical: 1h, High: 4h, Medium: 24h, Low: 72h
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone, timedelta

from flask import jsonify, request, g

from routes.v2 import v2_bp, auth, log_api_audit

# ═══════════════════════════════════════════
# Status Workflow Definition
# ═══════════════════════════════════════════

VALID_STATUSES = ("new", "investigating", "escalated", "resolved", "closed")

STATUS_TRANSITIONS = {
    "new": ["investigating", "escalated", "resolved", "closed"],
    "investigating": ["escalated", "resolved", "closed"],
    "escalated": ["new", "investigating", "resolved", "closed"],
    "resolved": ["closed", "investigating"],
    "closed": ["investigating"],
}

VALID_PRIORITIES = ("low", "medium", "high", "critical")

SLA_DEADLINES_SECONDS = {
    "critical": 3600,     # 1 hour
    "high": 14400,        # 4 hours
    "medium": 86400,      # 24 hours
    "low": 259200,        # 72 hours
}

# ═══════════════════════════════════════════
# Case Manager Service
# ═══════════════════════════════════════════


class CaseManager:
    """Case management service — handles full incident lifecycle."""

    _instance = None
    _instance_lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        """Return the singleton CaseManager, creating it if needed."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._lock = threading.RLock()
        self._ensure_schema()

    def _get_db(self) -> sqlite3.Connection:
        """Get a connection to the detection database (alerts.db)."""
        import detection
        return detection.get_db()

    # ── Schema Migration (additive only) ──

    def _ensure_schema(self):
        """Ensure case management tables and columns exist (additive only).

        Uses executescript for atomic DDL, which is safe for concurrent access
        in WAL mode.
        """
        db = self._get_db()
        try:
            # Add missing columns to incidents table
            col_map = {
                "assignee_id": "INTEGER DEFAULT NULL",
                "priority": "TEXT DEFAULT 'medium'",
                "tags": "TEXT DEFAULT '[]'",
                "sla_deadline": "TEXT",
                "sla_breached": "INTEGER DEFAULT 0",
                "resolution": "TEXT DEFAULT ''",
                "resolved_note": "TEXT DEFAULT ''",
            }
            existing = db.execute("PRAGMA table_info(incidents)").fetchall()
            existing_names = {row["name"] for row in existing}
            for col_name, col_def in col_map.items():
                if col_name not in existing_names:
                    try:
                        db.execute(
                            f"ALTER TABLE incidents ADD COLUMN {col_name} {col_def}"
                        )
                    except sqlite3.OperationalError:
                        pass  # column already exists or other benign error

            # Create incident_notes table (IF NOT EXISTS is safe for concurrent access)
            db.execute(
                """CREATE TABLE IF NOT EXISTS incident_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    user_id INTEGER,
                    username TEXT DEFAULT '',
                    content TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                )"""
            )
            try:
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_incident_notes_incident "
                    "ON incident_notes(incident_id)"
                )
            except sqlite3.OperationalError:
                pass
            try:
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_incident_notes_created "
                    "ON incident_notes(created_at)"
                )
            except sqlite3.OperationalError:
                pass

            # Create case_audit_log table
            db.execute(
                """CREATE TABLE IF NOT EXISTS case_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    user_id INTEGER,
                    username TEXT,
                    incident_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    source_ip TEXT DEFAULT '',
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL
                )"""
            )
            try:
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_case_audit_incident "
                    "ON case_audit_log(incident_id)"
                )
            except sqlite3.OperationalError:
                pass
            try:
                db.execute(
                    "CREATE INDEX IF NOT EXISTS idx_case_audit_ts "
                    "ON case_audit_log(timestamp)"
                )
            except sqlite3.OperationalError:
                pass

            db.commit()
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            # If the error was just a duplicate column or index, ignore it
            if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                return
            raise

    # ── Audit Logging ──

    def _audit(self, incident_id: int, action: str, details: str = ""):
        """Record a case audit log entry."""
        user_id = None
        username = ""
        source_ip = ""
        if hasattr(g, "current_user") and g.current_user:
            user_id = g.current_user.get("user_id")
            username = g.current_user.get("username", "")
        if hasattr(auth, "_get_client_ip"):
            try:
                source_ip = auth._get_client_ip()
            except Exception:
                pass

        try:
            db = self._get_db()
            db.execute(
                """INSERT INTO case_audit_log
                   (user_id, username, incident_id, action, details, source_ip)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, username, incident_id, action, details, source_ip),
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    # ── SLA Calculation ──

    def _compute_sla_deadline(self, severity: str) -> str | None:
        """Compute SLA deadline ISO string from severity."""
        seconds = SLA_DEADLINES_SECONDS.get(severity)
        if seconds is None:
            return None
        deadline = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        return deadline.strftime("%Y-%m-%dT%H:%M:%SZ")

    def _check_sla_breach(self, deadline_str: str | None) -> bool:
        """Check if SLA deadline has passed."""
        if not deadline_str:
            return False
        try:
            deadline = datetime.fromisoformat(deadline_str.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > deadline
        except (ValueError, TypeError):
            return False

    # ── CRUD Operations ──

    def create_case(
        self,
        title: str,
        severity: str = "medium",
        priority: str = "medium",
        description: str = "",
        source_host: str = "",
        mitre_technique: str = "",
        alert_ids: list[int] | None = None,
        tags: list[str] | None = None,
    ) -> dict | None:
        """Create a new case with SLA tracking."""
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"
        if priority not in VALID_PRIORITIES:
            priority = "medium"

        tags_json = json.dumps(tags or [])
        sla_deadline = self._compute_sla_deadline(severity)

        with self._lock:
            db = self._get_db()
            try:
                cur = db.execute(
                    """INSERT INTO incidents
                       (title, description, severity, priority, status, source_host,
                        mitre_technique, tags, sla_deadline, sla_breached, resolution, resolved_note)
                       VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, 0, '', '')""",
                    (title, description, severity, priority, source_host,
                     mitre_technique, tags_json, sla_deadline),
                )
                db.commit()
                incident_id = cur.lastrowid

                # Link alerts if provided
                if alert_ids:
                    for aid in alert_ids:
                        try:
                            db.execute(
                                "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                                (incident_id, int(aid)),
                            )
                        except (ValueError, TypeError):
                            continue
                    db.commit()

                self._audit(incident_id, "case_created",
                            f"title='{title}' severity={severity} priority={priority}")

                return self.get_case(incident_id)
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def get_case(self, case_id: int) -> dict | None:
        """Get a case with full details: alerts, notes, SLA status."""
        db = self._get_db()
        row = db.execute(
            "SELECT * FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not row:
            return None

        case = dict(row)

        # Parse tags JSON
        try:
            case["tags"] = json.loads(case.get("tags", "[]") or "[]")
        except (json.JSONDecodeError, TypeError):
            case["tags"] = []

        # SLA fields
        sla_deadline = case.get("sla_deadline")
        case["sla_breached"] = bool(case.get("sla_breached", 0)) or self._check_sla_breach(sla_deadline)
        if sla_deadline and not case["sla_breached"]:
            try:
                dl = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
                remaining = (dl - datetime.now(timezone.utc)).total_seconds()
                case["sla_remaining_seconds"] = max(0, int(remaining))
            except (ValueError, TypeError):
                case["sla_remaining_seconds"] = 0
        else:
            case["sla_remaining_seconds"] = 0

        # Alert count and linked alerts
        alerts = db.execute(
            """SELECT a.* FROM alerts a
               JOIN incident_alerts ia ON a.id = ia.alert_id
               WHERE ia.incident_id = ?
               ORDER BY a.timestamp DESC""",
            (case_id,),
        ).fetchall()
        case["alerts"] = [dict(a) for a in alerts]
        case["alert_count"] = len(alerts)

        # Notes
        notes = db.execute(
            """SELECT * FROM incident_notes
               WHERE incident_id = ?
               ORDER BY created_at ASC""",
            (case_id,),
        ).fetchall()
        case["notes"] = [dict(n) for n in notes]

        return case

    def list_cases(
        self,
        status: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        assignee_id: int | None = None,
        tags: list[str] | None = None,
        search: str | None = None,
        host: str | None = None,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "updated_at",
        sort_dir: str = "desc",
    ) -> tuple[list[dict], int]:
        """List cases with comprehensive filtering."""
        db = self._get_db()

        where_clauses = ["1=1"]
        params = []

        if status:
            where_clauses.append("status = ?")
            params.append(status)
        if severity:
            where_clauses.append("severity = ?")
            params.append(severity)
        if priority:
            where_clauses.append("priority = ?")
            params.append(priority)
        if assignee_id is not None:
            where_clauses.append("assignee_id = ?")
            params.append(assignee_id)
        if host:
            where_clauses.append("source_host = ?")
            params.append(host)
        if search:
            where_clauses.append("(title LIKE ? OR description LIKE ?)")
            search_param = f"%{search}%"
            params.extend([search_param, search_param])
        if tags:
            for tag in tags:
                where_clauses.append("tags LIKE ?")
                params.append(f'%"{tag}"%')

        where_sql = " AND ".join(where_clauses)

        # Validate sort column
        valid_sort_cols = {"created_at", "updated_at", "severity", "status",
                           "priority", "title", "id"}
        if sort_by not in valid_sort_cols:
            sort_by = "updated_at"
        sort_dir_sql = "DESC" if sort_dir.lower() == "desc" else "ASC"

        # Count total
        count_row = db.execute(
            f"SELECT COUNT(*) as cnt FROM incidents WHERE {where_sql}",
            params,
        ).fetchone()
        total = count_row["cnt"] if count_row else 0

        # Fetch page
        rows = db.execute(
            f"""SELECT * FROM incidents
                WHERE {where_sql}
                ORDER BY {sort_by} {sort_dir_sql}
                LIMIT ? OFFSET ?""",
            params + [limit, offset],
        ).fetchall()

        cases = []
        for row in rows:
            case = dict(row)
            try:
                case["tags"] = json.loads(case.get("tags", "[]") or "[]")
            except (json.JSONDecodeError, TypeError):
                case["tags"] = []

            # Alert count
            alert_count = db.execute(
                "SELECT COUNT(*) as cnt FROM incident_alerts WHERE incident_id = ?",
                (case["id"],),
            ).fetchone()
            case["alert_count"] = alert_count["cnt"] if alert_count else 0

            # SLA
            sla_deadline = case.get("sla_deadline")
            case["sla_breached"] = bool(case.get("sla_breached", 0)) or self._check_sla_breach(sla_deadline)
            if sla_deadline and not case["sla_breached"]:
                try:
                    dl = datetime.fromisoformat(sla_deadline.replace("Z", "+00:00"))
                    remaining = (dl - datetime.now(timezone.utc)).total_seconds()
                    case["sla_remaining_seconds"] = max(0, int(remaining))
                except (ValueError, TypeError):
                    case["sla_remaining_seconds"] = 0
            else:
                case["sla_remaining_seconds"] = 0

            cases.append(case)

        return cases, total

    def update_case(self, case_id: int, updates: dict) -> tuple[dict | None, str | None]:
        """Update a case — status workflow, assignment, priority, tags, resolution.

        Returns (updated_case, error_message). On error, case is None.
        """
        db = self._get_db()
        existing = db.execute(
            "SELECT * FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not existing:
            return None, "case not found"

        # Validate status transition
        new_status = updates.get("status", "").strip().lower() if updates.get("status") else None
        if new_status and new_status not in VALID_STATUSES:
            return None, f"invalid status: must be one of {', '.join(VALID_STATUSES)}"

        if new_status:
            current_status = existing["status"]
            # Allow same-status transition (no-op)
            if new_status != current_status:
                allowed = STATUS_TRANSITIONS.get(current_status, [])
                if new_status not in allowed:
                    return None, (
                        f"invalid status transition: {current_status} → {new_status}. "
                        f"Valid transitions: {', '.join(allowed)}"
                    )

        # Validate priority
        new_priority = updates.get("priority", "").strip().lower() if updates.get("priority") else None
        if new_priority and new_priority not in VALID_PRIORITIES:
            return None, f"invalid priority: must be one of {', '.join(VALID_PRIORITIES)}"

        with self._lock:
            try:
                set_clauses = ["updated_at = datetime('now')"]
                params = []

                if new_status:
                    set_clauses.append("status = ?")
                    params.append(new_status)

                    # Handle resolution fields
                    if new_status == "resolved":
                        resolution = updates.get("resolution", "")
                        resolved_note = updates.get("resolved_note", "")
                        set_clauses.append("resolved_at = datetime('now')")
                        params.extend([resolution or "", resolved_note or ""])
                        set_clauses.append("resolution = ?")
                        set_clauses.append("resolved_note = ?")

                    elif new_status == "closed":
                        if not existing["resolved_at"]:
                            set_clauses.append("resolved_at = datetime('now')")
                        # Keep existing resolution info

                    elif new_status == "investigating":
                        if existing["status"] in ("resolved", "closed"):
                            # Reopen — keep resolution as historical note, clear resolved_at
                            set_clauses.append("resolved_at = NULL")

                    self._audit(case_id, "status_change",
                                json.dumps({"from": existing["status"], "to": new_status}))

                if new_priority:
                    set_clauses.append("priority = ?")
                    params.append(new_priority)

                # Assignee update
                if "assignee_id" in updates:
                    assignee_id = updates["assignee_id"]
                    set_clauses.append("assignee_id = ?")
                    params.append(assignee_id)
                    self._audit(case_id, "assignment",
                                f"assignee_id={assignee_id}")

                # Tags update
                if "tags" in updates:
                    tags_val = updates["tags"]
                    if isinstance(tags_val, list):
                        tags_val = json.dumps(tags_val)
                    set_clauses.append("tags = ?")
                    params.append(tags_val)

                # Description update
                if "description" in updates:
                    set_clauses.append("description = ?")
                    params.append(updates["description"])

                # Title update
                if "title" in updates and updates["title"]:
                    set_clauses.append("title = ?")
                    params.append(updates["title"])

                params.append(case_id)
                db.execute(
                    f"UPDATE incidents SET {', '.join(set_clauses)} WHERE id = ?",
                    params,
                )
                db.commit()

                return self.get_case(case_id), None
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def add_note(self, case_id: int, content: str) -> dict | None:
        """Add an investigation note to a case.

        Returns the note dict on success, None if case not found.
        """
        if not content or not content.strip():
            return None

        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not existing:
            return None

        user_id = None
        username = ""
        if hasattr(g, "current_user") and g.current_user:
            user_id = g.current_user.get("user_id")
            username = g.current_user.get("username", "")

        with self._lock:
            try:
                cur = db.execute(
                    """INSERT INTO incident_notes (incident_id, user_id, username, content)
                       VALUES (?, ?, ?, ?)""",
                    (case_id, user_id, username, content.strip()),
                )

                # Update case's updated_at timestamp
                db.execute(
                    "UPDATE incidents SET updated_at = datetime('now') WHERE id = ?",
                    (case_id,),
                )
                db.commit()

                note_id = cur.lastrowid
                self._audit(case_id, "note_added",
                            f"note_id={note_id}")

                note = db.execute(
                    "SELECT * FROM incident_notes WHERE id = ?", (note_id,)
                ).fetchone()
                return dict(note) if note else None
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def get_notes(self, case_id: int) -> list[dict] | None:
        """Get all notes for a case, ordered chronologically."""
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not existing:
            return None

        notes = db.execute(
            """SELECT * FROM incident_notes
               WHERE incident_id = ?
               ORDER BY created_at ASC""",
            (case_id,),
        ).fetchall()
        return [dict(n) for n in notes]

    def assign_case(self, case_id: int, assignee_id: int) -> dict | None:
        """Assign a case to an analyst."""
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not existing:
            return None

        with self._lock:
            try:
                db.execute(
                    "UPDATE incidents SET assignee_id = ?, updated_at = datetime('now') WHERE id = ?",
                    (assignee_id, case_id),
                )
                db.commit()
                self._audit(case_id, "assignment",
                            f"assignee_id={assignee_id}")
                return self.get_case(case_id)
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def add_alerts_to_case(self, case_id: int, alert_ids: list[int]) -> dict | None:
        """Add alerts to an existing case."""
        db = self._get_db()
        existing = db.execute(
            "SELECT id, severity FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not existing:
            return None

        with self._lock:
            try:
                count = 0
                for aid in alert_ids:
                    db.execute(
                        "INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                        (case_id, int(aid)),
                    )
                    count += db.total_changes

                # Update severity to highest among added alerts if needed
                if alert_ids:
                    max_sev = db.execute(
                        """SELECT severity FROM alerts
                           WHERE id IN ({})
                           ORDER BY CASE severity
                               WHEN 'critical' THEN 4
                               WHEN 'high' THEN 3
                               WHEN 'medium' THEN 2
                               WHEN 'low' THEN 1
                               ELSE 0 END DESC
                           LIMIT 1""".format(",".join("?" for _ in alert_ids)),
                        alert_ids,
                    ).fetchone()
                    if max_sev:
                        sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                        cur_sev = existing["severity"]
                        if sev_order.get(max_sev["severity"], 0) > sev_order.get(cur_sev, 0):
                            # Escalate severity
                            new_sev = max_sev["severity"]
                            db.execute(
                                "UPDATE incidents SET severity = ?, sla_deadline = ? WHERE id = ?",
                                (new_sev, self._compute_sla_deadline(new_sev), case_id),
                            )

                db.execute(
                    "UPDATE incidents SET updated_at = datetime('now') WHERE id = ?",
                    (case_id,),
                )
                db.commit()
                self._audit(case_id, "alerts_added",
                            f"added {len(alert_ids)} alert(s)")
                return self.get_case(case_id)
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def remove_alert_from_case(self, case_id: int, alert_id: int):
        """Remove an alert from a case. Returns (updated_case or None, error)."""
        db = self._get_db()
        existing = db.execute(
            "SELECT id FROM incidents WHERE id = ?", (case_id,)
        ).fetchone()
        if not existing:
            return None, "case not found"

        link = db.execute(
            "SELECT * FROM incident_alerts WHERE incident_id = ? AND alert_id = ?",
            (case_id, alert_id),
        ).fetchone()
        if not link:
            return None, "alert not linked to this case"

        with self._lock:
            try:
                db.execute(
                    "DELETE FROM incident_alerts WHERE incident_id = ? AND alert_id = ?",
                    (case_id, alert_id),
                )
                db.execute(
                    "UPDATE incidents SET updated_at = datetime('now') WHERE id = ?",
                    (case_id,),
                )
                db.commit()
                self._audit(case_id, "alert_removed",
                            f"alert_id={alert_id}")
                return self.get_case(case_id), None
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def merge_cases(self, target_id: int, source_id: int) -> tuple[dict | None, str | None]:
        """Merge source case into target case.

        Migrates alert associations and notes from source to target.
        Source case is NOT deleted — it's marked as resolved.
        """
        db = self._get_db()
        target = db.execute(
            "SELECT id FROM incidents WHERE id = ?", (target_id,)
        ).fetchone()
        if not target:
            return None, "target case not found"
        source = db.execute(
            "SELECT id FROM incidents WHERE id = ?", (source_id,)
        ).fetchone()
        if not source:
            return None, "source case not found"
        if source_id == target_id:
            return None, "cannot merge a case into itself"

        with self._lock:
            try:
                # Migrate alert associations
                db.execute(
                    """INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, auto_grouped)
                       SELECT ?, alert_id, 0 FROM incident_alerts
                       WHERE incident_id = ?""",
                    (target_id, source_id),
                )

                # Migrate notes (preserve original attribution)
                db.execute(
                    """UPDATE incident_notes SET incident_id = ?
                       WHERE incident_id = ?""",
                    (target_id, source_id),
                )

                # Mark source as resolved
                db.execute(
                    """UPDATE incidents
                       SET status = 'resolved',
                           resolution = ?,
                           resolved_at = datetime('now'),
                           updated_at = datetime('now')
                       WHERE id = ?""",
                    (f"Merged into case #{target_id}", source_id),
                )

                # Update target's updated_at
                db.execute(
                    "UPDATE incidents SET updated_at = datetime('now') WHERE id = ?",
                    (target_id,),
                )

                db.commit()
                self._audit(target_id, "merge",
                            f"merged case #{source_id} into this case")
                self._audit(source_id, "merged",
                            f"merged into case #{target_id}")

                return self.get_case(target_id), None
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
                raise

    def bulk_update(self, case_ids: list[int], updates: dict) -> dict:
        """Bulk update multiple cases.

        Returns: {succeeded: N, failed: M, results: [{id, success, error?}...]}
        """
        results = []
        succeeded = 0
        failed = 0

        for cid in case_ids:
            case, error = self.update_case(cid, updates)
            if case:
                results.append({"id": cid, "success": True})
                succeeded += 1
            else:
                results.append({"id": cid, "success": False, "error": error})
                failed += 1

        return {"succeeded": succeeded, "failed": failed, "results": results}

    def get_metrics(self, period_days: int = 30) -> dict:
        """Get time-to-resolution metrics grouped by severity."""
        db = self._get_db()

        metrics = {}
        for severity in ("critical", "high", "medium", "low"):
            rows = db.execute(
                """SELECT
                       (julianday(resolved_at) - julianday(created_at)) * 86400 as ttr_seconds
                   FROM incidents
                   WHERE severity = ?
                   AND resolved_at IS NOT NULL
                   AND resolved_at >= datetime('now', ?)
                   ORDER BY ttr_seconds""",
                (severity, f"-{period_days} days"),
            ).fetchall()

            ttrs = [r["ttr_seconds"] for r in rows if r["ttr_seconds"] is not None]
            ttrs.sort()

            if ttrs:
                avg = sum(ttrs) / len(ttrs)
                median = ttrs[len(ttrs) // 2]
                p95_idx = int(len(ttrs) * 0.95)
                p95 = ttrs[min(p95_idx, len(ttrs) - 1)]
                metrics[severity] = {
                    "count": len(ttrs),
                    "avg_resolution_hours": round(avg / 3600, 2),
                    "median_resolution_hours": round(median / 3600, 2),
                    "p95_resolution_hours": round(p95 / 3600, 2),
                }
            else:
                metrics[severity] = {
                    "count": 0,
                    "avg_resolution_hours": 0,
                    "median_resolution_hours": 0,
                    "p95_resolution_hours": 0,
                }

        return {
            "period_days": period_days,
            "by_severity": metrics,
        }


# ── Helper to get the CaseManager singleton ──


def _get_case_manager() -> CaseManager:
    """Return the CaseManager singleton."""
    return CaseManager.get_instance()


# ═══════════════════════════════════════════
# API Routes
# ═══════════════════════════════════════════


@v2_bp.route("/cases", methods=["POST"])
@auth.require_auth
def create_case():
    """Create a new case.

    POST body: {title, severity?, priority?, description?, source_host?,
                mitre_technique?, alert_ids?, tags?}
    """
    try:
        data = request.get_json(silent=True) or {}
        title = data.get("title", "").strip()
        if not title:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "title is required"}}), 400

        severity = data.get("severity", "medium")
        if severity not in ("critical", "high", "medium", "low"):
            severity = "medium"

        priority = data.get("priority", severity)  # default to severity level
        if priority not in VALID_PRIORITIES:
            priority = "medium"

        mgr = _get_case_manager()
        case = mgr.create_case(
            title=title,
            severity=severity,
            priority=priority,
            description=data.get("description", ""),
            source_host=data.get("source_host", ""),
            mitre_technique=data.get("mitre_technique", ""),
            alert_ids=data.get("alert_ids"),
            tags=data.get("tags"),
        )

        if case is None:
            log_api_audit("POST", "/api/v2/cases", 500)
            return jsonify({"error": {"code": "INTERNAL_ERROR", "message": "failed to create case"}}), 500

        log_api_audit("POST", "/api/v2/cases", 201,
                      details=f"case_id={case['id']}")
        return jsonify({"data": case}), 201
    except Exception as e:
        log_api_audit("POST", "/api/v2/cases", 500, details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases", methods=["GET"])
@auth.require_auth
def list_cases():
    """List cases with filters.

    Query params: status, severity, priority, assignee_id, tags, search,
                  host, limit, offset, sort_by, sort_dir
    """
    try:
        status = request.args.get("status")
        severity = request.args.get("severity")
        priority = request.args.get("priority")
        assignee_id = request.args.get("assignee_id", type=int)
        tags_str = request.args.get("tags")
        search = request.args.get("search")
        host = request.args.get("host")
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)
        sort_by = request.args.get("sort_by", "updated_at")
        sort_dir = request.args.get("sort_dir", "desc")

        # Handle "assignee=me" shortcut from VAL-CROSS-009
        if request.args.get("assignee") == "me":
            if hasattr(g, "current_user") and g.current_user:
                assignee_id = g.current_user.get("user_id")

        # Parse tags filter
        tags = None
        if tags_str:
            tags = [t.strip() for t in tags_str.split(",") if t.strip()]

        mgr = _get_case_manager()
        cases, total = mgr.list_cases(
            status=status,
            severity=severity,
            priority=priority,
            assignee_id=assignee_id,
            tags=tags,
            search=search,
            host=host,
            limit=min(limit, 500),
            offset=offset,
            sort_by=sort_by,
            sort_dir=sort_dir,
        )

        log_api_audit("GET", "/api/v2/cases", 200)
        return jsonify({
            "data": cases,
            "meta": {"total": total, "limit": limit, "offset": offset},
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/cases", 500, details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/metrics", methods=["GET"])
@auth.require_auth
def get_case_metrics():
    """Get time-to-resolution metrics.

    Query params: period_days (default 30)
    """
    try:
        period_days = request.args.get("period_days", 30, type=int)
        mgr = _get_case_manager()
        metrics = mgr.get_metrics(period_days=period_days)
        log_api_audit("GET", "/api/v2/cases/metrics", 200)
        return jsonify({"data": metrics})
    except Exception as e:
        log_api_audit("GET", "/api/v2/cases/metrics", 500, details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>", methods=["GET"])
@auth.require_auth
def get_case(case_id):
    """Get a single case with alerts, notes, and SLA status."""
    try:
        mgr = _get_case_manager()
        case = mgr.get_case(case_id)
        if case is None:
            log_api_audit("GET", f"/api/v2/cases/{case_id}", 404)
            return jsonify({"error": {"code": "NOT_FOUND", "message": "case not found"}}), 404

        log_api_audit("GET", f"/api/v2/cases/{case_id}", 200)
        return jsonify({"data": case})
    except Exception as e:
        log_api_audit("GET", f"/api/v2/cases/{case_id}", 500, details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>", methods=["PATCH"])
@auth.require_auth
def update_case(case_id):
    """Update a case — status workflow, assignment, priority, tags, resolution.

    PATCH body may include: {status, priority, assignee_id, tags, description,
                             title, resolution, resolved_note}

    Status workflow transitions:
      new → investigating, escalated, resolved, closed
      investigating → escalated, resolved, closed
      escalated → new, investigating, resolved, closed
      resolved → closed, investigating
      closed → investigating

    Resolution: when transitioning to "resolved", include {resolution: "...",
    resolved_note: "..."}
    """
    try:
        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": "request body is required"}}), 400

        mgr = _get_case_manager()
        case, error = mgr.update_case(case_id, data)

        if error:
            code = "VALIDATION_ERROR" if "invalid" in error.lower() else "NOT_FOUND"
            status_code = 400 if code == "VALIDATION_ERROR" else 404
            log_api_audit("PATCH", f"/api/v2/cases/{case_id}", status_code,
                          details=error)
            return jsonify({"error": {"code": code, "message": error}}), status_code

        log_api_audit("PATCH", f"/api/v2/cases/{case_id}", 200)
        return jsonify({"data": case})
    except Exception as e:
        log_api_audit("PATCH", f"/api/v2/cases/{case_id}", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/bulk", methods=["PATCH"])
@auth.require_auth
def bulk_update_cases():
    """Bulk update multiple cases.

    PATCH body: {ids: [1, 2, 3], status: "resolved", assignee_id: 5}

    Returns: {succeeded: N, failed: M, results: [{id, success, error?}...]}
    """
    try:
        data = request.get_json(silent=True) or {}
        case_ids = data.get("ids", [])
        if not case_ids or not isinstance(case_ids, list):
            return jsonify({
                "error": {"code": "VALIDATION_ERROR", "message": "missing or invalid ids (must be a list)"}
            }), 400

        updates = {}
        if "status" in data:
            updates["status"] = data["status"]
        if "assignee_id" in data:
            updates["assignee_id"] = data["assignee_id"]
        if "priority" in data:
            updates["priority"] = data["priority"]
        if "tags" in data:
            updates["tags"] = data["tags"]

        if not updates:
            return jsonify({
                "error": {"code": "VALIDATION_ERROR",
                          "message": "at least one of status, assignee_id, priority, tags is required"}
            }), 400

        mgr = _get_case_manager()
        result = mgr.bulk_update([int(c) for c in case_ids], updates)

        status_code = 200 if result["failed"] == 0 else 207
        log_api_audit("PATCH", "/api/v2/cases/bulk", status_code,
                      details=f"succeeded={result['succeeded']} failed={result['failed']}")
        return jsonify({"data": result}), status_code
    except Exception as e:
        log_api_audit("PATCH", "/api/v2/cases/bulk", 500, details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>/notes", methods=["POST"])
@auth.require_auth
def add_case_note(case_id):
    """Add an investigation note to a case.

    POST body: {content: "Investigation findings..."}
    """
    try:
        data = request.get_json(silent=True) or {}
        content = data.get("content", "").strip()
        if not content:
            return jsonify({
                "error": {"code": "VALIDATION_ERROR", "message": "content is required"}
            }), 400

        mgr = _get_case_manager()
        note = mgr.add_note(case_id, content)

        if note is None:
            log_api_audit("POST", f"/api/v2/cases/{case_id}/notes", 404)
            return jsonify({"error": {"code": "NOT_FOUND", "message": "case not found"}}), 404

        log_api_audit("POST", f"/api/v2/cases/{case_id}/notes", 201,
                      details=f"note_id={note['id']}")
        return jsonify({"data": note}), 201
    except Exception as e:
        log_api_audit("POST", f"/api/v2/cases/{case_id}/notes", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>/notes", methods=["GET"])
@auth.require_auth
def get_case_notes(case_id):
    """Get all notes for a case, ordered chronologically."""
    try:
        mgr = _get_case_manager()
        notes = mgr.get_notes(case_id)

        if notes is None:
            log_api_audit("GET", f"/api/v2/cases/{case_id}/notes", 404)
            return jsonify({"error": {"code": "NOT_FOUND", "message": "case not found"}}), 404

        log_api_audit("GET", f"/api/v2/cases/{case_id}/notes", 200)
        return jsonify({"data": notes})
    except Exception as e:
        log_api_audit("GET", f"/api/v2/cases/{case_id}/notes", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>/assign", methods=["POST"])
@auth.require_auth
def assign_case(case_id):
    """Assign a case to an analyst.

    POST body: {assignee_id: <user_id>}
    """
    try:
        data = request.get_json(silent=True) or {}
        assignee_id = data.get("assignee_id")
        if not assignee_id:
            return jsonify({
                "error": {"code": "VALIDATION_ERROR", "message": "assignee_id is required"}
            }), 400

        mgr = _get_case_manager()
        case = mgr.assign_case(case_id, int(assignee_id))

        if case is None:
            log_api_audit("POST", f"/api/v2/cases/{case_id}/assign", 404)
            return jsonify({"error": {"code": "NOT_FOUND", "message": "case not found"}}), 404

        log_api_audit("POST", f"/api/v2/cases/{case_id}/assign", 200,
                      details=f"assignee_id={assignee_id}")
        return jsonify({"data": case})
    except (ValueError, TypeError):
        return jsonify({
            "error": {"code": "VALIDATION_ERROR", "message": "assignee_id must be an integer"}
        }), 400
    except Exception as e:
        log_api_audit("POST", f"/api/v2/cases/{case_id}/assign", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>/alerts", methods=["POST"])
@auth.require_auth
def add_alerts_to_case(case_id):
    """Manually add alerts to an existing case.

    POST body: {alert_ids: [1, 2, 3]}
    """
    try:
        data = request.get_json(silent=True) or {}
        alert_ids = data.get("alert_ids", [])
        if not alert_ids or not isinstance(alert_ids, list):
            return jsonify({
                "error": {"code": "VALIDATION_ERROR",
                          "message": "missing or invalid alert_ids (must be a list)"}
            }), 400

        mgr = _get_case_manager()
        case = mgr.add_alerts_to_case(case_id, [int(a) for a in alert_ids])

        if case is None:
            log_api_audit("POST", f"/api/v2/cases/{case_id}/alerts", 404)
            return jsonify({"error": {"code": "NOT_FOUND", "message": "case not found"}}), 404

        log_api_audit("POST", f"/api/v2/cases/{case_id}/alerts", 200,
                      details=f"added {len(alert_ids)} alerts")
        return jsonify({"data": case})
    except (ValueError, TypeError):
        return jsonify({
            "error": {"code": "VALIDATION_ERROR", "message": "alert_ids must contain integers"}
        }), 400
    except Exception as e:
        log_api_audit("POST", f"/api/v2/cases/{case_id}/alerts", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>/alerts/<int:alert_id>", methods=["DELETE"])
@auth.require_auth
def remove_alert_from_case(case_id, alert_id):
    """Remove an alert from a case."""
    try:
        mgr = _get_case_manager()
        case, error = mgr.remove_alert_from_case(case_id, alert_id)

        if error:
            log_api_audit("DELETE",
                          f"/api/v2/cases/{case_id}/alerts/{alert_id}", 404,
                          details=error)
            return jsonify({"error": {"code": "NOT_FOUND", "message": error}}), 404

        log_api_audit("DELETE",
                      f"/api/v2/cases/{case_id}/alerts/{alert_id}", 200)
        return jsonify({"data": case})
    except Exception as e:
        log_api_audit("DELETE",
                      f"/api/v2/cases/{case_id}/alerts/{alert_id}", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500


@v2_bp.route("/cases/<int:case_id>/merge", methods=["POST"])
@auth.require_auth
def merge_cases(case_id):
    """Merge another case into this case.

    POST body: {source_case_id: <id>}
    """
    try:
        data = request.get_json(silent=True) or {}
        source_id = data.get("source_case_id")
        if not source_id:
            return jsonify({
                "error": {"code": "VALIDATION_ERROR", "message": "source_case_id is required"}
            }), 400

        mgr = _get_case_manager()
        merged, error = mgr.merge_cases(case_id, int(source_id))

        if error:
            log_api_audit("POST", f"/api/v2/cases/{case_id}/merge", 400,
                          details=error)
            return jsonify({"error": {"code": "VALIDATION_ERROR", "message": error}}), 400

        log_api_audit("POST", f"/api/v2/cases/{case_id}/merge", 200,
                      details=f"merged case #{source_id}")
        return jsonify({"data": merged})
    except (ValueError, TypeError):
        return jsonify({
            "error": {"code": "VALIDATION_ERROR", "message": "source_case_id must be an integer"}
        }), 400
    except Exception as e:
        log_api_audit("POST", f"/api/v2/cases/{case_id}/merge", 500,
                      details=str(e)[:200])
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": str(e)[:200]}}), 500
