#!/usr/bin/env python3
"""
DeepSight Sigma Rule Engine

Parses Sigma-format detection rules (YAML) and evaluates them against
ECS-normalized events. Ships with a community rule set and supports
custom user-defined rules via the API.

Sigma format reference: https://github.com/SigmaHQ/sigma
"""

import os
import re
import json
import glob
import time
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any

import yaml

# ── Shared state (set by detection.py on startup) ──
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "alerts.db")
SIGMA_RULES_DIR = os.path.join(DATA_DIR, "sigma_rules")

# ── Log function ──
def _log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[sigma-engine {ts}] {msg}", flush=True)


# ═══════════════════════════════════════════
# Sigma Condition Parser
# ═══════════════════════════════════════════

# Sigma field modifiers (map to Python matching logic)
_FIELD_MODIFIERS = {
    "contains": lambda field_val, pattern: pattern.lower() in str(field_val).lower(),
    "endswith": lambda field_val, pattern: str(field_val).lower().endswith(pattern.lower()),
    "startswith": lambda field_val, pattern: str(field_val).lower().startswith(pattern.lower()),
    "re": lambda field_val, pattern: bool(re.search(pattern, str(field_val), re.IGNORECASE)),
    "base64": lambda field_val, pattern: pattern.lower() in str(field_val).lower(),  # simplified
    "base64offset": lambda field_val, pattern: pattern.lower() in str(field_val).lower(),  # simplified
}


def _get_field_op(field_key: str):
    """Extract field name and modifier from a Sigma field key.

    Examples:
        'Image|endswith' → ('Image', 'endswith')
        'CommandLine|contains' → ('CommandLine', 'contains')
        'Image' → ('Image', None)
    """
    if "|" in field_key:
        parts = field_key.split("|")
        field_name = parts[0]
        modifier = parts[1]
        if modifier in _FIELD_MODIFIERS:
            return field_name, modifier
        return field_name, None
    return field_key, None


def _match_field(event: dict, field_name: str, expected_value: Any, modifier: str | None = None) -> bool:
    """Check if an event field matches an expected value, with optional modifier."""

    # Map Sigma field names to our event field names
    field_name_lower = field_name.lower()

    # Try exact match first
    actual_value = event.get(field_name)
    if actual_value is None:
        # Try case-insensitive key lookup
        for key in event:
            if key.lower() == field_name_lower:
                actual_value = event[key]
                break
    if actual_value is None:
        return False

    # If expected_value is a list, match any
    if isinstance(expected_value, list):
        return any(
            _match_single_field_value(actual_value, ev, modifier)
            for ev in expected_value
        )

    return _match_single_field_value(actual_value, expected_value, modifier)


def _match_single_field_value(actual_value: Any, expected_value: Any, modifier: str | None) -> bool:
    """Match a single field value against expected."""

    if modifier:
        fn = _FIELD_MODIFIERS.get(modifier)
        if fn:
            return fn(actual_value, str(expected_value))

    # Default: case-insensitive substring match
    actual_str = str(actual_value).lower()
    expected_str = str(expected_value).lower()

    # If expected contains wildcard (*), do wildcard match
    if "*" in expected_str:
        pattern = re.escape(expected_str).replace(r"\*", ".*")
        return bool(re.fullmatch(pattern, actual_str, re.IGNORECASE))

    # If both are simple, do direct comparison
    return actual_str == expected_str


def _evaluate_selection(event: dict, selection: dict) -> bool:
    """Evaluate a Sigma selection (dict of field conditions).

    All fields must match (AND logic within a selection).
    """
    if not selection:
        return False

    for field_key, expected_value in selection.items():
        field_name, modifier = _get_field_op(field_key)
        if not _match_field(event, field_name, expected_value, modifier):
            return False
    return True


def _evaluate_condition(event: dict, detection: dict, condition_name: str) -> bool:
    """Evaluate a named condition from a Sigma detection block.

    Supports:
        - Simple: condition: selection
        - OR: condition: selection1 or selection2
        - AND: condition: selection1 and selection2
        - NOT: condition: selection1 and not selection2
        - Grouped: condition: (selection1 or selection2) and not selection3
    """
    condition_str = detection.get("condition", "")
    if not condition_str:
        # Default: use the first selection
        for key in detection:
            if key != "condition" and isinstance(detection[key], dict):
                return _evaluate_selection(event, detection[key])
        return False

    if condition_name and condition_name != "condition":
        condition_str = condition_name

    # Parse the condition expression
    return _parse_condition_expr(event, detection, condition_str)


def _parse_condition_expr(event: dict, detection: dict, expr: str) -> bool:
    """Parse and evaluate a Sigma condition expression.

    Handles: 'selection', 'sel1 or sel2', 'sel1 and sel2', 'not sel1',
             '(sel1 or sel2) and not sel3', '1 of them', 'all of them',
             '1 of selection_*'
    """
    expr = expr.strip()

    # Handle keyword operators: '1 of them', 'all of them'
    if expr.endswith(" of them"):
        num_str = expr.split()[0]
        if num_str == "all":
            # Match all selections
            for key in detection:
                if key != "condition" and isinstance(detection[key], dict):
                    if not _evaluate_selection(event, detection[key]):
                        return False
            return True
        else:
            try:
                required = int(num_str)
            except ValueError:
                required = 1
            matched = 0
            for key in detection:
                if key != "condition" and isinstance(detection[key], dict):
                    if _evaluate_selection(event, detection[key]):
                        matched += 1
            return matched >= required

    # Handle wildcard selections: '1 of selection_*'
    if " of " in expr and "*" in expr:
        parts = expr.split(" of ", 1)
        prefix = parts[1].rstrip("*")
        try:
            required = int(parts[0].strip())
        except ValueError:
            required = 1
        matched = 0
        for key in detection:
            if key.startswith(prefix) and isinstance(detection[key], dict):
                if _evaluate_selection(event, detection[key]):
                    matched += 1
        return matched >= required

    # Handle parenthesized expressions
    if expr.startswith("(") and expr.endswith(")"):
        return _parse_condition_expr(event, detection, expr[1:-1].strip())

    # Handle 'not <expr>' 
    if expr.lower().startswith("not "):
        sub = expr[4:].strip()
        return not _parse_condition_expr(event, detection, sub)

    # Handle 'and' operator (lowest precedence outside parens)
    # Split on ' and ' that is NOT inside parentheses
    and_parts = _split_top_level(expr, " and ")
    if len(and_parts) > 1:
        return all(_parse_condition_expr(event, detection, p) for p in and_parts)

    # Handle 'or' operator
    or_parts = _split_top_level(expr, " or ")
    if len(or_parts) > 1:
        return any(_parse_condition_expr(event, detection, p) for p in or_parts)

    # Must be a selection name
    selection_name = expr.strip()
    if selection_name in detection and isinstance(detection[selection_name], dict):
        return _evaluate_selection(event, detection[selection_name])
    return False


def _split_top_level(expr: str, delimiter: str) -> list[str]:
    """Split a condition expression on a delimiter, respecting parentheses."""
    parts = []
    current = ""
    depth = 0
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif depth == 0 and expr[i:].lower().startswith(delimiter):
            parts.append(current.strip())
            current = ""
            i += len(delimiter) - 1
        else:
            current += ch
        i += 1
    if current.strip():
        parts.append(current.strip())
    return parts


# ═══════════════════════════════════════════
# Logsource → Event Type Mapping
# ═══════════════════════════════════════════

# Map Sigma logsource fields to our internal event types
LOGSOURCE_MAP = {
    # Sigma logsource → our event_type
    ("process_creation", "linux"): "sigma_process_event",
    ("file_event", "linux"): "sigma_file_event",
    ("network_connection", "linux"): "sigma_network_event",
    ("dns", "linux"): "sigma_dns_event",
    ("authentication", "linux"): "sigma_auth_event",
    # Catch-all
    ("*", "linux"): "sigma_event",
}

# Normalized event fields for different event types (ECS-like)
ECS_FIELD_MAP = {
    "process": {
        "Image": "process.executable",
        "CommandLine": "process.command_line",
        "ParentImage": "process.parent.executable",
        "ParentCommandLine": "process.parent.command_line",
        "User": "user.name",
        "ProcessId": "process.pid",
        "ParentProcessId": "process.parent.pid",
    },
    "file": {
        "TargetFilename": "file.path",
        "Image": "process.executable",
        "CommandLine": "process.command_line",
    },
    "network": {
        "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port",
        "SourceIp": "source.ip",
        "SourcePort": "source.port",
        "Image": "process.executable",
        "Protocol": "network.protocol",
    },
    "dns": {
        "QueryName": "dns.question.name",
        "Image": "process.executable",
    },
    "auth": {
        "User": "user.name",
        "SourceIp": "source.ip",
        "TargetUser": "user.target.name",
    },
}


def _normalize_sigma_event(event: dict, rule_logsource: dict) -> dict:
    """Normalize an event's field names for Sigma rule matching.

    Creates ECS-style aliases so Sigma rules can reference either
    the original field name or the ECS mapped field name.
    """
    normalized = dict(event)

    # Determine event category from logsource
    category = rule_logsource.get("category", "")
    product = rule_logsource.get("product", "")

    # Add ECS field aliases
    field_map = {}
    if "process" in category:
        field_map.update(ECS_FIELD_MAP.get("process", {}))
    if "file" in category:
        field_map.update(ECS_FIELD_MAP.get("file", {}))
    if "network" in category or "net" in category:
        field_map.update(ECS_FIELD_MAP.get("network", {}))
    if "dns" in category:
        field_map.update(ECS_FIELD_MAP.get("dns", {}))

    # Always add the most common mappings
    for sigma_name, ecs_name in field_map.items():
        if ecs_name in event:
            normalized[sigma_name] = event[ecs_name]

    # Add lowercase variants for case-insensitive matching
    for key in list(normalized.keys()):
        normalized[key.lower()] = normalized[key]

    return normalized


# ═══════════════════════════════════════════
# Sigma Rule Engine
# ═══════════════════════════════════════════

class SigmaRule:
    """Represents a parsed Sigma rule."""

    def __init__(self, rule_dict: dict, file_path: str = "", is_custom: bool = False):
        self.raw = rule_dict
        self.file_path = file_path
        self.is_custom = is_custom
        self.title = rule_dict.get("title", "Untitled Rule")
        self.rule_id = rule_dict.get("id", "")
        self.status = rule_dict.get("status", "stable")
        self.level = rule_dict.get("level", "medium")
        self.description = rule_dict.get("description", "")
        self.author = rule_dict.get("author", "")
        self.tags = rule_dict.get("tags", [])
        self.falsepositives = rule_dict.get("falsepositives", [])
        self.logsource = rule_dict.get("logsource", {})
        self.detection = rule_dict.get("detection", {})
        self.enabled = True  # runtime toggle

        # Extract MITRE ATT&CK techniques from tags
        self.mitre_tactics = []
        self.mitre_techniques = []
        for tag in self.tags:
            if tag.startswith("attack.t"):
                # Format: attack.tXXXX or attack.tactic_name
                tech_id = tag.replace("attack.", "")
                self.mitre_techniques.append(tech_id)

        # Map Sigma level to our severity
        self.severity = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "low",
        }.get(self.level, "medium")

    def evaluate(self, event: dict) -> list[dict] | None:
        """Evaluate this rule against an event.

        Returns a list of matched alert dicts or None.
        """
        if not self.enabled:
            return None

        # Check logsource match
        logsource_cat = self.logsource.get("category", "")
        event_type = event.get("event_type", "")

        # Logsource filtering — accept both Sigma-standard and our internal event types
        if logsource_cat and event_type:
            if logsource_cat == "process_creation" and event_type not in (
                "sigma_process_event", "process_creation", "process", "process_audit",
                "sigma_event", "reverse_shell", "webshell", "process_from_suspect_dir",
                "hidden_cmdline", "suspicious_execution",
            ):
                return None
            if logsource_cat == "file_event" and event_type not in (
                "sigma_file_event", "file_event", "file_integrity", "sigma_event",
                "sudoers_change", "authorized_keys_change",
            ):
                return None
            if logsource_cat == "network_connection" and event_type not in (
                "sigma_network_event", "network_connection", "network", "beaconing",
                "sigma_event",
            ):
                return None
            if logsource_cat == "dns" and event_type not in (
                "sigma_dns_event", "dns", "sigma_event", "dga",
            ):
                return None
            if logsource_cat == "authentication" and event_type not in (
                "sigma_auth_event", "authentication", "auth", "sigma_event",
                "ssh_brute_force", "ssh_fail", "ssh_success", "sudo", "su",
            ):
                return None

        # Normalize event fields
        norm_event = _normalize_sigma_event(event, self.logsource)

        # Evaluate detection
        if not self.detection:
            return None

        matched = _evaluate_condition(norm_event, self.detection, "")
        
        if matched:
            return [{
                "title": self.title,
                "description": self.description or f"Sigma rule matched: {self.title}",
                "severity": self.severity,
                "category": "sigma",
                "mitre_tactic": ", ".join(self.mitre_tactics) if self.mitre_tactics else "Sigma Detection",
                "mitre_technique": ", ".join(self.mitre_techniques) if self.mitre_techniques else "",
                "rule_id": self.rule_id,
                "rule_file": os.path.basename(self.file_path) if self.file_path else "",
                "raw_data": {
                    "sigma_id": self.rule_id,
                    "sigma_title": self.title,
                    "sigma_level": self.level,
                    "file_path": self.file_path,
                },
            }]

        return None

    def to_dict(self) -> dict:
        """Serializable representation."""
        return {
            "id": self.rule_id,
            "title": self.title,
            "status": self.status,
            "level": self.level,
            "severity": self.severity,
            "description": self.description,
            "author": self.author,
            "tags": self.tags,
            "falsepositives": self.falsepositives,
            "logsource": self.logsource,
            "detection": self.detection,
            "enabled": self.enabled,
            "is_custom": self.is_custom,
            "file_path": self.file_path,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
        }


class SigmaEngine:
    """Manages Sigma rules: loading, evaluation, CRUD."""

    def __init__(self, rules_dir: str = SIGMA_RULES_DIR):
        self.rules_dir = rules_dir
        self.rules: list[SigmaRule] = []
        self.custom_rules: list[SigmaRule] = []
        self.lock = threading.Lock()
        self._load_builtin_rules()
        self._load_custom_rules()

    def _load_builtin_rules(self) -> None:
        """Load community Sigma rules from the rules directory."""
        if not os.path.isdir(self.rules_dir):
            _log(f"Sigma rules directory not found: {self.rules_dir}")
            return

        count = 0
        for yaml_file in sorted(glob.glob(os.path.join(self.rules_dir, "*.yml"))) + \
                         sorted(glob.glob(os.path.join(self.rules_dir, "*.yaml"))):
            try:
                with open(yaml_file) as f:
                    data = yaml.safe_load(f)
                if data and isinstance(data, dict) and "title" in data:
                    rule = SigmaRule(data, file_path=yaml_file)
                    self.rules.append(rule)
                    count += 1
            except yaml.YAMLError as e:
                _log(f"YAML parse error in {yaml_file}: {e}")
            except Exception as e:
                _log(f"Error loading {yaml_file}: {e}")

        _log(f"Loaded {count} built-in Sigma rules from {self.rules_dir}")

    def _load_custom_rules(self) -> None:
        """Load custom rules from SQLite database."""
        try:
            conn = self._get_db()
            rows = conn.execute(
                "SELECT id, rule_yaml, enabled FROM sigma_rules_table"
            ).fetchall()
            for row in rows:
                try:
                    data = yaml.safe_load(row["rule_yaml"])
                    if data and isinstance(data, dict) and "title" in data:
                        rule = SigmaRule(data, file_path=f"custom:{row['id']}", is_custom=True)
                        rule.enabled = bool(row["enabled"])
                        self.custom_rules.append(rule)
                except Exception as e:
                    _log(f"Error parsing custom rule {row['id']}: {e}")
            if rows:
                _log(f"Loaded {len(rows)} custom Sigma rules from database")
        except Exception as e:
            _log(f"Error loading custom rules: {e}")

    def _get_db(self):
        """Get a SQLite connection."""
        os.makedirs(DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        self._ensure_sigma_tables(conn)
        return conn

    def _ensure_sigma_tables(self, conn):
        """Create Sigma-related tables if they don't exist."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sigma_rules_table (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_yaml TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                level TEXT DEFAULT 'medium',
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS sigma_rule_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                event_data TEXT NOT NULL DEFAULT '{}',
                matched_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (rule_id) REFERENCES sigma_rules_table(id)
            );
        """)
        conn.commit()

    def evaluate(self, event: dict) -> list[dict]:
        """Evaluate all enabled Sigma rules against an event.

        Returns a list of matched rule dicts compatible with create_alert().
        """
        results = []

        # Evaluate built-in rules
        with self.lock:
            for rule in self.rules:
                try:
                    match = rule.evaluate(event)
                    if match:
                        results.extend(match)
                except Exception as e:
                    _log(f"Error evaluating rule {rule.title}: {e}")

            # Evaluate custom rules
            for rule in self.custom_rules:
                try:
                    match = rule.evaluate(event)
                    if match:
                        results.extend(match)
                except Exception as e:
                    _log(f"Error evaluating custom rule {rule.title}: {e}")

        return results

    def get_all_rules(self) -> list[dict]:
        """Return all rules (builtin + custom) as dicts."""
        with self.lock:
            return [r.to_dict() for r in self.rules] + [r.to_dict() for r in self.custom_rules]

    def add_custom_rule(self, yaml_str: str) -> tuple[dict | None, str | None]:
        """Add a custom Sigma rule from YAML string.

        Returns (rule_dict, error_message).
        """
        try:
            data = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            return None, f"Invalid YAML: {e}"

        if not data or not isinstance(data, dict):
            return None, "Rule must be a YAML dictionary"

        if "title" not in data:
            return None, "Rule must have a 'title' field"

        # Generate an ID if not present
        if "id" not in data:
            import uuid
            data["id"] = str(uuid.uuid4())

        try:
            conn = self._get_db()
            cur = conn.execute(
                """INSERT INTO sigma_rules_table (rule_yaml, title, level)
                   VALUES (?, ?, ?)""",
                (yaml_str, data["title"], data.get("level", "medium"))
            )
            conn.commit()
            rule_id = cur.lastrowid
        except Exception as e:
            return None, f"Database error: {e}"

        # Load into memory
        rule = SigmaRule(data, file_path=f"custom:{rule_id}", is_custom=True)
        rule.enabled = True
        with self.lock:
            self.custom_rules.append(rule)

        _log(f"Added custom Sigma rule: {data['title']} (id={rule_id})")
        return rule.to_dict(), None

    def delete_custom_rule(self, rule_id: str) -> bool:
        """Delete a custom Sigma rule by its Sigma ID."""
        with self.lock:
            for i, rule in enumerate(self.custom_rules):
                if rule.rule_id == rule_id:
                    # Remove from DB
                    try:
                        conn = self._get_db()
                        conn.execute(
                            "DELETE FROM sigma_rules_table WHERE id = ?",
                            (int(rule.file_path.split(":")[1]),)
                        )
                        conn.commit()
                    except Exception:
                        pass
                    self.custom_rules.pop(i)
                    _log(f"Deleted custom Sigma rule: {rule.title}")
                    return True
        return False

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule by its Sigma ID."""
        with self.lock:
            # Check built-in
            for rule in self.rules:
                if rule.rule_id == rule_id:
                    rule.enabled = enabled
                    _log(f"Rule '{rule.title}' {'enabled' if enabled else 'disabled'}")
                    return True

            # Check custom
            for rule in self.custom_rules:
                if rule.rule_id == rule_id:
                    rule.enabled = enabled
                    try:
                        conn = self._get_db()
                        conn.execute(
                            "UPDATE sigma_rules_table SET enabled = ?, updated_at = datetime('now') WHERE id = ?",
                            (1 if enabled else 0, int(rule.file_path.split(":")[1]))
                        )
                        conn.commit()
                    except Exception:
                        pass
                    _log(f"Custom rule '{rule.title}' {'enabled' if enabled else 'disabled'}")
                    return True

        return False

    def get_rule_count(self) -> dict:
        """Return rule counts by type."""
        with self.lock:
            builtin_enabled = sum(1 for r in self.rules if r.enabled)
            custom_enabled = sum(1 for r in self.custom_rules if r.enabled)
            return {
                "builtin_total": len(self.rules),
                "builtin_enabled": builtin_enabled,
                "custom_total": len(self.custom_rules),
                "custom_enabled": custom_enabled,
                "total": len(self.rules) + len(self.custom_rules),
                "total_enabled": builtin_enabled + custom_enabled,
            }


# ── Singleton instance ──
_sigma_engine: SigmaEngine | None = None
_sigma_lock = threading.Lock()


def get_sigma_engine() -> SigmaEngine:
    """Return the singleton SigmaEngine, creating it if needed."""
    global _sigma_engine
    if _sigma_engine is None:
        with _sigma_lock:
            if _sigma_engine is None:
                _sigma_engine = SigmaEngine()
                _log("SigmaEngine initialized")
    return _sigma_engine


def evaluate_sigma(event: dict) -> list[dict]:
    """Convenience function: evaluate an event against all Sigma rules.

    This is the main entry point called by detection.py.
    """
    try:
        engine = get_sigma_engine()
        return engine.evaluate(event)
    except Exception as e:
        _log(f"sigma_engine.evaluate_sigma error: {e}")
        return []
