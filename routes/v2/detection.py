"""
API v2 Detection Routes — Sigma rules, custom detection rules, collector health.

Routes:
  GET  /api/v2/detection/rules        — list all detection rules
  POST /api/v2/detection/rules        — create custom detection rule
  PATCH /api/v2/detection/rules/:id   — update rule (enable/disable, modify)
  DELETE /api/v2/detection/rules/:id  — delete custom rule
  GET  /api/v2/sigma/rules            — list Sigma rules
  POST /api/v2/sigma/rules            — add custom Sigma rule YAML
  DELETE /api/v2/sigma/rules/:id      — delete custom Sigma rule
  PATCH /api/v2/sigma/rules/:id/toggle — enable/disable Sigma rule
  GET  /api/v2/detection/collectors   — collector health status
"""

import threading
import time

from flask import jsonify, request

from routes.v2 import v2_bp, auth, log_api_audit, require_permission
from sigma_engine import get_sigma_engine

# ═══════════════════════════════════════════
# Collector Health Tracking
# ═══════════════════════════════════════════

# Track collector health: {collector_name: {status, last_execution, execution_count, error_count, last_error}}
_collector_health: dict[str, dict] = {}
_collector_health_lock = threading.Lock()


def init_collector_health():
    """Initialize collector health tracking for all known collectors."""
    collectors = [
        ("process_audit", "Process Auditor"),
        ("beaconing", "Beaconing Analyzer"),
        ("auth_monitor", "Auth Monitor"),
        ("dns", "DNS Monitor"),
        ("file_integrity", "File Integrity"),
        ("packet_sniffer", "Packet Sniffer"),
        ("baseline", "UEBA Baseline Collector"),
        ("correlation", "Correlation Engine"),
    ]
    with _collector_health_lock:
        for key, name in collectors:
            if key not in _collector_health:
                _collector_health[key] = {
                    "name": name,
                    "status": "unknown",
                    "last_execution": None,
                    "execution_count": 0,
                    "error_count": 0,
                    "last_error": None,
                }


def update_collector_health(collector_name: str, status: str = "running",
                           error: str | None = None):
    """Update the health status of a collector from within detection.py."""
    with _collector_health_lock:
        if collector_name not in _collector_health:
            _collector_health[collector_name] = {
                "name": collector_name,
                "status": "unknown",
                "last_execution": None,
                "execution_count": 0,
                "error_count": 0,
                "last_error": None,
            }
        h = _collector_health[collector_name]
        h["status"] = status
        h["last_execution"] = time.time()
        if status == "running":
            h["execution_count"] += 1
        if error:
            h["error_count"] += 1
            h["last_error"] = error[:500]
            h["status"] = "error"


# Initialize on import
init_collector_health()


# ═══════════════════════════════════════════
# Detection Rules Endpoints (VAL-SEC-057)
# ═══════════════════════════════════════════

@v2_bp.route("/detection/rules")
@auth.require_auth
def list_detection_rules():
    """List all detection rules (built-in + custom) with metadata.

    GET /api/v2/detection/rules
    Returns array of rule objects with: name, category, severity, enabled, last_modified.
    """
    try:
        engine = get_sigma_engine()
        rules = engine.get_all_rules()

        # Format for detection rules API
        formatted = []
        for r in rules:
            formatted.append({
                "id": r["id"],
                "name": r["title"],
                "category": "sigma",
                "severity": r["severity"],
                "enabled": r["enabled"],
                "is_custom": r["is_custom"],
                "status": r["status"],
                "description": r["description"],
                "author": r["author"],
                "tags": r["tags"],
                "mitre_techniques": r["mitre_techniques"],
                "last_modified": None,  # could be from DB in the future
            })

        log_api_audit("GET", "/api/v2/detection/rules", 200)
        return jsonify({"data": formatted, "total": len(formatted)}), 200
    except Exception as e:
        log_api_audit("GET", "/api/v2/detection/rules", 500, details=str(e))
        return jsonify({"error": "detection_engine_error", "reason": str(e)}), 500


# ═══════════════════════════════════════════
# Sigma Rules Endpoints (VAL-SEC-056)
# ═══════════════════════════════════════════

@v2_bp.route("/sigma/rules")
@auth.require_auth
def list_sigma_rules():
    """List all Sigma rules (built-in + custom).

    GET /api/v2/sigma/rules
    Returns array of Sigma rule objects with enabled status.
    """
    try:
        engine = get_sigma_engine()
        rules = engine.get_all_rules()

        # Format for Sigma-specific API
        formatted = []
        for r in rules:
            formatted.append({
                "id": r["id"],
                "title": r["title"],
                "status": r["status"],
                "level": r["level"],
                "severity": r["severity"],
                "description": r["description"],
                "author": r["author"],
                "tags": r["tags"],
                "falsepositives": r["falsepositives"],
                "logsource": r["logsource"],
                "detection": r["detection"],
                "enabled": r["enabled"],
                "is_custom": r["is_custom"],
                "file_path": r["file_path"],
                "mitre_techniques": r["mitre_techniques"],
                "mitre_tactics": r["mitre_tactics"],
            })

        log_api_audit("GET", "/api/v2/sigma/rules", 200)
        return jsonify({"data": formatted, "total": len(formatted),
                       "rule_counts": engine.get_rule_count()}), 200
    except Exception as e:
        log_api_audit("GET", "/api/v2/sigma/rules", 500, details=str(e))
        return jsonify({"error": "sigma_engine_error", "reason": str(e)}), 500


@v2_bp.route("/sigma/rules", methods=["POST"])
@auth.require_auth
@require_permission("cases:write")
def create_sigma_rule():
    """Create a custom Sigma rule from YAML body.

    POST /api/v2/sigma/rules
    Body: Sigma rule YAML string (Content-Type: application/x-yaml or application/json)
    Validates against Sigma schema and returns 201 with rule object.
    """
    try:
        # Accept YAML body directly
        content_type = request.headers.get("Content-Type", "")
        if "json" in content_type:
            # JSON wrapper: {"yaml": "<sigma yaml string>"}
            data = request.get_json(silent=True)
            if not data:
                return jsonify({"error": "invalid_json", "reason": "Request body must be valid JSON"}), 400
            yaml_str = data.get("yaml", "")
        else:
            # Raw YAML body
            yaml_str = request.get_data(as_text=True)

        if not yaml_str or not yaml_str.strip():
            return jsonify({"error": "invalid_request", "reason": "YAML body is required"}), 400

        engine = get_sigma_engine()
        rule_dict, error = engine.add_custom_rule(yaml_str)

        if error:
            log_api_audit("POST", "/api/v2/sigma/rules", 400, details=error)
            return jsonify({"error": "invalid_rule", "reason": error}), 400

        log_api_audit("POST", "/api/v2/sigma/rules", 201)
        return jsonify({"data": rule_dict}), 201

    except Exception as e:
        log_api_audit("POST", "/api/v2/sigma/rules", 500, details=str(e))
        return jsonify({"error": "sigma_engine_error", "reason": str(e)}), 500


@v2_bp.route("/sigma/rules/<rule_id>", methods=["DELETE"])
@auth.require_auth
@require_permission("cases:write")
def delete_sigma_rule(rule_id: str):
    """Delete a custom Sigma rule. Built-in rules are protected.

    DELETE /api/v2/sigma/rules/:id
    """
    try:
        engine = get_sigma_engine()
        deleted = engine.delete_custom_rule(rule_id)

        if not deleted:
            # Check if it's a built-in rule (protected)
            all_rules = engine.get_all_rules()
            for r in all_rules:
                if r["id"] == rule_id and not r["is_custom"]:
                    log_api_audit("DELETE", f"/api/v2/sigma/rules/{rule_id}", 403,
                                 details="Cannot delete built-in rule")
                    return jsonify({
                        "error": "protected_rule",
                        "reason": "Built-in rules cannot be deleted. Disable them instead."
                    }), 403

            log_api_audit("DELETE", f"/api/v2/sigma/rules/{rule_id}", 404)
            return jsonify({"error": "not_found", "reason": "Rule not found"}), 404

        log_api_audit("DELETE", f"/api/v2/sigma/rules/{rule_id}", 200)
        return jsonify({"data": {"deleted": True, "rule_id": rule_id}}), 200

    except Exception as e:
        log_api_audit("DELETE", f"/api/v2/sigma/rules/{rule_id}", 500, details=str(e))
        return jsonify({"error": "sigma_engine_error", "reason": str(e)}), 500


@v2_bp.route("/sigma/rules/<rule_id>/toggle", methods=["PATCH"])
@auth.require_auth
def toggle_sigma_rule(rule_id: str):
    """Enable or disable a Sigma rule.

    PATCH /api/v2/sigma/rules/:id/toggle
    Body: {"enabled": true/false}
    """
    try:
        data = request.get_json(silent=True)
        if not data or "enabled" not in data:
            return jsonify({"error": "invalid_request", "reason": "Body must contain 'enabled' field"}), 400

        enabled = bool(data["enabled"])
        engine = get_sigma_engine()
        toggled = engine.toggle_rule(rule_id, enabled)

        if not toggled:
            log_api_audit("PATCH", f"/api/v2/sigma/rules/{rule_id}/toggle", 404)
            return jsonify({"error": "not_found", "reason": "Rule not found"}), 404

        log_api_audit("PATCH", f"/api/v2/sigma/rules/{rule_id}/toggle", 200)
        return jsonify({"data": {"rule_id": rule_id, "enabled": enabled}}), 200

    except Exception as e:
        log_api_audit("PATCH", f"/api/v2/sigma/rules/{rule_id}/toggle", 500, details=str(e))
        return jsonify({"error": "sigma_engine_error", "reason": str(e)}), 500


# ═══════════════════════════════════════════
# Collector Health Endpoints (VAL-SEC-058)
# ═══════════════════════════════════════════

@v2_bp.route("/detection/collectors")
@auth.require_auth
def list_collector_health():
    """Return health status for all background detection collectors.

    GET /api/v2/detection/collectors
    Returns array of collector objects with: name, status (running/stopped/error),
    last_execution, execution_count, error_count, last_error.
    """
    try:
        with _collector_health_lock:
            collectors = []
            for key, h in sorted(_collector_health.items()):
                last_exec = None
                if h.get("last_execution"):
                    last_exec = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime(h["last_execution"])
                    )
                collectors.append({
                    "id": key,
                    "name": h["name"],
                    "status": h["status"],
                    "last_execution": last_exec,
                    "execution_count": h["execution_count"],
                    "error_count": h["error_count"],
                    "last_error": h.get("last_error"),
                })

        log_api_audit("GET", "/api/v2/detection/collectors", 200)
        return jsonify({"data": collectors, "total": len(collectors)}), 200
    except Exception as e:
        log_api_audit("GET", "/api/v2/detection/collectors", 500, details=str(e))
        return jsonify({"error": "collector_health_error", "reason": str(e)}), 500
