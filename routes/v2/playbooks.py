"""
API v2 Playbook Routes — SOAR enrichment playbook triggers and status.

Routes:
  POST /api/v2/playbooks/run                      — manually run enrichment
  GET  /api/v2/playbooks/status/<alert_id>        — check enrichment results
  GET  /api/v2/playbooks/history                  — recent playbook runs (paginated)
  GET  /api/v2/playbooks                          — list available playbooks
"""

import json

from flask import jsonify, request

from routes.v2 import v2_bp, auth, log_api_audit, require_permission

try:
    from playbook_engine import get_playbook_engine as _get_engine
    HAS_PLAYBOOK_ENGINE = True
except ImportError:
    HAS_PLAYBOOK_ENGINE = False

    def _get_engine():
        return None


# ═══════════════════════════════════════════
# GET /api/v2/playbooks — List available playbooks
# ═══════════════════════════════════════════

@v2_bp.route("/playbooks")
@auth.require_auth
def list_playbooks():
    """Return all configured enrichment playbooks."""
    if not HAS_PLAYBOOK_ENGINE:
        log_api_audit("GET", "/api/v2/playbooks", 503)
        return jsonify({"error": "playbook_engine_not_available"}), 503

    engine = _get_engine()
    playbooks = engine.playbooks

    log_api_audit("GET", "/api/v2/playbooks", 200)
    return jsonify({"data": playbooks, "total": len(playbooks)}), 200


# ═══════════════════════════════════════════
# POST /api/v2/playbooks/run — Manually trigger enrichment
# ═══════════════════════════════════════════

@v2_bp.route("/playbooks/run", methods=["POST"])
@auth.require_auth
@require_permission("cases:write")
def run_playbook():
    """Manually trigger enrichment for an alert or case.

    Body (JSON):
      {
        "alert_id": 42,                           # optional — alert ID
        "playbook": "ip_enrichment",              # required — playbook name
        "context": {                               # optional — manual context
          "ips": ["1.2.3.4"],
          "domains": ["example.com"],
          "hashes": ["abc123..."]
        }
      }

    Returns 202 with playbook run result.
    """
    if not HAS_PLAYBOOK_ENGINE:
        log_api_audit("POST", "/api/v2/playbooks/run", 503)
        return jsonify({"error": "playbook_engine_not_available"}), 503

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_request", "reason": "JSON body required"}), 400

    playbook_name = data.get("playbook", "").strip()
    if not playbook_name:
        return jsonify({"error": "invalid_request", "reason": "'playbook' field is required"}), 400

    # Build alert-like dict from request
    alert_id = data.get("alert_id")
    manual_context = data.get("context", {})
    alert_dict = {
        "id": alert_id,
        "source_ip": manual_context.get("source_ip", ""),
        "source_host": manual_context.get("source_host", ""),
        "category": manual_context.get("category", ""),
        "severity": manual_context.get("severity", "medium"),
        "title": manual_context.get("title", "Manual enrichment run"),
        "description": manual_context.get("description", ""),
        "raw_data": {
            "ips": manual_context.get("ips", []),
            "domains": manual_context.get("domains", []),
            "hashes": manual_context.get("hashes", []),
            **(manual_context.get("extra", {}) or {}),
        },
    }

    engine = _get_engine()
    result = engine.run_playbook_by_name(alert_dict, playbook_name)

    if "error" in result and result["error"] and "not found" in result["error"]:
        log_api_audit("POST", "/api/v2/playbooks/run", 404, details=result["error"])
        return jsonify({"error": "not_found", "reason": result["error"]}), 404

    log_api_audit("POST", "/api/v2/playbooks/run", 202,
                  details=f"playbook={playbook_name} alert_id={alert_id}")
    return jsonify({"data": result}), 202


# ═══════════════════════════════════════════
# GET /api/v2/playbooks/status/<alert_id> — Check enrichment results
# ═══════════════════════════════════════════

@v2_bp.route("/playbooks/status/<int:alert_id>")
@auth.require_auth
def playbook_status(alert_id):
    """Get enrichment results for a specific alert.

    Returns the full enrichment data (IP reputation, geo, whois, etc.)
    that was appended to the alert by the playbook engine.
    """
    if not HAS_PLAYBOOK_ENGINE:
        log_api_audit("GET", f"/api/v2/playbooks/status/{alert_id}", 503)
        return jsonify({"error": "playbook_engine_not_available"}), 503

    engine = _get_engine()

    # Try in-memory results first (recent)
    results = engine.get_results(alert_id)
    if results:
        log_api_audit("GET", f"/api/v2/playbooks/status/{alert_id}", 200)
        return jsonify({"data": results}), 200

    # Fall back to database
    try:
        from detection import get_db as _get_db
        conn = _get_db()
        row = conn.execute(
            "SELECT enrichment FROM alerts WHERE id = ? AND enrichment IS NOT NULL AND enrichment != ''",
            (alert_id,)
        ).fetchone()
        if row and row["enrichment"]:
            results = json.loads(row["enrichment"])
            log_api_audit("GET", f"/api/v2/playbooks/status/{alert_id}", 200)
            return jsonify({"data": results}), 200
    except Exception:
        pass

    log_api_audit("GET", f"/api/v2/playbooks/status/{alert_id}", 404)
    return jsonify({"error": "not_found", "reason": "No enrichment data for this alert"}), 404


# ═══════════════════════════════════════════
# GET /api/v2/playbooks/history — Recent playbook runs
# ═══════════════════════════════════════════

@v2_bp.route("/playbooks/history")
@auth.require_auth
def playbook_history():
    """Return recent playbook execution history (paginated).

    Query params: limit (default 50), offset (default 0)
    """
    if not HAS_PLAYBOOK_ENGINE:
        log_api_audit("GET", "/api/v2/playbooks/history", 503)
        return jsonify({"error": "playbook_engine_not_available"}), 503

    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)

    # Clamp values
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    engine = _get_engine()
    history = engine.get_history(limit=limit, offset=offset)

    log_api_audit("GET", "/api/v2/playbooks/history", 200,
                  details=f"limit={limit} offset={offset} total={history['total']}")
    return jsonify({"data": history}), 200
