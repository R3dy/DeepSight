"""
API v2 Incident Routes — Alert Grouping & Incident Management.

Routes:
  GET    /api/v2/incidents              — list incidents
  GET    /api/v2/incidents/:id          — get incident detail
  POST   /api/v2/incidents              — create incident manually
  POST   /api/v2/incidents/:id/alerts    — group alerts into incident
  DELETE /api/v2/incidents/:id/alerts/:alert_id — ungroup alert from incident
  PATCH  /api/v2/incidents/:id/status   — update incident status
  GET    /api/v2/incidents/config        — get grouping configuration
  PUT    /api/v2/incidents/config        — update grouping configuration
  GET    /api/v2/incidents/suggested     — get suggested alert groupings
  GET    /api/v2/incidents/stats         — incident statistics
"""

from flask import jsonify, request

from routes.v2 import v2_bp, auth, log_api_audit


# ── Helper: get the alert grouper ──
def _get_grouper():
    """Lazily import and return the alert grouper singleton."""
    import detection
    return detection.get_alert_grouper()


# ═══════════════════════════════════════════
# Incident CRUD
# ═══════════════════════════════════════════


@v2_bp.route("/incidents", methods=["GET"])
@auth.require_auth
def list_incidents():
    """List incidents with optional filters.

    Query params: status, host, limit, offset
    """
    try:
        status = request.args.get("status")
        host = request.args.get("host")
        limit = request.args.get("limit", 100, type=int)
        offset = request.args.get("offset", 0, type=int)

        grouper = _get_grouper()
        incidents = grouper.get_incidents(
            status=status, host=host, limit=limit, offset=offset,
        )

        log_api_audit("GET", "/api/v2/incidents", 200)
        return jsonify({"data": {"incidents": incidents, "count": len(incidents)}})
    except Exception as e:
        log_api_audit("GET", "/api/v2/incidents", 500, details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


@v2_bp.route("/incidents/<int:incident_id>", methods=["GET"])
@auth.require_auth
def get_incident(incident_id):
    """Get a single incident with all linked alerts."""
    try:
        grouper = _get_grouper()
        incident = grouper.get_incident(incident_id)
        if incident is None:
            log_api_audit("GET", f"/api/v2/incidents/{incident_id}", 404)
            return jsonify({"error": "incident not found"}), 404

        log_api_audit("GET", f"/api/v2/incidents/{incident_id}", 200)
        return jsonify({"data": incident})
    except Exception as e:
        log_api_audit("GET", f"/api/v2/incidents/{incident_id}", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


@v2_bp.route("/incidents", methods=["POST"])
@auth.require_auth
def create_incident():
    """Create a new incident manually from a set of alerts.

    POST body: {title, alert_ids: [1, 2, 3], severity?, description?,
                source_host?, mitre_technique?}
    """
    try:
        data = request.get_json(silent=True) or {}
        title = data.get("title", "").strip()
        if not title:
            return jsonify({"error": "title is required"}), 400

        alert_ids = data.get("alert_ids", [])
        severity = data.get("severity", "medium")
        description = data.get("description", "")
        source_host = data.get("source_host", "")
        mitre_technique = data.get("mitre_technique", "")

        grouper = _get_grouper()
        incident = grouper.create_incident(
            title=title,
            alert_ids=alert_ids,
            severity=severity,
            description=description,
            source_host=source_host,
            mitre_technique=mitre_technique,
        )

        if incident is None:
            log_api_audit("POST", "/api/v2/incidents", 500)
            return jsonify({"error": "failed to create incident"}), 500

        log_api_audit("POST", "/api/v2/incidents", 201,
                      details=f"incident_id={incident['id']}")
        return jsonify({"data": incident}), 201
    except Exception as e:
        log_api_audit("POST", "/api/v2/incidents", 500, details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


# ═══════════════════════════════════════════
# Alert Grouping / Ungrouping
# ═══════════════════════════════════════════


@v2_bp.route("/incidents/<int:incident_id>/alerts", methods=["POST"])
@auth.require_auth
def group_alerts(incident_id):
    """Manually group alerts into an existing incident.

    POST body: {alert_ids: [1, 2, 3]}
    """
    try:
        data = request.get_json(silent=True) or {}
        alert_ids = data.get("alert_ids", [])
        if not alert_ids or not isinstance(alert_ids, list):
            return jsonify({"error": "missing or invalid alert_ids (must be a list)"}), 400

        grouper = _get_grouper()
        ok = grouper.add_alerts_to_incident(incident_id, [int(a) for a in alert_ids])
        if not ok:
            log_api_audit("POST", f"/api/v2/incidents/{incident_id}/alerts", 404)
            return jsonify({"error": "incident not found"}), 404

        incident = grouper.get_incident(incident_id)
        log_api_audit("POST", f"/api/v2/incidents/{incident_id}/alerts", 200,
                      details=f"added {len(alert_ids)} alerts")
        return jsonify({"data": incident})
    except Exception as e:
        log_api_audit("POST", f"/api/v2/incidents/{incident_id}/alerts", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


@v2_bp.route("/incidents/<int:incident_id>/alerts/<int:alert_id>", methods=["DELETE"])
@auth.require_auth
def ungroup_alert(incident_id, alert_id):
    """Manually remove (ungroup) an alert from an incident."""
    try:
        grouper = _get_grouper()
        ok = grouper.remove_alert_from_incident(incident_id, alert_id)
        if not ok:
            log_api_audit("DELETE",
                          f"/api/v2/incidents/{incident_id}/alerts/{alert_id}", 404)
            return jsonify({"error": "incident or alert link not found"}), 404

        incident = grouper.get_incident(incident_id)
        log_api_audit("DELETE",
                      f"/api/v2/incidents/{incident_id}/alerts/{alert_id}", 200)
        return jsonify({"data": incident})
    except Exception as e:
        log_api_audit("DELETE",
                      f"/api/v2/incidents/{incident_id}/alerts/{alert_id}", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


# ═══════════════════════════════════════════
# Incident Status
# ═══════════════════════════════════════════


@v2_bp.route("/incidents/<int:incident_id>/status", methods=["PATCH"])
@auth.require_auth
def update_incident_status(incident_id):
    """Update incident status.

    PATCH body: {status: "investigating" | "escalated" | "resolved" | "closed"}

    Valid transitions:
      new → investigating, escalated, resolved, closed
      investigating → escalated, resolved, closed
      escalated → investigating, resolved, closed
      resolved → closed
      closed → (terminal)
    """
    try:
        data = request.get_json(silent=True) or {}
        new_status = data.get("status", "").strip().lower()
        valid_statuses = ("new", "investigating", "escalated", "resolved", "closed")
        if new_status not in valid_statuses:
            return jsonify({
                "error": f"invalid status, must be one of: {', '.join(valid_statuses)}"
            }), 400

        grouper = _get_grouper()
        ok = grouper.update_incident_status(incident_id, new_status)
        if not ok:
            log_api_audit("PATCH", f"/api/v2/incidents/{incident_id}/status", 404)
            return jsonify({"error": "incident not found"}), 404

        incident = grouper.get_incident(incident_id)
        log_api_audit("PATCH", f"/api/v2/incidents/{incident_id}/status", 200,
                      details=f"status={new_status}")
        return jsonify({"data": incident})
    except Exception as e:
        log_api_audit("PATCH", f"/api/v2/incidents/{incident_id}/status", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════


@v2_bp.route("/incidents/config", methods=["GET", "PUT"])
@auth.require_auth
def incident_config():
    """Get or update the alert grouping configuration.

    GET: returns current grouping_window_seconds, auto_group_enabled
    PUT body: {grouping_window_seconds: int, auto_group_enabled: bool}
    """
    grouper = _get_grouper()

    if request.method == "GET":
        config = grouper.get_config()
        log_api_audit("GET", "/api/v2/incidents/config", 200)
        return jsonify({"data": config})

    # PUT — update config
    data = request.get_json(silent=True) or {}
    window = data.get("grouping_window_seconds")
    auto_group = data.get("auto_group_enabled")

    if window is not None:
        try:
            grouper.set_grouping_window(int(window))
        except (ValueError, TypeError):
            return jsonify({"error": "grouping_window_seconds must be an integer"}), 400

    if auto_group is not None:
        grouper.set_auto_group(bool(auto_group))

    config = grouper.get_config()
    log_api_audit("PUT", "/api/v2/incidents/config", 200,
                  details=f"window={config['grouping_window_seconds']}s "
                          f"auto_group={config['auto_group_enabled']}")
    return jsonify({"data": config})


# ═══════════════════════════════════════════
# Suggestions & Statistics
# ═══════════════════════════════════════════


@v2_bp.route("/incidents/suggested")
@auth.require_auth
def get_suggested_groups():
    """Return suggested alert groupings for analyst review (VAL-CROSS-001).

    Query params: host, lookback_minutes (default 30)
    """
    try:
        host = request.args.get("host")
        lookback = request.args.get("lookback_minutes", 30, type=int)
        grouper = _get_grouper()
        suggestions = grouper.get_suggested_groups(
            host=host, lookback_minutes=lookback,
        )
        log_api_audit("GET", "/api/v2/incidents/suggested", 200)
        return jsonify({"data": {"suggestions": suggestions, "count": len(suggestions)}})
    except Exception as e:
        log_api_audit("GET", "/api/v2/incidents/suggested", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


@v2_bp.route("/incidents/stats")
@auth.require_auth
def get_incident_stats():
    """Return incident statistics: counts by status."""
    try:
        grouper = _get_grouper()
        stats = grouper.get_incident_stats()
        log_api_audit("GET", "/api/v2/incidents/stats", 200)
        return jsonify({"data": stats})
    except Exception as e:
        log_api_audit("GET", "/api/v2/incidents/stats", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500


# ═══════════════════════════════════════════
# Investigation Suggestions (alias for /incidents/suggested)
# ═══════════════════════════════════════════


@v2_bp.route("/investigations/suggested")
@auth.require_auth
def get_investigation_suggestions():
    """Return suggested alert groupings for investigation (VAL-CROSS-001).

    Alias for /api/v2/incidents/suggested with the same query params.
    """
    try:
        host = request.args.get("host")
        lookback = request.args.get("lookback_minutes", 30, type=int)
        grouper = _get_grouper()
        suggestions = grouper.get_suggested_groups(
            host=host, lookback_minutes=lookback,
        )
        log_api_audit("GET", "/api/v2/investigations/suggested", 200)
        return jsonify({"data": {"suggestions": suggestions, "count": len(suggestions)}})
    except Exception as e:
        log_api_audit("GET", "/api/v2/investigations/suggested", 500,
                      details=str(e)[:200])
        return jsonify({"error": "internal server error"}), 500
