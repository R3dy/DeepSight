"""
API v2 UEBA Routes — Enhanced UEBA with per-entity baselines, peer groups, risk scoring.

Routes:
  GET  /api/v2/ueba/health                    — UEBA health metrics dashboard
  GET  /api/v2/ueba/model-status              — ML model status (loading/ready/error)
  POST /api/v2/ueba/reset-model               — reset and retrain the ML model
  GET  /api/v2/ueba/timeline                  — anomaly timeline data
  GET  /api/v2/ueba/deviations                — entity deviation table
  GET  /api/v2/ueba/anomalies                 — anomaly event list (paginated)
  GET  /api/v2/ueba/anomalies/:id             — anomaly detail
  POST /api/v2/ueba/anomalies/:id/acknowledge — acknowledge anomaly
  POST /api/v2/ueba/anomalies/acknowledge/bulk — bulk acknowledge
  POST /api/v2/ueba/anomalies/:id/promote     — promote anomaly to alert
  POST /api/v2/ueba/anomalies/:id/false-positive — mark false positive
  GET  /api/v2/ueba/entities                  — list/search entities
  GET  /api/v2/ueba/baselines/:entity_type/:entity_id — entity baseline detail
  POST /api/v2/ueba/baselines/:entity_type/:entity_id/reset — reset baseline
  GET  /api/v2/ueba/risk-scores               — entity risk scores
  GET  /api/v2/ueba/risk-scores/:entity_type/:entity_id — single entity risk
  GET  /api/v2/ueba/peer-groups               — peer group listing
  GET  /api/v2/ueba/export                    — export UEBA data
"""


from flask import jsonify, request, g

from routes.v2 import v2_bp, auth, log_api_audit, require_permission


@v2_bp.route("/ueba/health")
@auth.require_auth
def ueba_health():
    """Return comprehensive UEBA health metrics for the health dashboard.

    Response includes: ML model status, entities monitored, baselines active,
    anomalies detected in last 24h, model training timestamp, ML config,
    enhanced UEBA metrics (entity types, peer groups, false positive rate).

    VAL-UEBA-029: Model health/accuracy dashboard.
    VAL-UEBA-035: UEBA baselined metric types are documented and visible.
    """
    import detection
    import ueba_engine

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        # ML model health
        ml_health = detection.get_ueba_health()

        # Enhanced UEBA engine health
        enh_engine = ueba_engine.get_enhanced_ueba_engine()
        enh_health = enh_engine.get_ueba_health()

        # Merge health data
        combined = {
            **ml_health,
            **enh_health,
            "engine": "enhanced",
            "peer_groups": len(ueba_engine.get_peer_group_manager().list_groups()),
        }

        log_api_audit("GET", "/api/v2/ueba/health", 200)
        return jsonify({"data": combined})
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/health", 500)
        return jsonify({
            "error": "Failed to retrieve UEBA health",
            "detail": str(e),
        }), 500


@v2_bp.route("/ueba/model-status")
@auth.require_auth
def ueba_model_status():
    """Return the current ML model status for UI state management.

    Response includes status string:
    - "initializing": model just created, collecting initial samples
    - "insufficient_data": collecting samples, below min_samples threshold
    - "ready_to_train": enough samples collected, training not yet triggered
    - "training": model is currently training
    - "ready": model trained and running
    - "error": scikit-learn unavailable or model failed

    VAL-UEBA-017: Loading state while ML model initializes.
    VAL-UEBA-018: Insufficient data state.
    VAL-UEBA-019: Error state when ML engine unavailable.
    VAL-UEBA-021: "No anomalies detected" empty state (derived from anomaly count).
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        detector = detection.get_anomaly_detector()
        engine = detection.get_baseline_engine()
        status = detector.get_status()

        # Add UEBA context for UI states
        anomalies_24h = len(engine.get_anomalies(hours=24))
        baselines = engine.get_baselines()
        learning_count = sum(1 for b in baselines if b.get("is_learning", True))

        log_api_audit("GET", "/api/v2/ueba/model-status", 200)
        return jsonify({
            "data": {
                "model_status": status["status"],
                "is_trained": status["is_trained"],
                "samples_collected": status["samples_collected"],
                "samples_required": status["samples_required"],
                "error_message": status.get("error_message"),
                "anomalies_24h": anomalies_24h,
                "baselines_total": len(baselines),
                "baselines_learning": learning_count,
                "baselines_active": len(baselines) - learning_count,
                # UI state hints for the frontend
                "ui_states": {
                    "show_loading": status["status"] in ("initializing", "ready_to_train"),
                    "show_insufficient_data": status["status"] == "insufficient_data",
                    "show_error": status["status"] == "error",
                    "show_no_anomalies": (
                        status["is_trained"] and anomalies_24h == 0
                    ),
                    "show_healthy": status["is_trained"] and anomalies_24h > 0,
                },
            }
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/model-status", 500)
        return jsonify({
            "error": "Failed to retrieve model status",
            "detail": str(e),
        }), 500


@v2_bp.route("/ueba/reset-model", methods=["POST"])
@auth.require_auth
@require_permission("admin:access")
def ueba_reset_model():
    """Reset the ML model to force retraining from scratch.

    Requires admin permission. Clears samples and model, triggers a fresh
    learning period. Useful after major system changes.

    VAL-UEBA-026: Baseline reset/retrain control.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        detector = detection.get_anomaly_detector()

        # Reset model state
        with detector._lock:
            detector.model = None
            detector._samples = []
            detector._trained_at = None
            detector._error_message = None

        # Also remove saved model file
        import os
        if os.path.exists(detector.model_path):
            os.unlink(detector.model_path)

        log_api_audit("POST", "/api/v2/ueba/reset-model", 200,
                      details="ML model reset by user")
        return jsonify({
            "data": {
                "status": "reset",
                "message": "ML model reset. Retraining will begin as new samples arrive.",
                "samples_required": detector.min_samples,
            }
        })
    except Exception as e:
        log_api_audit("POST", "/api/v2/ueba/reset-model", 500)
        return jsonify({
            "error": "Failed to reset model",
            "detail": str(e),
        }), 500


# ═══════════════════════════════════════════
# Enhanced UEBA Routes — Entity Baselines
# ═══════════════════════════════════════════

def _get_ueba_engine():
    """Lazy-import and return the EnhancedUEBAEngine singleton."""
    import ueba_engine
    return ueba_engine.get_enhanced_ueba_engine()


def _get_peer_manager():
    """Lazy-import and return the PeerGroupManager singleton."""
    import ueba_engine
    return ueba_engine.get_peer_group_manager()


def _get_risk_scorer():
    """Lazy-import and return the RiskScorer singleton."""
    import ueba_engine
    return ueba_engine.get_risk_scorer()


@v2_bp.route("/ueba/entities")
@auth.require_auth
def ueba_entities():
    """List all tracked UEBA entities with optional search filter.

    GET /api/v2/ueba/entities
    Query params: type (host|user|process), search (fuzzy name match)

    VAL-UEBA-025: UEBA entity search.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        entity_type = request.args.get("type")
        search = request.args.get("search", "").strip()

        engine = _get_ueba_engine()

        if search:
            entities = engine.search_entities(search)
            if entity_type:
                entities = [e for e in entities if e["entity_type"] == entity_type]
        else:
            entities = engine.list_entities(entity_type=entity_type)

        log_api_audit("GET", "/api/v2/ueba/entities", 200)
        return jsonify({
            "data": entities,
            "total": len(entities),
            "entity_type_counts": {
                "host": sum(1 for e in entities if e["entity_type"] == "host"),
                "user": sum(1 for e in entities if e["entity_type"] == "user"),
                "process": sum(1 for e in entities if e["entity_type"] == "process"),
            },
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/entities", 500, details=str(e))
        return jsonify({"error": "Failed to list entities", "detail": str(e)}), 500


@v2_bp.route("/ueba/baselines/<entity_type>/<entity_id>")
@auth.require_auth
def ueba_entity_baselines(entity_type, entity_id):
    """Get detailed baseline profile for a single entity.

    GET /api/v2/ueba/baselines/:entity_type/:entity_id
    Query params: metric (optional filter)

    VAL-UEBA-011: Entity detail page shows baseline profiles.
    VAL-UEBA-012: Baseline view shows learning period and confidence.
    VAL-UEBA-035: UEBA baselined metric types are documented and visible.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        metric = request.args.get("metric")
        engine = _get_ueba_engine()

        baselines = engine.get_entity_baselines(
            entity_type=entity_type, entity_id=entity_id, metric=metric
        )

        # Get peer group info
        pgm = _get_peer_manager()
        peer_group = pgm.get_entity_group(entity_id, entity_type)
        peer_comparisons = {}

        if peer_group:
            for b in baselines:
                if not b["is_learning"]:
                    comp = engine.get_peer_comparison(
                        entity_type, entity_id, peer_group, b["metric"]
                    )
                    if comp:
                        peer_comparisons[b["metric"]] = comp

        # Get risk score
        scorer = _get_risk_scorer()
        risk = scorer.get_risk_score(entity_type, entity_id)
        trend = scorer.get_risk_trend(entity_type, entity_id)

        log_api_audit("GET", f"/api/v2/ueba/baselines/{entity_type}/{entity_id}", 200)
        return jsonify({
            "data": {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "baselines": baselines,
                "peer_group": peer_group,
                "peer_comparisons": peer_comparisons,
                "risk_score": risk,
                "risk_trend": trend,
                "learning_count": sum(1 for b in baselines if b["is_learning"]),
                "active_count": sum(1 for b in baselines if not b["is_learning"]),
                "total_metrics": len(baselines),
            }
        })
    except Exception as e:
        log_api_audit("GET", f"/api/v2/ueba/baselines/{entity_type}/{entity_id}", 500,
                      details=str(e))
        return jsonify({"error": "Failed to get entity baselines", "detail": str(e)}), 500


@v2_bp.route("/ueba/baselines/<entity_type>/<entity_id>/reset", methods=["POST"])
@auth.require_auth
@require_permission("cases:write")
def ueba_reset_entity_baseline(entity_type, entity_id):
    """Reset baseline for a specific entity.

    POST /api/v2/ueba/baselines/:entity_type/:entity_id/reset
    Body: {"metric": "cpu_percent"} (optional, resets all if omitted)

    VAL-UEBA-026: UEBA baseline reset/retrain control.
    VAL-UEBA-027: UEBA baseline retrain transition state.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        data = request.get_json(silent=True) or {}
        metric = data.get("metric")

        engine = _get_ueba_engine()
        success = engine.reset_entity_baseline(entity_type, entity_id, metric=metric)

        log_api_audit("POST", f"/api/v2/ueba/baselines/{entity_type}/{entity_id}/reset",
                      200, details=f"Reset baseline for {entity_type}/{entity_id}" +
                      (f" metric={metric}" if metric else ""))

        if success:
            return jsonify({
                "data": {
                    "status": "reset",
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "metric": metric,
                    "message": f"Baseline reset for {entity_type}/{entity_id}. "
                               f"Entity will re-enter learning period." +
                               (f" Metric: {metric}" if metric else " All metrics reset."),
                    "ui_state": "retraining",
                }
            })
        else:
            return jsonify({"error": "Failed to reset baseline"}), 500
    except Exception as e:
        log_api_audit("POST", f"/api/v2/ueba/baselines/{entity_type}/{entity_id}/reset",
                      500, details=str(e))
        return jsonify({"error": "Failed to reset baseline", "detail": str(e)}), 500


# ═══════════════════════════════════════════
# Enhanced UEBA Routes — Anomalies
# ═══════════════════════════════════════════

@v2_bp.route("/ueba/anomalies")
@auth.require_auth
def ueba_anomalies():
    """List anomaly events with comprehensive filtering and pagination.

    GET /api/v2/ueba/anomalies
    Query params: entity_type, entity_id, metric, severity, acknowledged,
                  hours, limit, offset, sort_by, sort_order

    VAL-UEBA-008: Anomaly list shows individual anomaly events.
    VAL-UEBA-010: Anomaly list supports pagination.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        entity_type = request.args.get("entity_type")
        entity_id = request.args.get("entity_id")
        metric = request.args.get("metric")
        severity = request.args.get("severity")
        acked = request.args.get("acknowledged")
        hours = max(request.args.get("hours", 24, type=int), 1)
        limit = max(request.args.get("limit", 100, type=int), 1)
        offset = max(request.args.get("offset", 0, type=int), 0)
        sort_by = request.args.get("sort_by", "timestamp")
        sort_order = request.args.get("sort_order", "desc")

        acknowledged = None
        if acked is not None:
            acknowledged = acked.lower() in ("true", "1", "yes")

        engine = _get_ueba_engine()
        anomalies = engine.get_anomalies(
            entity_type=entity_type, entity_id=entity_id, metric=metric,
            severity=severity, acknowledged=acknowledged, hours=hours,
            limit=limit, offset=offset, sort_by=sort_by, sort_order=sort_order
        )

        total = engine.get_anomaly_count(
            entity_type=entity_type, entity_id=entity_id, hours=hours
        )

        # Severity counts
        sev_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for a in anomalies:
            s = a.get("severity", "low")
            if s in sev_counts:
                sev_counts[s] += 1

        log_api_audit("GET", "/api/v2/ueba/anomalies", 200)
        return jsonify({
            "data": anomalies,
            "total": total,
            "count": len(anomalies),
            "limit": limit,
            "offset": offset,
            "severity_counts": sev_counts,
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/anomalies", 500, details=str(e))
        return jsonify({"error": "Failed to list anomalies", "detail": str(e)}), 500


@v2_bp.route("/ueba/anomalies/<int:anomaly_id>")
@auth.require_auth
def ueba_anomaly_detail(anomaly_id):
    """Get detailed information for a single anomaly event.

    GET /api/v2/ueba/anomalies/:id

    VAL-UEBA-009: Anomaly events show detailed comparison on expand.
    VAL-UEBA-037: UEBA anomaly detail drill-down to raw contributing events.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        engine = _get_ueba_engine()
        anomalies = engine.get_anomalies(hours=720, limit=1)

        # Find the specific anomaly
        anomaly = None
        for a in anomalies:
            if a["id"] == anomaly_id:
                anomaly = a
                break

        # If not found in recent, query directly
        if anomaly is None:
            row = engine.db.execute(
                "SELECT * FROM ueba_anomalies WHERE id=?", (anomaly_id,)
            ).fetchone()
            if row:
                anomaly = engine._format_anomaly(row)

        if not anomaly:
            return jsonify({"error": "Anomaly not found"}), 404

        # Get peer comparison
        pgm = _get_peer_manager()
        peer_group = pgm.get_entity_group(anomaly["entity_id"], anomaly["entity_type"])
        peer_comparison = None
        if peer_group:
            peer_comparison = engine.get_peer_comparison(
                anomaly["entity_type"], anomaly["entity_id"],
                peer_group, anomaly["metric"]
            )

        # Get related anomalies (same entity, similar time)
        related = engine.get_anomalies(
            entity_type=anomaly["entity_type"],
            entity_id=anomaly["entity_id"],
            hours=24,
            limit=10
        )

        log_api_audit("GET", f"/api/v2/ueba/anomalies/{anomaly_id}", 200)
        return jsonify({
            "data": {
                **anomaly,
                "peer_comparison": peer_comparison,
                "peer_group": peer_group,
                "related_anomalies": [r for r in related if r["id"] != anomaly_id],
            }
        })
    except Exception as e:
        log_api_audit("GET", f"/api/v2/ueba/anomalies/{anomaly_id}", 500, details=str(e))
        return jsonify({"error": "Failed to get anomaly detail", "detail": str(e)}), 500


@v2_bp.route("/ueba/anomalies/<int:anomaly_id>/acknowledge", methods=["POST"])
@auth.require_auth
@require_permission("alerts:acknowledge")
def ueba_acknowledge_anomaly(anomaly_id):
    """Acknowledge a single anomaly.

    POST /api/v2/ueba/anomalies/:id/acknowledge

    VAL-UEBA-022: UEBA anomaly acknowledgment.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        username = g.current_user.get("username") if hasattr(g, "current_user") else None
        engine = _get_ueba_engine()
        success = engine.acknowledge_anomaly(anomaly_id, username=username)

        if success:
            log_api_audit("POST", f"/api/v2/ueba/anomalies/{anomaly_id}/acknowledge", 200)
            return jsonify({"data": {"acknowledged": True, "id": anomaly_id}})
        else:
            return jsonify({"error": "Anomaly not found or already acknowledged"}), 404
    except Exception as e:
        log_api_audit("POST", f"/api/v2/ueba/anomalies/{anomaly_id}/acknowledge",
                      500, details=str(e))
        return jsonify({"error": "Failed to acknowledge anomaly", "detail": str(e)}), 500


@v2_bp.route("/ueba/anomalies/acknowledge/bulk", methods=["POST"])
@auth.require_auth
@require_permission("alerts:acknowledge")
def ueba_acknowledge_anomalies_bulk():
    """Acknowledge multiple anomalies in bulk.

    POST /api/v2/ueba/anomalies/acknowledge/bulk
    Body: {"ids": [1, 2, 3, ...]}

    VAL-UEBA-039: Bulk anomaly acknowledgment.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        data = request.get_json(silent=True) or {}
        ids = data.get("ids", [])

        if not ids or not isinstance(ids, list):
            return jsonify({"error": "Request body must contain 'ids' array"}), 400

        username = g.current_user.get("username") if hasattr(g, "current_user") else None
        engine = _get_ueba_engine()
        result = engine.acknowledge_anomalies_bulk(ids, username=username)

        log_api_audit("POST", "/api/v2/ueba/anomalies/acknowledge/bulk", 200,
                      details=f"Bulk acknowledged {result['acknowledged']}/{result['total']}")
        return jsonify({"data": result})
    except Exception as e:
        log_api_audit("POST", "/api/v2/ueba/anomalies/acknowledge/bulk", 500, details=str(e))
        return jsonify({"error": "Failed to bulk acknowledge", "detail": str(e)}), 500


@v2_bp.route("/ueba/anomalies/<int:anomaly_id>/promote", methods=["POST"])
@auth.require_auth
@require_permission("cases:write")
def ueba_promote_anomaly(anomaly_id):
    """Promote an anomaly to a proper alert.

    POST /api/v2/ueba/anomalies/:id/promote

    VAL-UEBA-023: UEBA anomaly promotion to alert.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        engine = _get_ueba_engine()
        success = engine.promote_to_alert(anomaly_id)

        if success:
            log_api_audit("POST", f"/api/v2/ueba/anomalies/{anomaly_id}/promote", 200,
                          details="Anomaly promoted to alert")
            return jsonify({"data": {"promoted": True, "id": anomaly_id}})
        else:
            return jsonify({"error": "Anomaly not found"}), 404
    except Exception as e:
        log_api_audit("POST", f"/api/v2/ueba/anomalies/{anomaly_id}/promote",
                      500, details=str(e))
        return jsonify({"error": "Failed to promote anomaly", "detail": str(e)}), 500


@v2_bp.route("/ueba/anomalies/<int:anomaly_id>/false-positive", methods=["POST"])
@auth.require_auth
@require_permission("cases:write")
def ueba_false_positive(anomaly_id):
    """Mark an anomaly as a false positive.

    POST /api/v2/ueba/anomalies/:id/false-positive
    Body: {"reason": "Normal maintenance window"}

    VAL-UEBA-028: UEBA false positive marking for model improvement.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        data = request.get_json(silent=True) or {}
        reason = data.get("reason", "")

        engine = _get_ueba_engine()
        success = engine.mark_false_positive(anomaly_id, reason)

        if success:
            log_api_audit("POST", f"/api/v2/ueba/anomalies/{anomaly_id}/false-positive",
                          200, details=f"Marked as false positive: {reason[:200]}")
            return jsonify({"data": {"marked": True, "id": anomaly_id, "reason": reason}})
        else:
            return jsonify({"error": "Anomaly not found"}), 404
    except Exception as e:
        log_api_audit("POST", f"/api/v2/ueba/anomalies/{anomaly_id}/false-positive",
                      500, details=str(e))
        return jsonify({"error": "Failed to mark false positive", "detail": str(e)}), 500


# ═══════════════════════════════════════════
# Enhanced UEBA Routes — Timeline and Deviations
# ═══════════════════════════════════════════

@v2_bp.route("/ueba/timeline")
@auth.require_auth
def ueba_timeline():
    """Get anomaly timeline data for charting.

    GET /api/v2/ueba/timeline
    Query params: hours, entity_type, bucket_minutes

    VAL-UEBA-001: Anomaly timeline chart shows anomaly events over time.
    VAL-UEBA-002: Anomaly timeline supports time range selection.
    VAL-UEBA-003: Anomaly timeline shows tooltips on hover (data provides tooltip fields).
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        hours = max(request.args.get("hours", 24, type=int), 1)
        entity_type = request.args.get("entity_type")
        bucket_minutes = max(request.args.get("bucket_minutes", 60, type=int), 5)

        engine = _get_ueba_engine()
        timeline = engine.get_anomaly_timeline(
            hours=hours, entity_type=entity_type, bucket_minutes=bucket_minutes
        )

        log_api_audit("GET", "/api/v2/ueba/timeline", 200)
        return jsonify({"data": timeline})
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/timeline", 500, details=str(e))
        return jsonify({"error": "Failed to get anomaly timeline", "detail": str(e)}), 500


@v2_bp.route("/ueba/deviations")
@auth.require_auth
def ueba_deviations():
    """Get entity deviation table sorted by risk.

    GET /api/v2/ueba/deviations
    Query params: entity_type, sort_by, sort_order, limit

    VAL-UEBA-004: Baseline deviation table shows entities sorted by risk.
    VAL-UEBA-005: Deviation table supports sorting by any column.
    VAL-UEBA-006: Deviation table supports entity type filtering.
    VAL-UEBA-007: Deviation rows show visual risk indicators.
    VAL-UEBA-033: UEBA anomaly trend direction indicator.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        entity_type = request.args.get("entity_type")
        sort_by = request.args.get("sort_by", "risk_score")
        sort_order = request.args.get("sort_order", "desc")
        limit = max(request.args.get("limit", 100, type=int), 1)

        engine = _get_ueba_engine()
        deviations = engine.get_deviations(
            entity_type=entity_type, sort_by=sort_by,
            sort_order=sort_order, limit=limit
        )

        # Count by entity type
        type_counts = {}
        for d in deviations:
            et = d.get("entity_type", "unknown")
            type_counts[et] = type_counts.get(et, 0) + 1

        log_api_audit("GET", "/api/v2/ueba/deviations", 200)
        return jsonify({
            "data": deviations,
            "total": len(deviations),
            "entity_type_counts": type_counts,
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/deviations", 500, details=str(e))
        return jsonify({"error": "Failed to get deviations", "detail": str(e)}), 500


# ═══════════════════════════════════════════
# Enhanced UEBA Routes — Risk Scores
# ═══════════════════════════════════════════

@v2_bp.route("/ueba/risk-scores")
@auth.require_auth
def ueba_risk_scores():
    """List risk scores for all entities.

    GET /api/v2/ueba/risk-scores
    Query params: entity_type, sort_by, sort_order, limit

    VAL-UEBA-014: Entity risk score is a composite of multiple factors.
    VAL-UEBA-015: Risk score shows trend over time.
    VAL-UEBA-016: Risk score breakdown shows contributing factors.
    VAL-UEBA-032: UEBA risk score threshold configuration.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        entity_type = request.args.get("entity_type")
        sort_by = request.args.get("sort_by", "risk_score")
        sort_order = request.args.get("sort_order", "desc")
        limit = max(request.args.get("limit", 100, type=int), 1)

        scorer = _get_risk_scorer()
        scores = scorer.list_all_scores(
            entity_type=entity_type, sort_by=sort_by,
            sort_order=sort_order, limit=limit
        )

        log_api_audit("GET", "/api/v2/ueba/risk-scores", 200)
        return jsonify({
            "data": scores,
            "total": len(scores),
            "config": {
                "thresholds": scorer.thresholds,
                "decay_half_life_hours": scorer.decay_half_life,
                "notification_threshold": scorer.notification_threshold,
            },
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/risk-scores", 500, details=str(e))
        return jsonify({"error": "Failed to get risk scores", "detail": str(e)}), 500


@v2_bp.route("/ueba/risk-scores/<entity_type>/<entity_id>")
@auth.require_auth
def ueba_entity_risk_score(entity_type, entity_id):
    """Get risk score and trend for a specific entity.

    GET /api/v2/ueba/risk-scores/:entity_type/:entity_id

    VAL-UEBA-014: Composite risk score for entity.
    VAL-UEBA-015: Risk trend sparkline data.
    VAL-UEBA-016: Risk score factor breakdown.
    VAL-UEBA-034: UEBA integrates with host dashboard.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        scorer = _get_risk_scorer()
        score = scorer.get_risk_score(entity_type, entity_id)
        trend = scorer.get_risk_trend(entity_type, entity_id, hours=168)
        history = scorer.get_risk_history(entity_type, entity_id, hours=168)

        log_api_audit("GET", f"/api/v2/ueba/risk-scores/{entity_type}/{entity_id}", 200)
        return jsonify({
            "data": {
                **score,
                "trend": trend,
                "history": history,
            }
        })
    except Exception as e:
        log_api_audit("GET", f"/api/v2/ueba/risk-scores/{entity_type}/{entity_id}",
                      500, details=str(e))
        return jsonify({"error": "Failed to get entity risk score", "detail": str(e)}), 500


# ═══════════════════════════════════════════
# Enhanced UEBA Routes — Peer Groups
# ═══════════════════════════════════════════

@v2_bp.route("/ueba/peer-groups")
@auth.require_auth
def ueba_peer_groups():
    """List all peer groups with member counts.

    GET /api/v2/ueba/peer-groups
    Query params: entity_type

    VAL-UEBA-013: Baseline view shows peer group comparison.
    VAL-UEBA-036: UEBA peer group auto-assignment and display.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        entity_type = request.args.get("entity_type")
        pgm = _get_peer_manager()
        groups = pgm.list_groups(entity_type=entity_type)

        log_api_audit("GET", "/api/v2/ueba/peer-groups", 200)
        return jsonify({
            "data": groups,
            "total": len(groups),
        })
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/peer-groups", 500, details=str(e))
        return jsonify({"error": "Failed to list peer groups", "detail": str(e)}), 500


# ═══════════════════════════════════════════
# Enhanced UEBA Routes — Export
# ═══════════════════════════════════════════

@v2_bp.route("/ueba/export")
@auth.require_auth
def ueba_export():
    """Export UEBA data as JSON or CSV.

    GET /api/v2/ueba/export
    Query params: entity_type, format (json|csv), hours

    VAL-UEBA-040: UEBA data export to CSV/JSON.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        entity_type = request.args.get("entity_type")
        export_format = request.args.get("format", "json").lower()
        hours = max(request.args.get("hours", 168, type=int), 1)

        engine = _get_ueba_engine()
        data = engine.export_data(
            entity_type=entity_type, format=export_format, hours=hours
        )

        log_api_audit("GET", "/api/v2/ueba/export", 200)

        if export_format == "csv":
            from flask import Response
            return Response(
                data,
                mimetype="text/csv",
                headers={"Content-Disposition": "attachment; filename=ueba_export.csv"}
            )

        return jsonify({"data": data})
    except Exception as e:
        log_api_audit("GET", "/api/v2/ueba/export", 500, details=str(e))
        return jsonify({"error": "Failed to export UEBA data", "detail": str(e)}), 500
