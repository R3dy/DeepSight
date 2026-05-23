"""
API v2 UEBA Routes — anomaly detection health and model status.

Routes:
  GET  /api/v2/ueba/health         — model health metrics dashboard
  GET  /api/v2/ueba/model-status   — ML model status (loading/ready/error)
  POST /api/v2/ueba/reset-model    — reset and retrain the ML model
"""

import time
import threading

from flask import jsonify, request

from routes.v2 import v2_bp, auth, log_api_audit, require_permission


@v2_bp.route("/ueba/health")
@auth.require_auth
def ueba_health():
    """Return UEBA model health metrics for the health dashboard.

    Response includes: model status, entities monitored, baselines active,
    anomalies detected in last 24h, model training timestamp, and ML config.

    VAL-UEBA-029: Model health/accuracy dashboard.
    """
    import detection

    if not getattr(detection, 'DETECTION_AVAILABLE', True):
        return jsonify({"error": "detection engine not available"}), 503

    try:
        health = detection.get_ueba_health()
        log_api_audit("GET", "/api/v2/ueba/health", 200)
        return jsonify({"data": health})
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
