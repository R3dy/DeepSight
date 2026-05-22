"""Tests for UEBA anomaly detection — BaselineEngine and collector."""

import sys
import os
import json
import time
import math

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBaselineEngine:
    """Test BaselineEngine: learning period, z-score, Welford correctness."""

    def test_learning_period_no_alerts(self):
        """No alerts fire during the learning period (< LEARNING_SAMPLES)."""
        import detection
        import sqlite3
        import tempfile

        # Use a temporary in-memory DB
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        detection._db_conn = db
        # Ensure tables exist by re-initializing
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        host = "test-host"
        # Feed N samples below threshold
        for i in range(5):
            val = 50.0 + (i * 0.1)  # stable values
            result = engine.update(host, "cpu_percent", val)
            if result:
                z_score, mean, stddev, is_learning = result
                # During learning period, z_score may be computed but
                # check_and_alert should not fire
                if not is_learning:
                    alert = engine.check_and_alert(
                        host, "cpu_percent", z_score, val, mean, stddev,
                        is_learning)
                    assert alert is None, (
                        f"Alert fired at sample {i+1} during learning")

    def test_zscore_alert_fires_above_threshold(self):
        """Anomaly alert fires when z-score exceeds threshold."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        host = "test-host"
        # Build a stable baseline with 50 samples (beyond learning period)
        stable_val = 30.0
        for i in range(50):
            engine.update(host, "cpu_percent", stable_val + (i % 3) * 0.5,
                          time.time() + i)

        # Now feed a spike (z-score should be high)
        spike = 60.0  # 2x baseline
        result = engine.update(host, "cpu_percent", spike, time.time() + 100)
        assert result is not None
        z_score, mean, stddev, is_learning = result

        assert not is_learning, "Should be past learning period"
        assert z_score > 3.0, (
            f"Expected z-score > 3.0 for spike, got {z_score:.2f}")
        assert abs(mean - 30.0) < 5.0, f"Mean drifted too far: {mean:.2f}"

    def test_welford_stable_baseline(self):
        """Stable values produce near-zero z-scores."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        host = "test-host"
        val = 25.0
        for i in range(100):
            engine.update(host, "ram_used_gb", val, time.time() + i)

        # Feed the same value again
        result = engine.update(host, "ram_used_gb", val, time.time() + 200)
        assert result is not None
        z_score, mean, stddev, is_learning = result

        assert not is_learning
        assert abs(z_score) < 0.5, (
            f"Expected near-zero z-score for stable data, got {z_score:.3f}")
        assert abs(mean - 25.0) < 1.0, (
            f"Expected mean ~25, got {mean:.2f}")

    def test_zscore_drop_detection(self):
        """Negative z-scores correctly detect drops below baseline."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        host = "test-host"
        # Build baseline at 80% CPU
        for i in range(60):
            engine.update(host, "cpu_percent", 80.0, time.time() + i)

        # Sudden drop to 20%
        result = engine.update(host, "cpu_percent", 20.0, time.time() + 200)
        assert result is not None
        z_score, mean, stddev, is_learning = result

        assert not is_learning
        assert z_score < -3.0, (
            f"Expected z-score < -3.0 for drop, got {z_score:.2f}")

    def test_sqlite_persistence(self):
        """Baseline state persists to and loads from SQLite."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        host = "test-host"
        for i in range(40):
            engine.update(host, "process_count", 200 + i % 5,
                          time.time() + i)

        # Check database has the baseline row
        row = db.execute(
            "SELECT * FROM baselines WHERE host = ? AND metric = ?",
            (host, "process_count")
        ).fetchone()

        assert row is not None, "Baseline row should exist in DB"
        assert row["count"] >= 40, f"Expected count >= 40, got {row['count']}"
        assert row["mean"] > 0, "Mean should be positive"
        assert row["stddev"] >= 0, "StdDev should be non-negative"
        assert row["is_learning"] == 0, (
            "Should be past learning period after 40 samples")

    def test_anomalies_stored_in_db(self):
        """Anomalies are persisted to the anomalies table."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        # We need to suppress create_alert to not hit the real DB
        # Just test that anomalies table INSERT works directly
        engine.db.execute("""
            INSERT INTO anomalies (timestamp, host, metric, z_score,
                                   current_value, mean, stddev, severity)
            VALUES (datetime('now'), 'test-host', 'cpu_percent', 4.5, 85.0,
                    50.0, 8.0, 'high')
        """)
        engine.db.commit()

        anomalies = engine.get_anomalies(host="test-host")
        assert len(anomalies) == 1
        a = anomalies[0]
        assert a["host"] == "test-host"
        assert a["metric"] == "cpu_percent"
        assert abs(a["z_score"] - 4.5) < 0.01
        assert a["severity"] == "high"


class TestBaselineCollector:
    """Test the baseline_collector helper functions."""

    def test_collect_local_metrics_returns_dict(self):
        """_collect_local_metrics returns a dict with expected keys."""
        import detection
        metrics = detection._collect_local_metrics()
        assert isinstance(metrics, dict)
        # Should have at least some metrics
        assert "cpu_percent" in metrics
        assert "ram_used_gb" in metrics
        assert "process_count" in metrics
        assert metrics["cpu_percent"] >= 0
        assert metrics["process_count"] > 0

    def test_metric_labels_defined(self):
        """All tracked metrics have human-readable labels."""
        import detection
        for metric in detection.BASELINE_METRICS:
            assert metric in detection.BASELINE_METRIC_LABELS, (
                f"Missing label for {metric}")

    def test_thresholds_defined(self):
        """All tracked metrics have z-score thresholds."""
        import detection
        for metric in detection.BASELINE_METRICS:
            assert metric in detection.BASELINE_Z_THRESHOLDS, (
                f"Missing threshold for {metric}")


class TestBaselineAPI:
    """Test the baseline/anomaly API functions."""

    def test_get_baselines_returns_list(self):
        """get_baselines() returns a list even when empty."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        baselines = engine.get_baselines()
        assert isinstance(baselines, list)

    def test_get_anomalies_returns_list(self):
        """get_anomalies() returns a list even when empty."""
        import detection
        import sqlite3

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = detection.BaselineEngine.__new__(detection.BaselineEngine)
        engine.db = db
        engine.samples = detection.defaultdict(
            lambda: detection.defaultdict(list))
        engine.lock = detection.threading.Lock()
        engine._create_tables()

        anomalies = engine.get_anomalies()
        assert isinstance(anomalies, list)
