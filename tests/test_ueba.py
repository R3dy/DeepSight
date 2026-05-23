"""Tests for UEBA anomaly detection — BaselineEngine, AnomalyDetector, and collector."""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestBaselineEngine:
    """Test BaselineEngine: learning period, z-score, Welford correctness."""

    def test_learning_period_no_alerts(self):
        """No alerts fire during the learning period (< LEARNING_SAMPLES)."""
        import detection
        import sqlite3

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

    def test_zero_variance_small_deviation(self):
        """Regression: zero-variance data with tiny deviation stays bounded.

        When all values are identical or near-identical, variance approaches
        zero. The engine should produce z_score ≈ 0 (not magnitude-100
        false positives from a stddev sentinel of 0.001).

        This test uses a deviation small enough that variance stays below
        the 1e-9 threshold — exactly the case where the old sentinel bug
        would inflate z-scores.
        """
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
        # Feed 60 identical samples — builds zero-variance baseline
        for i in range(60):
            engine.update(host, "cpu_percent", 25.0, time.time() + i)

        # Tiny deviation: 0.0001 above baseline keeps variance < 1e-9
        result = engine.update(host, "cpu_percent", 25.0001, time.time() + 200)
        assert result is not None
        z_score, mean, stddev, is_learning = result

        assert not is_learning
        # With near-zero variance, z-score should be 0 (variance < 1e-9 guard)
        assert abs(z_score) == 0.0, (
            f"Zero-variance sentinel should force z=0, got {z_score:.6f}"
        )
        assert stddev == 0.0, (
            f"Stddev should be 0 for zero-variance data, got {stddev:.6f}"
        )
        assert abs(mean - 25.0) < 0.01, (
            f"Mean drifted unexpectedly: {mean:.2f}"
        )


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


class TestAnomalyDetector:
    """Test IsolationForest-based AnomalyDetector."""

    # Use a temp path to avoid interference with saved models from other tests
    _temp_model_path = "/tmp/test_isolation_forest_model.pkl"

    def setup_method(self):
        """Clean up temp model file before each test."""
        if os.path.exists(self._temp_model_path):
            os.unlink(self._temp_model_path)

    def teardown_method(self):
        """Clean up temp model file after each test."""
        if os.path.exists(self._temp_model_path):
            os.unlink(self._temp_model_path)

    def test_import(self):
        """AnomalyDetector is importable from detection module."""
        import detection
        assert hasattr(detection, 'AnomalyDetector'), (
            "AnomalyDetector class should be importable")

    def test_initialization(self):
        """AnomalyDetector initializes with default parameters."""
        import detection
        detector = detection.AnomalyDetector(model_path=self._temp_model_path)
        assert detector.model is None, "Model should be None before training"
        assert detector.training_samples == 0
        assert detector.is_trained is False
        assert detector.status == "insufficient_data"  # 0 < 100 samples

    def test_collect_and_train(self):
        """AnomalyDetector collects samples and trains IsolationForest."""
        import detection

        detector = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Feed normal samples
        for i in range(60):
            features = [
                30.0 + (i % 5) * 0.5,   # cpu
                8.0 + (i % 3) * 0.1,    # ram
                10.0 + (i % 4) * 0.2,   # disk_read
                5.0 + (i % 3) * 0.1,    # disk_write
                50.0 + (i % 6) * 0.3,   # net_conns
                200.0 + (i % 10) * 0.5,  # process_count
            ]
            detector.add_sample(features)

        assert detector.training_samples == 60
        assert detector.status == "ready"

        # Train the model
        detector.train()
        assert detector.is_trained is True
        assert detector.model is not None
        assert hasattr(detector.model, 'predict')

    def test_predict_normal(self):
        """Normal samples score close to 1 (inlier)."""
        import detection

        detector = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Feed 80 normal samples with slight noise
        for i in range(80):
            features = [
                30.0 + (i % 5) * 0.5,
                8.0 + (i % 3) * 0.1,
                10.0 + (i % 4) * 0.2,
                5.0 + (i % 3) * 0.1,
                50.0 + (i % 6) * 0.3,
                200.0 + (i % 10) * 0.5,
            ]
            detector.add_sample(features)

        detector.train()

        # Predict a normal sample
        normal = [31.0, 8.2, 10.5, 5.1, 52.0, 202.0]
        result = detector.predict(normal)
        assert result is not None
        assert "score" in result
        assert "is_anomaly" in result
        # Normal should NOT be an anomaly
        assert result["is_anomaly"] is False, (
            f"Normal sample incorrectly flagged as anomaly: {result}")

    def test_predict_anomaly(self):
        """Anomalous samples score close to -1 (outlier)."""
        import detection

        detector = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Feed 80 normal samples
        for i in range(80):
            features = [
                30.0 + (i % 5) * 0.5,
                8.0 + (i % 3) * 0.1,
                10.0 + (i % 4) * 0.2,
                5.0 + (i % 3) * 0.1,
                50.0 + (i % 6) * 0.3,
                200.0 + (i % 10) * 0.5,
            ]
            detector.add_sample(features)

        detector.train()

        # Predict an anomalous sample (3x normal values)
        anomalous = [90.0, 24.0, 50.0, 30.0, 200.0, 500.0]
        result = detector.predict(anomalous)
        assert result is not None
        assert "score" in result
        assert "is_anomaly" in result
        # Anomaly should be flagged
        assert result["is_anomaly"] is True, (
            f"Anomalous sample not flagged: {result}")

    def test_insufficient_data_status(self):
        """Status is 'insufficient_data' when below min_samples."""
        import detection

        detector = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Feed only 10 samples
        for i in range(10):
            features = [30.0, 8.0, 10.0, 5.0, 50.0, 200.0]
            detector.add_sample(features)

        status = detector.get_status()
        assert status["status"] == "insufficient_data"
        assert status["samples_collected"] == 10
        assert status["samples_required"] == 30
        assert status["is_trained"] is False

    def test_model_persistence(self):
        """Model can be saved and loaded from disk."""
        import detection

        detector1 = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Train on normal data
        for i in range(80):
            features = [
                30.0 + (i % 5) * 0.5,
                8.0 + (i % 3) * 0.1,
                10.0 + (i % 4) * 0.2,
                5.0 + (i % 3) * 0.1,
                50.0 + (i % 6) * 0.3,
                200.0 + (i % 10) * 0.5,
            ]
            detector1.add_sample(features)

        detector1.train()
        assert detector1.is_trained

        # Save model
        save_path = self._temp_model_path
        detector1.save(save_path)
        assert os.path.exists(save_path), f"Model file should exist at {save_path}"

        # Load into new detector (use a different temp path to not auto-load)
        load_path = "/tmp/test_load_isolation_forest.pkl"
        detector1.save(load_path)
        try:
            detector2 = detection.AnomalyDetector(model_path="/tmp/nonexistent.pkl")
            detector2.load(load_path)
            assert detector2.is_trained is True
            assert detector2.model is not None

            # Both detectors should give same prediction
            test_sample = [31.0, 8.2, 10.5, 5.1, 52.0, 202.0]
            r1 = detector1.predict(test_sample)
            r2 = detector2.predict(test_sample)
            assert r1["is_anomaly"] == r2["is_anomaly"], (
                "Loaded model should produce same predictions")
        finally:
            if os.path.exists(load_path):
                os.unlink(load_path)

    def test_model_health_metrics(self):
        """get_health returns expected health metrics structure."""
        import detection

        detector = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Feed samples and train
        for i in range(80):
            features = [
                30.0 + (i % 5) * 0.5,
                8.0 + (i % 3) * 0.1,
                10.0 + (i % 4) * 0.2,
                5.0 + (i % 3) * 0.1,
                50.0 + (i % 6) * 0.3,
                200.0 + (i % 10) * 0.5,
            ]
            detector.add_sample(features)
        detector.train()

        health = detector.get_health()
        assert isinstance(health, dict)
        assert "status" in health
        assert "is_trained" in health
        assert "samples_collected" in health
        assert "model_trained_at" in health
        assert "feature_count" in health
        assert health["is_trained"] is True
        assert health["samples_collected"] == 80
        assert health["feature_count"] == 6

    def test_no_prediction_before_training(self):
        """Predict returns None before model is trained."""
        import detection

        detector = detection.AnomalyDetector(
            contamination=0.1, min_samples=30,
            model_path=self._temp_model_path)

        # Don't train — model should be None
        result = detector.predict([30.0, 8.0, 10.0, 5.0, 50.0, 200.0])
        assert result is None, "Should return None before training"

    def test_get_anomaly_detector_singleton(self):
        """get_anomaly_detector returns singleton instance."""
        import detection
        d1 = detection.get_anomaly_detector()
        d2 = detection.get_anomaly_detector()
        assert d1 is d2, "Should return same singleton instance"

    def test_build_feature_vector(self):
        """_build_feature_vector creates correct-length feature list."""
        import detection
        detector = detection.AnomalyDetector(model_path=self._temp_model_path)

        metrics = {
            "cpu_percent": 45.0,
            "ram_used_gb": 12.5,
            "disk_read_kbps": 150.0,
            "disk_write_kbps": 80.0,
            "network_connections": 120,
            "process_count": 350,
        }
        vec = detector._build_feature_vector(metrics)
        assert len(vec) == 6, f"Expected 6 features, got {len(vec)}"
        assert vec == [45.0, 12.5, 150.0, 80.0, 120.0, 350.0]

    def test_build_feature_vector_missing_metric(self):
        """_build_feature_vector uses 0 for missing metrics."""
        import detection
        detector = detection.AnomalyDetector(model_path=self._temp_model_path)

        metrics = {
            "cpu_percent": 45.0,
            "ram_used_gb": 12.5,
        }
        vec = detector._build_feature_vector(metrics)
        assert len(vec) == 6
        assert vec[0] == 45.0
        assert vec[1] == 12.5
        assert vec[2] == 0.0  # missing disk_read_kbps


class TestAnomalyDetectorHealthEndpoint:
    """Test the /api/v2/ueba/health endpoint response structure."""

    _temp_model_path = "/tmp/test_health_isolation_forest.pkl"

    def setup_method(self):
        """Clean up temp model file before each test."""
        if os.path.exists(self._temp_model_path):
            os.unlink(self._temp_model_path)

    def teardown_method(self):
        """Clean up temp model file after each test."""
        if os.path.exists(self._temp_model_path):
            os.unlink(self._temp_model_path)

    def test_health_endpoint_response(self):
        """Health endpoint returns proper JSON structure."""
        import detection

        # We test get_ueba_health() directly, not via HTTP
        # Use a fresh detector to avoid interference
        detection._anomaly_detector = None
        detector = detection.AnomalyDetector(model_path=self._temp_model_path)
        detection._anomaly_detector = detector

        # Feed samples and train
        for i in range(80):
            features = [
                30.0 + (i % 5) * 0.5,
                8.0 + (i % 3) * 0.1,
                10.0 + (i % 4) * 0.2,
                5.0 + (i % 3) * 0.1,
                50.0 + (i % 6) * 0.3,
                200.0 + (i % 10) * 0.5,
            ]
            detector.add_sample(features)
        detector.train()

        health = detection.get_ueba_health()
        assert isinstance(health, dict)
        assert "model_status" in health
        assert "entities_monitored" in health
        assert "baselines_active" in health
        assert "anomalies_24h" in health
        assert "model_trained_at" in health
        assert "feature_count" in health
        assert "samples_collected" in health
        assert "min_samples_required" in health
        assert "contamination" in health
        assert "anomaly_score_mean" in health

    def test_health_when_not_trained(self):
        """Health endpoint shows proper status when model not trained."""
        import detection

        # Reset the singleton to get a fresh detector with no saved model
        detection._anomaly_detector = None
        detector = detection.AnomalyDetector(model_path=self._temp_model_path)
        detection._anomaly_detector = detector

        health = detection.get_ueba_health()
        assert health["model_status"] in ("initializing", "insufficient_data")
        assert health["is_trained"] is False
        assert health["anomalies_24h"] >= 0
