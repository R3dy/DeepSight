"""Tests for Enhanced UEBA — per-entity baselines, peer groups, risk scoring."""

import sys
import os
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestEntityBaselines:
    """Test per-entity (per-user, per-host) baseline tracking."""

    def test_entity_baseline_creation(self):
        """Entity baselines can be created for hosts and users."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)
        # Ensure tables created
        engine._create_tables()

        # Create host baseline
        engine.update_entity("host", "web-server-01", "cpu_percent", 45.0)
        engine.update_entity("host", "web-server-01", "cpu_percent", 46.0)
        engine.update_entity("host", "web-server-01", "cpu_percent", 44.0)

        # Create user baseline
        engine.update_entity("user", "alice", "login_count_per_hour", 3.0)
        engine.update_entity("user", "alice", "login_count_per_hour", 4.0)
        engine.update_entity("user", "alice", "login_count_per_hour", 3.0)

        # Get baselines
        host_baselines = engine.get_entity_baselines(entity_type="host", entity_id="web-server-01")
        user_baselines = engine.get_entity_baselines(entity_type="user", entity_id="alice")

        assert len(host_baselines) == 1
        assert len(user_baselines) == 1
        assert host_baselines[0]["entity_type"] == "host"
        assert host_baselines[0]["entity_id"] == "web-server-01"
        assert user_baselines[0]["entity_type"] == "user"
        assert user_baselines[0]["entity_id"] == "alice"

    def test_entity_baseline_zscore(self):
        """Entity baselines correctly compute z-scores."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        # Build stable baseline with very tight values (low stddev)
        for i in range(50):
            engine.update_entity("host", "db-01", "disk_io_mbps", 100.0 + (i % 2) * 0.3)

        # Huge spike (>5 sigma)
        result = engine.update_entity("host", "db-01", "disk_io_mbps", 400.0)
        assert result is not None
        z_score, mean, stddev, is_learning = result
        assert not is_learning
        assert z_score > 3.0, f"Z-score should be high for spike, got {z_score:.2f}"

        # For drop test, use a fresh baseline with low variance and different host
        for i in range(50):
            engine.update_entity("host", "db-drop-test", "disk_io_mbps", 100.0 + (i % 2) * 0.2)

        # Massive drop (>5 sigma)
        result = engine.update_entity("host", "db-drop-test", "disk_io_mbps", 5.0)
        assert result is not None
        z_score, mean, stddev, is_learning = result
        assert z_score < -3.0, f"Z-score should be negative for drop, got {z_score:.2f}"

    def test_entity_baseline_sqlite_persistence(self):
        """Entity baseline state persists to SQLite."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        for i in range(35):
            engine.update_entity("user", "bob", "commands_per_hour", 50.0 + i % 10)

        row = db.execute(
            "SELECT * FROM ueba_entity_baselines WHERE entity_type=? AND entity_id=? AND metric=?",
            ("user", "bob", "commands_per_hour")
        ).fetchone()

        assert row is not None, "Baseline row should exist"
        assert row["count"] >= 35
        assert row["mean"] > 0
        assert row["is_learning"] == 0

    def test_list_all_entities(self):
        """Can list all entities with their types."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        engine.update_entity("host", "web-01", "cpu_percent", 30.0)
        engine.update_entity("host", "db-01", "cpu_percent", 50.0)
        engine.update_entity("user", "alice", "login_count_per_hour", 2.0)

        entities = engine.list_entities()
        assert len(entities) >= 3

        # Filter by type
        hosts = engine.list_entities(entity_type="host")
        assert len(hosts) >= 2
        users = engine.list_entities(entity_type="user")
        assert len(users) >= 1

    def test_entity_metrics_list(self):
        """Can list all metrics tracked for an entity."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        engine.update_entity("host", "web-01", "cpu_percent", 30.0)
        engine.update_entity("host", "web-01", "ram_used_gb", 8.0)
        engine.update_entity("host", "web-01", "network_connections", 50.0)

        metrics = engine.get_entity_baselines(entity_type="host", entity_id="web-01")
        metric_names = [m["metric"] for m in metrics]
        assert "cpu_percent" in metric_names
        assert "ram_used_gb" in metric_names
        assert "network_connections" in metric_names


class TestPeerGroupComparison:
    """Test peer group assignment and comparison."""

    def test_peer_group_assignment(self):
        """Entities can be assigned to peer groups."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        pgm = ueba_engine.PeerGroupManager(db)

        # Assign entity to peer group
        pgm.assign_entity("web-server-01", "production_web_servers", "host", auto=False)
        pgm.assign_entity("web-server-02", "production_web_servers", "host", auto=False)
        pgm.assign_entity("db-server-01", "database_servers", "host", auto=False)

        # Get peer group members
        members = pgm.get_group_members("production_web_servers")
        assert len(members) == 2
        member_ids = [m["entity_id"] for m in members]
        assert "web-server-01" in member_ids
        assert "web-server-02" in member_ids

    def test_peer_group_auto_assignment(self):
        """Entities are auto-assigned based on hostname patterns."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        pgm = ueba_engine.PeerGroupManager(db)

        group = pgm.auto_assign_group("prod-web-01", "host")
        assert group is not None
        # Should match "prod-web" pattern
        assert "web" in group.lower() or "prod" in group.lower()

        group2 = pgm.auto_assign_group("prod-web-02", "host")
        assert group2 == group, "Similar hosts should get same peer group"

        group3 = pgm.auto_assign_group("staging-db-01", "host")
        assert group3 != group, "Different host type should get different peer group"

    def test_peer_comparison_statistics(self):
        """Peer group comparison provides statistics."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        pgm = ueba_engine.PeerGroupManager(db)

        # Assign 3 web servers to same group
        pgm.assign_entity("web-01", "web_servers", "host")
        pgm.assign_entity("web-02", "web_servers", "host")
        pgm.assign_entity("web-03", "web_servers", "host")

        # Set baselines via engine
        engine = ueba_engine.EnhancedUEBAEngine(db)
        for host in ["web-01", "web-02", "web-03"]:
            base_cpu = 30.0 if host != "web-03" else 65.0  # web-03 is outlier
            for i in range(40):
                engine.update_entity("host", host, "cpu_percent", base_cpu + (i % 3) * 0.5)
            engine.update_entity("host", host, "ram_used_gb", 8.0)

        # Get peer comparison for web-03 (should show deviation)
        comparison = engine.get_peer_comparison("host", "web-03", "web_servers", "cpu_percent")
        assert comparison is not None
        assert "entity_value" in comparison
        assert "peer_mean" in comparison
        assert "peer_stddev" in comparison
        assert "percentile" in comparison
        # web-03 should be above peer mean
        if comparison["peer_mean"] > 0:
            assert comparison["entity_value"] > comparison["peer_mean"]

    def test_list_peer_groups(self):
        """Can list all peer groups."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        pgm = ueba_engine.PeerGroupManager(db)

        pgm.assign_entity("web-01", "web_servers", "host")
        pgm.assign_entity("db-01", "database_servers", "host")

        groups = pgm.list_groups()
        assert len(groups) >= 2
        group_names = [g["name"] for g in groups]
        assert "web_servers" in group_names
        assert "database_servers" in group_names


class TestRiskScorer:
    """Test composite risk scoring with decay."""

    def test_initial_risk_score(self):
        """RiskScorer starts entities at 0 risk."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db)

        score = scorer.get_risk_score("host", "web-01")
        assert isinstance(score, dict)
        assert score["risk_score"] == 0.0
        assert score["risk_level"] == "normal"

    def test_risk_score_increase(self):
        """Risk score increases when anomalous events occur."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db)

        # Add behavioral anomaly signal
        scorer.add_signal("host", "web-01", "behavioral_deviation", 45.0)
        score = scorer.get_risk_score("host", "web-01")
        assert score["risk_score"] > 0
        assert "behavioral" in score["factors"]

    def test_risk_score_decay(self):
        """Risk scores decay over time."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db, decay_half_life_hours=0.001)  # very fast decay

        # Boost risk with multiple signals to build composite > 50
        scorer.add_signal("host", "web-01", "behavioral_deviation", 90.0)
        scorer.add_signal("host", "web-01", "threat_intel_match", 70.0)
        scorer.add_signal("host", "web-01", "alert_count", 60.0)
        scorer.add_signal("host", "web-01", "peer_outlier", 80.0)
        score1 = scorer.get_risk_score("host", "web-01")
        assert score1["risk_score"] > 50, (
            f"Composite should be > 50, got {score1['risk_score']:.1f}"
        )

        # Force decay: update risk score with old timestamp
        # Use ISO format matching what the app stores
        from datetime import datetime, timezone, timedelta
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.execute("""
            UPDATE ueba_risk_scores
            SET last_updated = ?
            WHERE entity_type='host' AND entity_id='web-01'
        """, (old_ts,))
        db.commit()

        score2 = scorer.get_risk_score("host", "web-01")
        assert score2["risk_score"] < score1["risk_score"], (
            f"Risk should decay: {score1['risk_score']:.1f} → {score2['risk_score']:.1f}"
        )

    def test_composite_factors(self):
        """Risk score breakdown shows contributing factors."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db)

        scorer.add_signal("host", "db-01", "behavioral_deviation", 60.0)
        scorer.add_signal("host", "db-01", "threat_intel_match", 30.0)
        scorer.add_signal("host", "db-01", "alert_count", 20.0)
        scorer.add_signal("host", "db-01", "peer_outlier", 40.0)

        score = scorer.get_risk_score("host", "db-01")
        assert "factors" in score
        factors = score["factors"]
        assert "behavioral" in factors
        assert "threat_intel" in factors
        assert "alerts" in factors
        assert "peer_outlier" in factors
        assert factors["behavioral"] > 0
        assert factors["threat_intel"] > 0

    def test_risk_levels(self):
        """Risk levels map to correct thresholds."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db)

        # Test various risk levels.
        # Composite = behavioral*0.40 + threat_intel*0.25 + alert*0.20 + peer*0.15
        # To reach elevated (30): need composite >= 30, e.g. behavioral >= 75
        # To reach moderate (60): need composite >= 60, e.g. multiple signals

        # Test normal (low signal)
        scorer.add_signal("host", "test-normal", "behavioral_deviation", 20.0)
        score = scorer.get_risk_score("host", "test-normal")
        assert score["risk_level"] == "normal", (
            f"Signal 20: expected normal, got {score['risk_level']} (score={score['risk_score']})"
        )

        # Test elevated (single strong signal: 85*0.40 = 34 >= 30)
        scorer.add_signal("host", "test-elevated", "behavioral_deviation", 85.0)
        score = scorer.get_risk_score("host", "test-elevated")
        assert score["risk_level"] == "elevated", (
            f"Signal 85: expected elevated, got {score['risk_level']} (score={score['risk_score']})"
        )

        # Test moderate (multiple strong signals: 95*0.40 + 90*0.25 = 38+22.5=60.5)
        scorer.add_signal("host", "test-moderate", "behavioral_deviation", 95.0)
        scorer.add_signal("host", "test-moderate", "threat_intel_match", 90.0)
        score = scorer.get_risk_score("host", "test-moderate")
        assert score["risk_level"] == "moderate", (
            f"Multiple signals: expected moderate, got {score['risk_level']} (score={score['risk_score']})"
        )

        # Test critical (very strong across multiple factors: 100*0.40+100*0.25+100*0.20 = 85)
        scorer.add_signal("host", "test-critical", "behavioral_deviation", 100.0)
        scorer.add_signal("host", "test-critical", "threat_intel_match", 100.0)
        scorer.add_signal("host", "test-critical", "alert_count", 100.0)
        score = scorer.get_risk_score("host", "test-critical")
        assert score["risk_level"] == "critical", (
            f"Multiple max signals: expected critical, got {score['risk_level']} (score={score['risk_score']})"
        )

    def test_risk_score_history(self):
        """Risk score changes are recorded in history."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db)

        scorer.add_signal("host", "web-01", "behavioral_deviation", 70.0)
        history = scorer.get_risk_history("host", "web-01", hours=24)
        assert len(history) >= 1
        assert history[0]["entity_type"] == "host"
        assert history[0]["entity_id"] == "web-01"

    def test_risk_threshold_config(self):
        """Risk thresholds are configurable."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        # Lower thresholds so moderate signals trigger higher levels
        scorer = ueba_engine.RiskScorer(db, thresholds={
            "elevated": 10, "moderate": 20, "critical": 40
        })

        # composite = 80*0.40 = 32, with critical=40 → moderate (between 20 and 40)
        scorer.add_signal("host", "custom-01", "behavioral_deviation", 80.0)
        score = scorer.get_risk_score("host", "custom-01")
        assert score["risk_level"] == "moderate", (
            f"With custom thresholds, composite~32 should be moderate, got {score['risk_level']} (score={score['risk_score']})"
        )

    def test_decay_notification_on_crossing_threshold(self):
        """When risk decays below a threshold, it's recorded."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db, decay_half_life_hours=0.001)

        # Boost to high with multiple signals to guarantee moderate/critical
        scorer.add_signal("host", "decay-test", "behavioral_deviation", 100.0)
        scorer.add_signal("host", "decay-test", "threat_intel_match", 100.0)
        score1 = scorer.get_risk_score("host", "decay-test")
        # composite = 100*0.40 + 100*0.25 = 65, which is moderate (>= 60)
        assert score1["risk_level"] in ("critical", "moderate", "elevated"), (
            f"Expected at least elevated, got {score1['risk_level']} (score={score1['risk_score']})"
        )

        # Force fast decay
        from datetime import datetime, timezone, timedelta
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.execute("""
            UPDATE ueba_risk_scores
            SET last_updated = ?
            WHERE entity_type='host' AND entity_id='decay-test'
        """, (old_ts,))
        db.commit()

        score2 = scorer.get_risk_score("host", "decay-test")
        # Should have decayed below original level
        assert score2["risk_score"] < score1["risk_score"]


class TestUEBAApiEndpoints:
    """Test the UEBA v2 API endpoints response structure."""

    def test_timeline_endpoint_structure(self):
        """Timeline endpoint returns anomaly timeline data."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)
        engine._create_tables()

        # Add some anomalies with different times
        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES
            (datetime('now', '-1 hours'), 'host', 'web-01', 'cpu_percent',
             4.5, 85.0, 45.0, 8.9, 'high', 'spike', 0),
            (datetime('now', '-2 hours'), 'host', 'web-01', 'ram_used_gb',
             5.2, 24.0, 8.0, 3.1, 'high', 'spike', 0),
            (datetime('now', '-30 minutes'), 'user', 'alice', 'login_count_per_hour',
             3.8, 25.0, 5.0, 5.3, 'medium', 'spike', 0)
        """)
        db.commit()

        timeline = engine.get_anomaly_timeline(hours=24)
        assert isinstance(timeline, dict)
        assert "labels" in timeline
        assert "counts" in timeline
        assert timeline["total"] == 3

    def test_deviations_endpoint_structure(self):
        """Deviations endpoint returns sorted entity deviations."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        # Create entities with different deviations
        for i in range(40):
            engine.update_entity("host", "high-risk-host", "cpu_percent", 90.0)
            engine.update_entity("host", "normal-host", "cpu_percent", 45.0)

        # Spike on high-risk
        engine.update_entity("host", "high-risk-host", "cpu_percent", 99.0)

        deviations = engine.get_deviations()
        assert isinstance(deviations, list)
        # Highest risk should be first
        if len(deviations) >= 2:
            assert deviations[0]["risk_score"] >= deviations[-1]["risk_score"]

    def test_anomaly_list_pagination(self):
        """Anomaly list supports limit/offset pagination."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        # Add 15 anomalies
        for i in range(15):
            db.execute("""
                INSERT INTO ueba_anomalies
                (timestamp, entity_type, entity_id, metric, z_score,
                 current_value, mean, stddev, severity, anomaly_type, acknowledged)
                VALUES (datetime('now', ?), 'host', 'test', 'cpu_percent',
                 ?, 80.0, 50.0, 10.0, 'medium', 'spike', 0)
            """, (f"-{i} minutes", 3.0 + i * 0.1))
        db.commit()

        # Page 1
        page1 = engine.get_anomalies(limit=10, offset=0)
        assert len(page1) == 10

        # Page 2
        page2 = engine.get_anomalies(limit=10, offset=10)
        assert len(page2) == 5

    def test_anomaly_acknowledgment(self):
        """Anomalies can be acknowledged."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES (datetime('now'), 'host', 'test', 'cpu_percent',
             4.0, 80.0, 50.0, 7.5, 'high', 'spike', 0)
        """)
        db.commit()
        anomaly_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        result = engine.acknowledge_anomaly(anomaly_id)
        assert result is True

        # Check it's acknowledged
        row = db.execute("SELECT acknowledged FROM ueba_anomalies WHERE id=?",
                         (anomaly_id,)).fetchone()
        assert row["acknowledged"] == 1

    def test_anomaly_promote_to_alert(self):
        """Anomalies can be promoted to alerts."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES (datetime('now'), 'host', 'prod-01', 'cpu_percent',
             5.5, 95.0, 50.0, 8.2, 'high', 'spike', 0)
        """)
        db.commit()
        anomaly_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        promoted = engine.promote_to_alert(anomaly_id)
        assert promoted is True

        # Check anomaly is marked as promoted
        row = db.execute("SELECT promoted_alert_id FROM ueba_anomalies WHERE id=?",
                         (anomaly_id,)).fetchone()
        assert row["promoted_alert_id"] is not None

    def test_false_positive_marking(self):
        """Anomalies can be marked as false positives."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES (datetime('now'), 'host', 'test', 'cpu_percent',
             3.5, 70.0, 50.0, 5.7, 'medium', 'spike', 0)
        """)
        db.commit()
        anomaly_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        result = engine.mark_false_positive(anomaly_id, "Normal maintenance window")
        assert result is True

        row = db.execute("SELECT is_false_positive, false_positive_reason FROM ueba_anomalies WHERE id=?",
                         (anomaly_id,)).fetchone()
        assert row["is_false_positive"] == 1
        assert "maintenance" in row["false_positive_reason"].lower()

    def test_bulk_anomaly_acknowledgment(self):
        """Multiple anomalies can be acknowledged in bulk."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        ids = []
        for i in range(5):
            db.execute("""
                INSERT INTO ueba_anomalies
                (timestamp, entity_type, entity_id, metric, z_score,
                 current_value, mean, stddev, severity, anomaly_type, acknowledged)
                VALUES (datetime('now'), 'host', 'test', 'cpu_percent',
                 ?, 80.0, 50.0, 10.0, 'medium', 'spike', 0)
            """, (3.0 + i * 0.2,))
            db.commit()
            ids.append(db.execute("SELECT last_insert_rowid()").fetchone()[0])

        result = engine.acknowledge_anomalies_bulk(ids)
        assert result["acknowledged"] >= 5, (
            f"Expected at least 5 acknowledged, got {result['acknowledged']}"
        )

        # Verify all acknowledged
        for aid in ids:
            row = db.execute("SELECT acknowledged FROM ueba_anomalies WHERE id=?",
                             (aid,)).fetchone()
            assert row["acknowledged"] == 1

    def test_baseline_reset(self):
        """Entity baseline can be reset."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        # Build baseline
        for i in range(50):
            engine.update_entity("host", "reset-test", "cpu_percent", 45.0)

        baselines_before = engine.get_entity_baselines(entity_type="host", entity_id="reset-test")
        assert len(baselines_before) == 1
        assert not baselines_before[0]["is_learning"]

        # Reset
        result = engine.reset_entity_baseline("host", "reset-test")
        assert result is True

        baselines_after = engine.get_entity_baselines(entity_type="host", entity_id="reset-test")
        # After reset, baseline should be in learning state or removed
        if len(baselines_after) > 0:
            assert baselines_after[0]["is_learning"]

    def test_entity_search(self):
        """Entities can be searched by name."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        engine.update_entity("host", "prod-web-01", "cpu_percent", 30.0)
        engine.update_entity("host", "prod-web-02", "cpu_percent", 35.0)
        engine.update_entity("host", "staging-db-01", "cpu_percent", 50.0)
        engine.update_entity("user", "alice", "login_count_per_hour", 2.0)

        results = engine.search_entities("prod-web")
        assert len(results) >= 2
        result_ids = [r["entity_id"] for r in results]
        assert "prod-web-01" in result_ids
        assert "prod-web-02" in result_ids

        results2 = engine.search_entities("alice")
        assert len(results2) >= 1
        assert results2[0]["entity_type"] == "user"

    def test_export_anomalies(self):
        """Anomaly data can be exported."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES
            (datetime('now'), 'host', 'web-01', 'cpu_percent',
             4.5, 85.0, 45.0, 8.9, 'high', 'spike', 0)
        """)
        db.commit()

        export = engine.export_data(entity_type="host", format="json")
        assert isinstance(export, dict)
        assert "anomalies" in export
        assert len(export["anomalies"]) >= 1

        export_csv = engine.export_data(entity_type="host", format="csv")
        assert isinstance(export_csv, str)
        assert "entity_id" in export_csv  # header row

    def test_risk_score_notification_threshold(self):
        """High risk triggers notification threshold flag."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        # Use lower notification threshold so weighted composite triggers it
        scorer = ueba_engine.RiskScorer(db, notification_threshold=30.0)

        # Below threshold (composite = 20 * 0.40 = 8)
        scorer.add_signal("host", "low-risk", "behavioral_deviation", 20.0)
        score_low = scorer.get_risk_score("host", "low-risk")
        assert not score_low.get("notify", False)

        # Above threshold (composite = 100 * 0.40 = 40)
        scorer.add_signal("host", "high-risk", "behavioral_deviation", 100.0)
        score_high = scorer.get_risk_score("host", "high-risk")
        assert score_high.get("notify", False), (
            f"Expected notify=True, got notify={score_high.get('notify')} (score={score_high['risk_score']})"
        )


class TestUEBAIntegration:
    """Integration tests between Enhanced UEBA components."""

    def test_full_flow_baseline_to_risk(self):
        """End-to-end: entity baseline → anomaly → risk score."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row

        # Initialize all components
        engine = ueba_engine.EnhancedUEBAEngine(db)
        pgm = ueba_engine.PeerGroupManager(db)
        scorer = ueba_engine.RiskScorer(db)

        # Assign peer group
        pgm.assign_entity("web-01", "web_servers", "host")
        pgm.assign_entity("web-02", "web_servers", "host")
        pgm.assign_entity("web-03", "web_servers", "host")

        # Build baselines for all web servers (normal behavior)
        for host in ["web-01", "web-02", "web-03"]:
            for i in range(40):
                engine.update_entity("host", host, "cpu_percent", 35.0 + (i % 5) * 0.5)
                engine.update_entity("host", host, "ram_used_gb", 8.0 + (i % 3) * 0.1)
                engine.update_entity("host", host, "network_connections", 100.0 + (i % 4) * 5.0)

        # Anomalous event on web-01
        result = engine.update_entity("host", "web-01", "cpu_percent", 95.0)
        assert result is not None
        z_score, mean, stddev, is_learning = result
        assert z_score > 3.0

        # Record anomaly
        engine.record_anomaly("host", "web-01", "cpu_percent", z_score, 95.0,
                              mean, stddev, "high", "spike")

        # Add risk signal
        scorer.add_signal("host", "web-01", "behavioral_deviation", min(abs(z_score) * 10, 100))

        # Get peer comparison
        comparison = engine.get_peer_comparison("host", "web-01", "web_servers", "cpu_percent")
        if comparison and comparison.get("percentile", 0) > 80:
            scorer.add_signal("host", "web-01", "peer_outlier",
                              (comparison["percentile"] - 50) * 1.6)

        # Composite risk score
        score = scorer.get_risk_score("host", "web-01")
        assert "risk_score" in score
        assert "risk_level" in score
        assert "factors" in score

    def test_risk_score_trend(self):
        """Risk score trend shows direction over time."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        scorer = ueba_engine.RiskScorer(db)

        # Add signals over time (simulate increasing risk)
        scorer.add_signal("host", "trend-test", "behavioral_deviation", 30.0)
        scorer.add_signal("host", "trend-test", "behavioral_deviation", 50.0)
        scorer.add_signal("host", "trend-test", "alert_count", 20.0)

        trend = scorer.get_risk_trend("host", "trend-test", hours=24)
        assert "current" in trend
        assert "previous" in trend
        assert "direction" in trend
        # Should be rising since we added signals
        assert trend["direction"] in ("rising", "stable")

    def test_entity_type_filtering(self):
        """All UEBA data can be filtered by entity type."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        # Add anomalies for both entity types
        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES
            (datetime('now'), 'host', 'web-01', 'cpu_percent', 4.0, 80.0, 50.0, 7.5, 'high', 'spike', 0),
            (datetime('now'), 'user', 'alice', 'login_count_per_hour', 3.5, 20.0, 5.0, 4.3, 'medium', 'spike', 0)
        """)
        db.commit()

        host_anomalies = engine.get_anomalies(entity_type="host")
        user_anomalies = engine.get_anomalies(entity_type="user")

        assert all(a["entity_type"] == "host" for a in host_anomalies)
        assert all(a["entity_type"] == "user" for a in user_anomalies)

    def test_ueba_health_aggregate(self):
        """UEBA health endpoint aggregates comprehensive metrics."""
        import ueba_engine

        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        engine = ueba_engine.EnhancedUEBAEngine(db)

        # Create some entities and anomalies
        for i in range(30):
            engine.update_entity("host", "web-01", "cpu_percent", 40.0 + i % 5)
            engine.update_entity("host", "db-01", "cpu_percent", 60.0 + i % 5)
            engine.update_entity("user", "alice", "login_count_per_hour", 3.0 + i % 2)

        db.execute("""
            INSERT INTO ueba_anomalies
            (timestamp, entity_type, entity_id, metric, z_score,
             current_value, mean, stddev, severity, anomaly_type, acknowledged)
            VALUES
            (datetime('now', '-1 hours'), 'host', 'web-01', 'cpu_percent', 4.5, 85.0, 40.0, 10.0, 'high', 'spike', 0),
            (datetime('now', '-3 hours'), 'host', 'db-01', 'cpu_percent', 5.0, 95.0, 60.0, 7.0, 'high', 'spike', 0)
        """)
        db.commit()

        health = engine.get_ueba_health()
        assert "entities_monitored" in health
        assert health["entities_monitored"] >= 3
        assert "baselines_active" in health
        assert "anomalies_24h" in health
        assert health["anomalies_24h"] >= 2
        assert "false_positive_rate" in health
