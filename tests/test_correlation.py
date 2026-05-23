"""Tests for the Correlation Engine — multi-stage attack chain detection."""

import sys
import os
import time
import pytest

# Add parent dir to path so detection module is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import detection


@pytest.fixture
def fresh_engine():
    """Create a fresh CorrelationEngine with no pending state."""
    import sqlite3
    import tempfile

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.row_factory = sqlite3.Row
    # Create the correlation_matches table
    db.executescript("""
        CREATE TABLE IF NOT EXISTS correlation_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id TEXT NOT NULL,
            chain_name TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT NOT NULL DEFAULT (datetime('now')),
            steps_json TEXT DEFAULT '[]',
            severity TEXT NOT NULL DEFAULT 'high'
        );
    """)
    db.commit()

    engine = detection.CorrelationEngine(db)
    # Don't start expiry thread — we control expiry manually
    yield engine
    engine.stop()


def make_alert(category, severity="high", title="Test", source_host="",
               source_ip=""):
    """Helper: create a minimal alert dict as the pipeline would.

    Pass source_ip only (empty source_host) so the correlation key uses the IP.
    """
    from datetime import datetime, timezone
    return {
        "id": 1,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "severity": severity,
        "category": category,
        "title": title,
        "source_host": source_host,
        "source_ip": source_ip,
        "description": "",
        "raw_data": {},
        "acknowledged": False,
    }


# ── Test 1: Complete chain triggers ──
def test_full_chain_completes(fresh_engine):
    """Processing all steps of a chain in order creates a completed match."""
    engine = fresh_engine

    # portscan_sshbrute: step 1 = port_scan, step 2 = brute_force
    engine.process_alert(make_alert("port_scan", source_ip="10.0.0.99"))
    assert len(engine._pending) == 1

    engine.process_alert(make_alert("brute_force", source_ip="10.0.0.99"))
    # After completion, pending is cleared
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains()
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "portscan_sshbrute"
    assert completed[0]["host"] == "10.0.0.99"
    assert completed[0]["severity"] == "critical"


# ── Test 2: Partial chain stays pending ──
def test_partial_chain_stays_pending(fresh_engine):
    """If only the first step fires, the chain remains in pending state."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.0.50"))
    assert len(engine._pending) == 1

    active = engine.get_active_chains()
    assert len(active) == 1
    assert active[0]["chain_id"] == "portscan_sshbrute"
    assert active[0]["step_index"] == 1
    assert active[0]["total_steps"] == 2


# ── Test 3: TTL expiry removes stale partial matches ──
def test_expiry_removes_stale(fresh_engine):
    """Stale pending matches are cleaned up by _expire_pending."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.0.7"))
    assert len(engine._pending) == 1

    # Manually age the pending entry
    key = ("10.0.0.7", "portscan_sshbrute")
    engine._pending[key]["last_match_at"] = time.time() - 9999

    engine._expire_pending()
    assert len(engine._pending) == 0


# ── Test 4: Multi-step chain (3 steps) completes ──
def test_multi_step_chain_completes(fresh_engine):
    """Chain with 3 steps (fim → new_process → outbound_connection) completes."""
    engine = fresh_engine

    host = "10.0.1.1"
    engine.process_alert(make_alert("file_integrity", source_ip=host))
    assert len(engine._pending) == 1

    engine.process_alert(make_alert("new_process", source_ip=host))
    active = engine.get_active_chains(host=host)
    assert active[0]["step_index"] == 2

    engine.process_alert(make_alert("outbound_connection", source_ip=host))
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains(host=host)
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "fim_process_outbound"


# ── Test 5: Multiple hosts tracked independently ──
def test_multiple_hosts_tracked_separately(fresh_engine):
    """Each host gets its own pending chain state."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.1.1"))
    engine.process_alert(make_alert("port_scan", source_ip="10.0.2.2"))
    assert len(engine._pending) == 2

    # Complete chain for host 1 only
    engine.process_alert(make_alert("brute_force", source_ip="10.0.1.1"))
    assert len(engine._pending) == 1  # host 2 still pending

    active = engine.get_active_chains()
    assert len(active) == 1
    assert active[0]["host"] == "10.0.2.2"

    completed = engine.get_completed_chains()
    assert len(completed) == 1
    assert completed[0]["host"] == "10.0.1.1"


# ── Test 6: Duplicate alerts don't break chain tracking ──
def test_duplicate_alerts_dont_break_chain(fresh_engine):
    """Processing the same category multiple times doesn't break the chain."""
    engine = fresh_engine

    # auth_spike_login_newip needs 3 auth_failure then 1 auth_success
    host = "10.0.3.3"
    engine.process_alert(make_alert("auth_failure", source_ip=host))
    engine.process_alert(make_alert("auth_failure", source_ip=host))
    engine.process_alert(make_alert("auth_failure", source_ip=host))
    assert len(engine._pending) == 1

    active = engine.get_active_chains(host=host)
    assert active[0]["step_index"] == 1  # moved to step 2
    assert active[0]["step_counts"].get("auth_failure") == 3

    engine.process_alert(make_alert("auth_success", source_ip=host))
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains(host=host)
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "auth_spike_login_newip"


# ── Test 7: Out-of-order step resets (gap timeout) ──
def test_gap_timeout_resets_chain(fresh_engine):
    """If the next step doesn't arrive within max_gap, the chain expires."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.5.5"))
    assert len(engine._pending) == 1

    # Age the last_match_at past the max_gap for step 1 (300s)
    key = ("10.0.5.5", "portscan_sshbrute")
    engine._pending[key]["last_match_at"] = time.time() - 999

    # Process a wrong-category alert — the pending state is aged, so it should
    # be deleted and a new one won't start unless it matches step 0
    engine.process_alert(make_alert("dga", source_ip="10.0.5.5"))
    # The old pending entry timed out (portscan_sshbrute), dga starts its own chain
    assert len(engine._pending) >= 1
    # portscan_sshbrute should be gone
    assert ("10.0.5.5", "portscan_sshbrute") not in engine._pending


# ── Test 8: get_active_chains host filter ──
def test_get_active_chains_host_filter(fresh_engine):
    """Host filter returns only matching chains."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.10.1"))
    engine.process_alert(make_alert("port_scan", source_ip="10.0.10.2"))
    engine.process_alert(make_alert("threat_intel", source_ip="10.0.10.3"))

    all_active = engine.get_active_chains()
    assert len(all_active) == 3

    filtered = engine.get_active_chains(host="10.0.10.1")
    assert len(filtered) == 1
    assert filtered[0]["host"] == "10.0.10.1"


# ── Test 9: Empty alert is ignored ──
def test_empty_alert_ignored(fresh_engine):
    """None or empty alert does not crash the engine."""
    engine = fresh_engine
    engine.process_alert(None)
    engine.process_alert({})
    assert len(engine._pending) == 0


# ── Test 10: get_completed_chains returns empty when no matches ──
def test_get_completed_chains_empty(fresh_engine):
    """Fresh engine returns empty completed list."""
    engine = fresh_engine
    completed = engine.get_completed_chains()
    assert completed == []


# ── Test 11: Concurrent access doesn't corrupt state ──
def test_concurrent_access_is_safe(fresh_engine):
    """Multiple threads processing alerts don't corrupt pending state."""
    import threading

    engine = fresh_engine
    errors = []

    def worker(host_suffix):
        try:
            for i in range(50):
                engine.process_alert(
                    make_alert("port_scan", source_ip=f"10.0.{host_suffix}.1")
                )
                engine.process_alert(
                    make_alert("brute_force", source_ip=f"10.0.{host_suffix}.1")
                )
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0


# ── Test 12: Threat intel → alert spike chain ──
def test_threatintel_alertspike_chain(fresh_engine):
    """threat_intel + 3 alerts within 60s completes the chain."""
    engine = fresh_engine

    host = "10.0.20.1"
    engine.process_alert(make_alert("threat_intel", source_ip=host))
    assert len(engine._pending) == 1

    # Need 3 alerts (step 2 min_count = 3)
    engine.process_alert(make_alert("alert", source_ip=host))
    engine.process_alert(make_alert("alert", source_ip=host))
    # Should still be pending with step_index < total_steps
    active = engine.get_active_chains(host=host)
    assert len(active) == 1
    assert active[0]["step_index"] == 1
    assert active[0]["step_counts"].get("alert", 0) == 2

    engine.process_alert(make_alert("alert", source_ip=host))
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains(host=host)
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "threatintel_alertspike"


# ── Test 13: Correlation alert has MITRE ATT&CK tactic chain from pattern ──
def test_correlation_alert_has_mitre_chain(fresh_engine, monkeypatch):
    """Correlation alert created by _check_completion uses pattern's mitre_chain."""
    engine = fresh_engine

    # Intercept create_alert to inspect the correlation alert
    captured = []
    import detection
    original_create = detection.create_alert

    def fake_create(**kwargs):
        captured.append(kwargs)
        return {"id": 999, "acknowledged": False}

    monkeypatch.setattr(detection, "create_alert", fake_create)

    # Trigger portscan_sshbrute chain (critical, mitre_chain: Reconnaissance → Credential Access)
    engine.process_alert(make_alert("port_scan", source_ip="10.0.30.1"))
    engine.process_alert(make_alert("brute_force", source_ip="10.0.30.1"))

    assert len(captured) == 1
    corr_alert = captured[0]
    assert corr_alert["category"] == "correlation"
    assert corr_alert["severity"] == "critical"
    assert "Reconnaissance" in corr_alert["mitre_tactic"]
    assert "Credential Access" in corr_alert["mitre_tactic"]
    assert "T1046" in corr_alert["mitre_technique"]
    assert "T1110" in corr_alert["mitre_technique"]
    assert "MITRE ATT&CK Chain:" in corr_alert["description"]
    assert "Reconnaissance → Credential Access" in corr_alert["description"]
    raw = corr_alert.get("raw_data", {})
    assert "mitre_chain" in raw
    assert len(raw["mitre_chain"]) == 2


# ── Test 14: Sliding window event buffer stores events ──
def test_event_buffer_stores_events(fresh_engine):
    """After processing alerts, they appear in the sliding window buffer."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.40.1"))
    engine.process_alert(make_alert("brute_force", source_ip="10.0.40.1"))
    engine.process_alert(make_alert("dga", source_ip="10.0.40.2"))

    buffered = engine.get_buffered_events()
    assert len(buffered) >= 3
    assert all("buffered_at" in e for e in buffered)


# ── Test 15: Buffer host filter works ──
def test_event_buffer_host_filter(fresh_engine):
    """get_buffered_events filters by host correctly."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.41.1"))
    engine.process_alert(make_alert("brute_force", source_ip="10.0.41.2"))

    filtered = engine.get_buffered_events(host="10.0.41.1")
    assert len(filtered) == 1
    assert filtered[0]["category"] == "port_scan"


# ── Test 16: Buffer category filter works ──
def test_event_buffer_category_filter(fresh_engine):
    """get_buffered_events filters by category correctly."""
    engine = fresh_engine

    engine.process_alert(make_alert("port_scan", source_ip="10.0.42.1"))
    engine.process_alert(make_alert("brute_force", source_ip="10.0.42.1"))

    filtered = engine.get_buffered_events(category="port_scan")
    assert len(filtered) == 1
    assert filtered[0]["category"] == "port_scan"


# ── Test 17: Periodic evaluation replays buffered events ──
def test_periodic_evaluation_detects_chain(fresh_engine):
    """_evaluate_buffered_events replays events and detects complete chains."""
    engine = fresh_engine

    # Feed events into buffer only (bypass event-driven matching by
    # manually adding to buffer without triggering process_alert logic)
    import time
    now = time.time()
    with engine._event_buffer_lock:
        engine._event_buffer = [
            (now - 60,  make_alert("port_scan", source_ip="10.0.50.1")),
            (now - 30,  make_alert("brute_force", source_ip="10.0.50.1")),
        ]

    # Run periodic evaluation
    engine._evaluate_buffered_events()

    # Should have detected the portscan_sshbrute chain
    completed = engine.get_completed_chains(host="10.0.50.1")
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "portscan_sshbrute"


# ── Test 18: Priv ESC → Beacon chain (new M2 pattern) ──
def test_priv_esc_beacon_chain(fresh_engine):
    """privilege_escalation followed by beaconing triggers priv_esc_beacon pattern."""
    engine = fresh_engine

    host = "10.0.60.1"
    engine.process_alert(make_alert("privilege_escalation", source_ip=host))
    assert len(engine._pending) == 1

    active = engine.get_active_chains(host=host)
    assert active[0]["chain_id"] == "priv_esc_beacon"
    assert active[0]["step_index"] == 1

    engine.process_alert(make_alert("beaconing", source_ip=host))
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains(host=host)
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "priv_esc_beacon"
    assert completed[0]["severity"] == "critical"


# ── Test 19: Lateral movement chain (3-step) ──
def test_lateral_movement_chain(fresh_engine):
    """auth_success → new_process → file_integrity triggers lateral_movement_chain."""
    engine = fresh_engine

    host = "10.0.70.1"
    engine.process_alert(make_alert("auth_success", source_ip=host))
    assert len(engine._pending) == 1

    active = engine.get_active_chains(host=host)
    assert active[0]["chain_id"] == "lateral_movement_chain"

    engine.process_alert(make_alert("new_process", source_ip=host))
    active = engine.get_active_chains(host=host)
    assert active[0]["step_index"] == 2

    engine.process_alert(make_alert("file_integrity", source_ip=host))
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains(host=host)
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "lateral_movement_chain"


# ── Test 20: Exfil beacon chain (multi-count step 2) ──
def test_exfil_beacon_chain(fresh_engine):
    """beaconing + 3 outbound_connections triggers exfil_beacon pattern."""
    engine = fresh_engine

    host = "10.0.80.1"
    engine.process_alert(make_alert("beaconing", source_ip=host))
    assert len(engine._pending) == 1

    active = engine.get_active_chains(host=host)
    assert active[0]["chain_id"] == "exfil_beacon"

    # Step 2 needs 3 outbound_connection alerts
    engine.process_alert(make_alert("outbound_connection", source_ip=host))
    engine.process_alert(make_alert("outbound_connection", source_ip=host))
    active = engine.get_active_chains(host=host)
    assert active[0]["step_index"] == 1
    assert active[0]["step_counts"].get("outbound_connection", 0) == 2

    engine.process_alert(make_alert("outbound_connection", source_ip=host))
    assert len(engine._pending) == 0

    completed = engine.get_completed_chains(host=host)
    assert len(completed) == 1
    assert completed[0]["chain_id"] == "exfil_beacon"


# ── Test 21: All 8 patterns have MITRE chains ──
def test_all_patterns_have_mitre_chains():
    """Every chain pattern must have a mitre_chain matching its step count."""
    import detection
    for pattern in detection.CHAIN_PATTERNS:
        assert "mitre_chain" in pattern, f"{pattern['id']} missing mitre_chain"
        mitre = pattern["mitre_chain"]
        assert len(mitre) == len(pattern["steps"]), (
            f"{pattern['id']}: mitre_chain length {len(mitre)} != steps {len(pattern['steps'])}"
        )
        for tactic, technique in mitre:
            assert isinstance(tactic, str) and len(tactic) > 0
            assert isinstance(technique, str) and len(technique) > 0


# ── Test 22: Buffer prunes events outside 300s window ──
def test_buffer_prunes_old_events(fresh_engine):
    """Events older than 300s are pruned from the sliding window."""
    engine = fresh_engine
    import time

    now = time.time()

    # Inject old event directly into buffer
    with engine._event_buffer_lock:
        engine._event_buffer = [
            (now - 400, make_alert("port_scan", source_ip="10.0.90.1")),
            (now - 200, make_alert("brute_force", source_ip="10.0.90.1")),
            (now - 50,  make_alert("dga", source_ip="10.0.90.2")),
        ]

    # Buffer a new event — triggers pruning
    engine.process_alert(make_alert("threat_intel", source_ip="10.0.90.3"))

    buffered = engine.get_buffered_events()
    # The 400s-old event should be pruned
    assert len(buffered) <= 3  # at most 3 (400s-old is pruned)
    # The 400s event should not be present
    hosts_in_buffer = {e.get("source_ip", "") for e in buffered}
    assert "10.0.90.1" in hosts_in_buffer  # the 200s event keeps this host


# ── Test 23: Buffer respects max size limit ──
def test_buffer_max_size(fresh_engine):
    """Buffer is trimmed when it exceeds EVENT_BUFFER_MAX_SIZE."""
    engine = fresh_engine
    import time
    import detection

    now = time.time()
    max_size = detection.EVENT_BUFFER_MAX_SIZE

    # Fill buffer past max
    with engine._event_buffer_lock:
        engine._event_buffer = [
            (now - i, make_alert("port_scan", source_ip=f"10.0.{i}.1"))
            for i in range(max_size + 500)
        ]

    # Trigger pruning via new event
    engine.process_alert(make_alert("brute_force", source_ip="10.0.99.1"))

    with engine._event_buffer_lock:
        assert len(engine._event_buffer) <= max_size


# ── Test 24: Correlation engine is importable ──
def test_correlation_engine_importable():
    """detection module exposes CorrelationEngine and get_correlation_engine."""
    import detection
    assert hasattr(detection, "CorrelationEngine")
    assert hasattr(detection, "get_correlation_engine")
    assert hasattr(detection, "CHAIN_PATTERNS")
    assert len(detection.CHAIN_PATTERNS) >= 8
