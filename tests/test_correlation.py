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
