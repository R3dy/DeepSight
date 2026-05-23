"""Case Management API tests — full incident lifecycle management.

Tests:
  - POST /api/v2/cases — create case
  - GET /api/v2/cases — list cases with filters
  - GET /api/v2/cases/:id — get case detail
  - PATCH /api/v2/cases/:id — update case (status workflow, assignment, tags)
  - PATCH /api/v2/cases/bulk — bulk status change / assignment
  - POST /api/v2/cases/:id/notes — add investigation note
  - GET /api/v2/cases/:id/notes — list notes
  - POST /api/v2/cases/:id/assign — assign case
  - POST /api/v2/cases/:id/alerts — add alerts to case
  - DELETE /api/v2/cases/:id/alerts/:alert_id — remove alert
  - POST /api/v2/cases/:id/merge — merge cases
  - GET /api/v2/cases/metrics — time-to-resolution metrics
  - Status workflow validation
  - SLA tracking fields
  - Auth requirements
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import app
import auth
import detection


# ═══════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════


@pytest.fixture(autouse=True)
def insecure_auth():
    """Enable insecure auth for test cases."""
    old = auth.INSECURE_NO_AUTH
    auth.INSECURE_NO_AUTH = True
    yield
    auth.INSECURE_NO_AUTH = old


@pytest.fixture
def client():
    """Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def fresh_cases_db():
    """Use a temp alerts.db and reset CaseManager singleton."""
    # Swap detection's DB_PATH with a temp file
    old_path = detection.DB_PATH
    fd, db_path = tempfile.mkstemp(suffix=".db", prefix="test_cases_")
    os.close(fd)
    detection.DB_PATH = db_path
    detection._db_conn = None  # Force reconnect

    # Reset CaseManager singleton
    from routes.v2.cases import CaseManager
    old_instance = CaseManager._instance
    CaseManager._instance = None

    yield

    # Restore
    detection.DB_PATH = old_path
    detection._db_conn = None
    CaseManager._instance = old_instance
    try:
        os.unlink(db_path)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                os.unlink(db_path + suffix)
    except OSError:
        pass


def make_case(client, title="Test Case", severity="high", priority="high",
              description="A test case", source_host="test-host-1",
              alert_ids=None, tags=None):
    """Helper: create a case and return the response JSON data."""
    body = {
        "title": title,
        "severity": severity,
        "priority": priority,
        "description": description,
        "source_host": source_host,
    }
    if alert_ids:
        body["alert_ids"] = alert_ids
    if tags:
        body["tags"] = tags

    rv = client.post("/api/v2/cases",
                     data=json.dumps(body),
                     content_type="application/json")
    assert rv.status_code == 201, f"Create case failed: {rv.get_json()}"
    return rv.get_json()["data"]


# ═══════════════════════════════════════════
# Status Workflow Tests
# ═══════════════════════════════════════════


class TestCaseStatusWorkflow:
    """Test case status lifecycle: New → Investigating → Escalated → Resolved → Closed."""

    def test_create_case_defaults_to_new(self, client, fresh_cases_db):
        """Creating a case sets status to 'new'."""
        case = make_case(client, title="Status Test")
        assert case["status"] == "new"

    def test_valid_transition_new_to_investigating(self, client, fresh_cases_db):
        """New → Investigating is valid."""
        case = make_case(client, title="WF Test")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "investigating"}),
                          content_type="application/json")
        assert rv.status_code == 200
        assert rv.get_json()["data"]["status"] == "investigating"

    def test_valid_transition_investigating_to_escalated(self, client, fresh_cases_db):
        """Investigating → Escalated is valid."""
        case = make_case(client, title="WF Test")
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "investigating"}),
                     content_type="application/json")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "escalated"}),
                          content_type="application/json")
        assert rv.status_code == 200
        assert rv.get_json()["data"]["status"] == "escalated"

    def test_valid_transition_to_resolved(self, client, fresh_cases_db):
        """Case can be resolved with resolution details."""
        case = make_case(client, title="WF Test")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({
                              "status": "resolved",
                              "resolution": "true_positive",
                              "resolved_note": "Blocked the IP and patched the vulnerability.",
                          }),
                          content_type="application/json")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["status"] == "resolved"
        assert data["resolved_at"] is not None
        assert data["resolution"] == "true_positive"
        assert data["resolved_note"] == "Blocked the IP and patched the vulnerability."

    def test_resolved_to_closed(self, client, fresh_cases_db):
        """Resolved → Closed is valid."""
        case = make_case(client, title="WF Test")
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "resolved"}),
                     content_type="application/json")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "closed"}),
                          content_type="application/json")
        assert rv.status_code == 200
        assert rv.get_json()["data"]["status"] == "closed"

    def test_valid_transition_new_to_closed(self, client, fresh_cases_db):
        """New → Closed IS valid (close a false positive directly)."""
        case = make_case(client, title="WF Test")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "closed"}),
                          content_type="application/json")
        assert rv.status_code == 200
        assert rv.get_json()["data"]["status"] == "closed"

    def test_invalid_transition_closed_to_new(self, client, fresh_cases_db):
        """Closed → New is NOT valid. Returns 400."""
        case = make_case(client, title="WF Test")
        # Go through: new → resolved → closed
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "resolved"}),
                     content_type="application/json")
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "closed"}),
                     content_type="application/json")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "new"}),
                          content_type="application/json")
        assert rv.status_code == 400

    def test_reopen_resolved_to_investigating(self, client, fresh_cases_db):
        """Resolved → Investigating is valid (reopen)."""
        case = make_case(client, title="WF Test")
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "resolved",
                                      "resolution": "true_positive"}),
                     content_type="application/json")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "investigating"}),
                          content_type="application/json")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["status"] == "investigating"
        # Reopened case should preserve resolution as historical note
        # and clear resolved_at

    def test_reopen_closed_to_investigating(self, client, fresh_cases_db):
        """Closed → Investigating is valid (reopen)."""
        case = make_case(client, title="WF Test")
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "resolved"}),
                     content_type="application/json")
        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "closed"}),
                     content_type="application/json")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "investigating"}),
                          content_type="application/json")
        assert rv.status_code == 200
        assert rv.get_json()["data"]["status"] == "investigating"

    def test_invalid_status_string_rejected(self, client, fresh_cases_db):
        """Invalid status string returns 400."""
        case = make_case(client, title="WF Test")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"status": "bogus_status"}),
                          content_type="application/json")
        assert rv.status_code == 400

    def test_full_workflow_cycle(self, client, fresh_cases_db):
        """Complete workflow: New → Investigating → Escalated → Resolved → Closed."""
        case = make_case(client, title="Full Cycle")

        steps = [
            ("investigating", 200),
            ("escalated", 200),
            ("resolved", 200),
            ("closed", 200),
        ]
        for status, expected_code in steps:
            rv = client.patch(f"/api/v2/cases/{case['id']}",
                              data=json.dumps({"status": status}),
                              content_type="application/json")
            assert rv.status_code == expected_code, \
                f"Transition to {status} failed: {rv.get_json()}"
            if expected_code == 200:
                assert rv.get_json()["data"]["status"] == status


# ═══════════════════════════════════════════
# CRUD Tests
# ═══════════════════════════════════════════


class TestCaseCRUD:
    """Test basic case CRUD operations."""

    def test_create_case_minimal(self, client, fresh_cases_db):
        """Create a case with only title."""
        rv = client.post("/api/v2/cases",
                         data=json.dumps({"title": "Minimal Case"}),
                         content_type="application/json")
        assert rv.status_code == 201
        data = rv.get_json()["data"]
        assert data["title"] == "Minimal Case"
        assert data["status"] == "new"
        assert data["severity"] == "medium"
        assert data["priority"] == "medium"
        assert "id" in data
        assert "created_at" in data
        assert "sla_deadline" in data

    def test_create_case_requires_title(self, client, fresh_cases_db):
        """Creating a case without title returns 400."""
        rv = client.post("/api/v2/cases",
                         data=json.dumps({}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_create_case_with_all_fields(self, client, fresh_cases_db):
        """Create a case with all optional fields."""
        rv = client.post("/api/v2/cases",
                         data=json.dumps({
                             "title": "Full Case",
                             "severity": "critical",
                             "priority": "critical",
                             "description": "Detailed description",
                             "source_host": "db-server-01",
                             "mitre_technique": "T1110",
                             "tags": ["brute-force", "ssh"],
                             "alert_ids": [],
                         }),
                         content_type="application/json")
        assert rv.status_code == 201
        data = rv.get_json()["data"]
        assert data["title"] == "Full Case"
        assert data["severity"] == "critical"
        assert data["priority"] == "critical"
        assert data["source_host"] == "db-server-01"
        assert data["mitre_technique"] == "T1110"
        assert "brute-force" in data["tags"]
        assert "ssh" in data["tags"]

    def test_get_case_returns_full_detail(self, client, fresh_cases_db):
        """GET /cases/:id returns case with alerts, notes, SLA status."""
        case = make_case(client, title="Detail Test")
        rv = client.get(f"/api/v2/cases/{case['id']}")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["id"] == case["id"]
        assert "alerts" in data
        assert "notes" in data
        assert "alert_count" in data
        assert "sla_deadline" in data
        assert "sla_remaining_seconds" in data

    def test_get_case_404(self, client, fresh_cases_db):
        """GET nonexistent case returns 404."""
        rv = client.get("/api/v2/cases/99999")
        assert rv.status_code == 404

    def test_list_cases_returns_array(self, client, fresh_cases_db):
        """GET /cases returns array with meta."""
        rv = client.get("/api/v2/cases")
        assert rv.status_code == 200
        result = rv.get_json()
        assert "data" in result
        assert "meta" in result
        assert isinstance(result["data"], list)

    def test_list_cases_with_filters(self, client, fresh_cases_db):
        """List cases supports filtering by status, severity, etc."""
        make_case(client, title="Case A", severity="critical", source_host="host-a")
        make_case(client, title="Case B", severity="high", source_host="host-b")
        make_case(client, title="Case C", severity="medium", source_host="host-a")

        # Filter by severity
        rv = client.get("/api/v2/cases?severity=critical")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert len(data) == 1
        assert data[0]["title"] == "Case A"

        # Filter by host
        rv = client.get("/api/v2/cases?host=host-a")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert len(data) == 2

    def test_list_cases_search(self, client, fresh_cases_db):
        """Search cases by title/description."""
        make_case(client, title="Brute Force Attack", description="SSH brute force detected")
        make_case(client, title="Malware Detection", description="Suspicious process")

        rv = client.get("/api/v2/cases?search=brute")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert len(data) == 1
        assert "Brute" in data[0]["title"]

    def test_list_cases_pagination(self, client, fresh_cases_db):
        """Cases support limit/offset pagination."""
        for i in range(5):
            make_case(client, title=f"Case {i}")

        rv = client.get("/api/v2/cases?limit=2&offset=0")
        assert rv.status_code == 200
        result = rv.get_json()
        assert len(result["data"]) == 2
        assert result["meta"]["total"] >= 5

    def test_list_cases_sorting(self, client, fresh_cases_db):
        """Cases support sorting by different columns."""
        make_case(client, title="AAAA Case")
        make_case(client, title="ZZZZ Case")

        rv = client.get("/api/v2/cases?sort_by=title&sort_dir=asc")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data[0]["title"] == "AAAA Case"
        assert data[1]["title"] == "ZZZZ Case"

    def test_patch_case_updates_fields(self, client, fresh_cases_db):
        """PATCH updates case fields: priority, tags, description, title."""
        case = make_case(client, title="Update Test")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({
                              "priority": "high",
                              "tags": ["phishing"],
                              "description": "Updated description",
                          }),
                          content_type="application/json")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["priority"] == "high"
        assert "phishing" in data["tags"]
        assert data["description"] == "Updated description"

    def test_patch_case_404(self, client, fresh_cases_db):
        """PATCH on nonexistent case returns 404."""
        rv = client.patch("/api/v2/cases/99999",
                          data=json.dumps({"status": "investigating"}),
                          content_type="application/json")
        assert rv.status_code == 404


# ═══════════════════════════════════════════
# Notes Tests
# ═══════════════════════════════════════════


class TestCaseNotes:
    """Test adding and listing case notes."""

    def test_add_note_to_case(self, client, fresh_cases_db):
        """POST /cases/:id/notes adds a timestamped note."""
        case = make_case(client, title="Notes Test")
        rv = client.post(f"/api/v2/cases/{case['id']}/notes",
                         data=json.dumps({"content": "Found evidence of lateral movement"}),
                         content_type="application/json")
        assert rv.status_code == 201
        note = rv.get_json()["data"]
        assert note["content"] == "Found evidence of lateral movement"
        assert note["incident_id"] == case["id"]
        assert "created_at" in note
        assert "id" in note

    def test_add_note_requires_content(self, client, fresh_cases_db):
        """Adding note without content returns 400."""
        case = make_case(client, title="Notes Test")
        rv = client.post(f"/api/v2/cases/{case['id']}/notes",
                         data=json.dumps({"content": ""}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_add_note_to_nonexistent_case(self, client, fresh_cases_db):
        """Adding note to nonexistent case returns 404."""
        rv = client.post("/api/v2/cases/99999/notes",
                         data=json.dumps({"content": "Test note"}),
                         content_type="application/json")
        assert rv.status_code == 404

    def test_list_notes_chronological(self, client, fresh_cases_db):
        """GET /cases/:id/notes returns notes in chronological order."""
        case = make_case(client, title="Notes Test")
        client.post(f"/api/v2/cases/{case['id']}/notes",
                    data=json.dumps({"content": "First note"}),
                    content_type="application/json")
        client.post(f"/api/v2/cases/{case['id']}/notes",
                    data=json.dumps({"content": "Second note"}),
                    content_type="application/json")

        rv = client.get(f"/api/v2/cases/{case['id']}/notes")
        assert rv.status_code == 200
        notes = rv.get_json()["data"]
        assert len(notes) == 2
        assert notes[0]["content"] == "First note"
        assert notes[1]["content"] == "Second note"

    def test_notes_appear_in_case_detail(self, client, fresh_cases_db):
        """Notes are included when getting full case detail."""
        case = make_case(client, title="Notes Test")
        client.post(f"/api/v2/cases/{case['id']}/notes",
                    data=json.dumps({"content": "Investigation note"}),
                    content_type="application/json")

        rv = client.get(f"/api/v2/cases/{case['id']}")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert len(data["notes"]) == 1
        assert data["notes"][0]["content"] == "Investigation note"


# ═══════════════════════════════════════════
# Assignment Tests
# ═══════════════════════════════════════════


class TestCaseAssignment:
    """Test case assignment."""

    def test_assign_case(self, client, fresh_cases_db):
        """POST /cases/:id/assign assigns case to an analyst."""
        case = make_case(client, title="Assign Test")
        rv = client.post(f"/api/v2/cases/{case['id']}/assign",
                         data=json.dumps({"assignee_id": 42}),
                         content_type="application/json")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["assignee_id"] == 42

    def test_assign_case_requires_assignee_id(self, client, fresh_cases_db):
        """Assign requires assignee_id."""
        case = make_case(client, title="Assign Test")
        rv = client.post(f"/api/v2/cases/{case['id']}/assign",
                         data=json.dumps({}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_assign_case_nonexistent(self, client, fresh_cases_db):
        """Assign to nonexistent case returns 404."""
        rv = client.post("/api/v2/cases/99999/assign",
                         data=json.dumps({"assignee_id": 42}),
                         content_type="application/json")
        assert rv.status_code == 404

    def test_assign_via_patch(self, client, fresh_cases_db):
        """PATCH /cases/:id with assignee_id also assigns case."""
        case = make_case(client, title="Assign Via Patch")
        rv = client.patch(f"/api/v2/cases/{case['id']}",
                          data=json.dumps({"assignee_id": 7}),
                          content_type="application/json")
        assert rv.status_code == 200
        assert rv.get_json()["data"]["assignee_id"] == 7

    def test_list_cases_filtered_by_assignee(self, client, fresh_cases_db):
        """List cases filtered by assignee_id."""
        make_case(client, title="Assigned Case")
        c = make_case(client, title="Unassigned Case")

        # Assign first case
        client.post(f"/api/v2/cases/{(c['id'] - 1)}/assign",
                    data=json.dumps({"assignee_id": 99}),
                    content_type="application/json")

        rv = client.get("/api/v2/cases?assignee_id=99")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assigned = [x for x in data if x.get("assignee_id") == 99]
        assert len(assigned) >= 1


# ═══════════════════════════════════════════
# Alert Linking Tests
# ═══════════════════════════════════════════


class TestCaseAlertLinking:
    """Test linking/unlinking alerts to cases."""

    def test_add_alerts_to_case(self, client, fresh_cases_db):
        """Add alerts to a case and verify they appear."""
        case = make_case(client, title="Alert Linking Test")

        # Create alerts directly via detection and capture their IDs
        db = detection.get_db()
        cur1 = db.execute(
            """INSERT INTO alerts (timestamp, severity, category, title,
               source_host, source_ip, acknowledged)
               VALUES (datetime('now'), 'high', 'brute_force', 'Test Alert 1',
               'host-1', '10.0.0.1', 0)"""
        )
        aid1 = cur1.lastrowid
        cur2 = db.execute(
            """INSERT INTO alerts (timestamp, severity, category, title,
               source_host, source_ip, acknowledged)
               VALUES (datetime('now'), 'medium', 'suspicious_process', 'Test Alert 2',
               'host-1', '10.0.0.2', 0)"""
        )
        aid2 = cur2.lastrowid
        db.commit()

        rv = client.post(f"/api/v2/cases/{case['id']}/alerts",
                         data=json.dumps({"alert_ids": [aid1, aid2]}),
                         content_type="application/json")
        assert rv.status_code == 200, f"Add alerts failed: {rv.get_json()}"
        data = rv.get_json()["data"]
        assert data["alert_count"] >= 2
        assert len(data["alerts"]) >= 2

    def test_remove_alert_from_case(self, client, fresh_cases_db):
        """Remove an alert from a case."""
        case = make_case(client, title="Remove Alert Test")

        db = detection.get_db()
        cur = db.execute(
            """INSERT INTO alerts (timestamp, severity, category, title,
               source_host, source_ip, acknowledged)
               VALUES (datetime('now'), 'high', 'brute_force', 'Test Alert',
               'host-1', '10.0.0.1', 0)"""
        )
        aid = cur.lastrowid
        db.commit()

        client.post(f"/api/v2/cases/{case['id']}/alerts",
                    data=json.dumps({"alert_ids": [aid]}),
                    content_type="application/json")

        rv = client.delete(f"/api/v2/cases/{case['id']}/alerts/{aid}")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["alert_count"] == 0

    def test_remove_alert_not_linked(self, client, fresh_cases_db):
        """Removing unlinked alert returns 404."""
        case = make_case(client, title="Unlinked Alert Test")
        rv = client.delete(f"/api/v2/cases/{case['id']}/alerts/99999")
        assert rv.status_code == 404

    def test_case_survives_empty_alerts(self, client, fresh_cases_db):
        """Case with zero alerts still exists (VAL-CASES-048)."""
        case = make_case(client, title="Empty Alerts Case")

        # Add and then remove an alert
        db = detection.get_db()
        cur = db.execute(
            """INSERT INTO alerts (timestamp, severity, category, title,
               source_host, source_ip, acknowledged)
               VALUES (datetime('now'), 'high', 'test', 'Test Alert',
               'host-1', '10.0.0.1', 0)"""
        )
        aid = cur.lastrowid
        db.commit()

        client.post(f"/api/v2/cases/{case['id']}/alerts",
                    data=json.dumps({"alert_ids": [aid]}),
                    content_type="application/json")
        client.delete(f"/api/v2/cases/{case['id']}/alerts/{aid}")

        rv = client.get(f"/api/v2/cases/{case['id']}")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["alert_count"] == 0
        # Case still exists with status = 'new'


# ═══════════════════════════════════════════
# SLA Tracking Tests
# ═══════════════════════════════════════════


class TestSLATracking:
    """Test SLA deadline computation and breach detection."""

    def test_critical_case_has_sla_deadline(self, client, fresh_cases_db):
        """Critical severity sets SLA deadline ~1h from now."""
        case = make_case(client, title="Critical SLA", severity="critical")
        assert case.get("sla_deadline") is not None
        assert case.get("sla_remaining_seconds", 0) > 0
        # Should be roughly 1 hour (3600 seconds)
        assert 3000 < case["sla_remaining_seconds"] <= 3600

    def test_high_severity_sla(self, client, fresh_cases_db):
        """High severity sets SLA deadline ~4h from now."""
        case = make_case(client, title="High SLA", severity="high")
        assert case.get("sla_deadline") is not None
        assert 14000 < case["sla_remaining_seconds"] <= 14400

    def test_medium_severity_sla(self, client, fresh_cases_db):
        """Medium severity sets SLA deadline ~24h from now."""
        case = make_case(client, title="Medium SLA", severity="medium")
        remaining = case.get("sla_remaining_seconds", 0)
        assert 86000 < remaining <= 86400

    def test_low_severity_sla(self, client, fresh_cases_db):
        """Low severity sets SLA deadline ~72h from now."""
        case = make_case(client, title="Low SLA", severity="low")
        remaining = case.get("sla_remaining_seconds", 0)
        assert 258000 < remaining <= 259200

    def test_sla_breached_flag_in_response(self, client, fresh_cases_db):
        """SLA breach status is included in case response."""
        case = make_case(client, title="SLA Breach Test", severity="critical")
        # Initially not breached
        assert case.get("sla_breached") is False

    def test_sla_fields_in_list_response(self, client, fresh_cases_db):
        """SLA fields appear in list endpoint too."""
        make_case(client, title="SLA List Test", severity="high")
        rv = client.get("/api/v2/cases")
        assert rv.status_code == 200
        cases = rv.get_json()["data"]
        assert len(cases) >= 1
        for c in cases:
            assert "sla_deadline" in c
            assert "sla_breached" in c
            assert "sla_remaining_seconds" in c


# ═══════════════════════════════════════════
# Bulk Operations Tests
# ═══════════════════════════════════════════


class TestBulkOperations:
    """Test bulk status change and assignment."""

    def test_bulk_status_change(self, client, fresh_cases_db):
        """Bulk update multiple cases to same status."""
        c1 = make_case(client, title="Bulk 1")
        c2 = make_case(client, title="Bulk 2")
        c3 = make_case(client, title="Bulk 3")

        rv = client.patch("/api/v2/cases/bulk",
                          data=json.dumps({
                              "ids": [c1["id"], c2["id"], c3["id"]],
                              "status": "investigating",
                          }),
                          content_type="application/json")
        assert rv.status_code == 200
        result = rv.get_json()["data"]
        assert result["succeeded"] == 3
        assert result["failed"] == 0

    def test_bulk_partial_failure(self, client, fresh_cases_db):
        """Bulk operation with some invalid transitions returns 207."""
        c1 = make_case(client, title="Bulk PF 1")
        c2 = make_case(client, title="Bulk PF 2")

        # Move c2 to closed so "new" is invalid
        client.patch(f"/api/v2/cases/{c2['id']}",
                     data=json.dumps({"status": "resolved"}),
                     content_type="application/json")
        client.patch(f"/api/v2/cases/{c2['id']}",
                     data=json.dumps({"status": "closed"}),
                     content_type="application/json")

        rv = client.patch("/api/v2/cases/bulk",
                          data=json.dumps({
                              "ids": [c1["id"], c2["id"]],
                              "status": "new",
                          }),
                          content_type="application/json")
        assert rv.status_code == 207
        result = rv.get_json()["data"]
        assert result["succeeded"] == 1
        assert result["failed"] == 1

    def test_bulk_assignment(self, client, fresh_cases_db):
        """Bulk assign multiple cases."""
        c1 = make_case(client, title="Bulk Assign 1")
        c2 = make_case(client, title="Bulk Assign 2")

        rv = client.patch("/api/v2/cases/bulk",
                          data=json.dumps({
                              "ids": [c1["id"], c2["id"]],
                              "assignee_id": 42,
                          }),
                          content_type="application/json")
        assert rv.status_code == 200
        result = rv.get_json()["data"]
        assert result["succeeded"] == 2

    def test_bulk_requires_ids(self, client, fresh_cases_db):
        """Bulk update without ids returns 400."""
        rv = client.patch("/api/v2/cases/bulk",
                          data=json.dumps({"status": "investigating"}),
                          content_type="application/json")
        assert rv.status_code == 400

    def test_bulk_requires_updates(self, client, fresh_cases_db):
        """Bulk update without any update fields returns 400."""
        rv = client.patch("/api/v2/cases/bulk",
                          data=json.dumps({"ids": [1, 2]}),
                          content_type="application/json")
        assert rv.status_code == 400


# ═══════════════════════════════════════════
# Merge Tests
# ═══════════════════════════════════════════


class TestCaseMerge:
    """Test case merging."""

    def test_merge_cases(self, client, fresh_cases_db):
        """Merge source case into target case."""
        target = make_case(client, title="Target Case")
        source = make_case(client, title="Source Case")

        # Add a note to source
        client.post(f"/api/v2/cases/{source['id']}/notes",
                    data=json.dumps({"content": "Source note"}),
                    content_type="application/json")

        # Add alerts to source
        db = detection.get_db()
        cur = db.execute(
            """INSERT INTO alerts (timestamp, severity, category, title,
               source_host, source_ip, acknowledged)
               VALUES (datetime('now'), 'high', 'test', 'Alert in source',
               'host-1', '10.0.0.1', 0)"""
        )
        aid = cur.lastrowid
        db.commit()
        client.post(f"/api/v2/cases/{source['id']}/alerts",
                    data=json.dumps({"alert_ids": [aid]}),
                    content_type="application/json")

        # Merge
        rv = client.post(f"/api/v2/cases/{target['id']}/merge",
                         data=json.dumps({"source_case_id": source["id"]}),
                         content_type="application/json")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert data["id"] == target["id"]

        # Verify notes migrated
        notes_rv = client.get(f"/api/v2/cases/{target['id']}/notes")
        notes = notes_rv.get_json()["data"]
        note_contents = [n["content"] for n in notes]
        assert "Source note" in note_contents

        # Source is now resolved
        src_rv = client.get(f"/api/v2/cases/{source['id']}")
        assert src_rv.status_code == 200
        assert src_rv.get_json()["data"]["status"] == "resolved"
        assert "Merged into" in src_rv.get_json()["data"]["resolution"]

    def test_merge_nonexistent_cases(self, client, fresh_cases_db):
        """Merging nonexistent cases returns 400."""
        case = make_case(client, title="Exists")
        rv = client.post(f"/api/v2/cases/{case['id']}/merge",
                         data=json.dumps({"source_case_id": 99999}),
                         content_type="application/json")
        assert rv.status_code == 400

    def test_merge_self_rejected(self, client, fresh_cases_db):
        """Cannot merge a case into itself."""
        case = make_case(client, title="Self Merge")
        rv = client.post(f"/api/v2/cases/{case['id']}/merge",
                         data=json.dumps({"source_case_id": case["id"]}),
                         content_type="application/json")
        assert rv.status_code == 400


# ═══════════════════════════════════════════
# Metrics Tests
# ═══════════════════════════════════════════


class TestCaseMetrics:
    """Test time-to-resolution metrics."""

    def test_metrics_endpoint_returns_data(self, client, fresh_cases_db):
        """GET /cases/metrics returns metrics grouped by severity."""
        rv = client.get("/api/v2/cases/metrics")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert "period_days" in data
        assert "by_severity" in data
        for sev in ("critical", "high", "medium", "low"):
            assert sev in data["by_severity"]
            m = data["by_severity"][sev]
            assert "count" in m
            assert "avg_resolution_hours" in m
            assert "median_resolution_hours" in m
            assert "p95_resolution_hours" in m

    def test_metrics_with_data(self, client, fresh_cases_db):
        """Metrics reflect resolved cases."""
        c = make_case(client, title="Resolved for Metrics", severity="high")
        client.patch(f"/api/v2/cases/{c['id']}",
                     data=json.dumps({"status": "resolved"}),
                     content_type="application/json")

        rv = client.get("/api/v2/cases/metrics")
        assert rv.status_code == 200
        m = rv.get_json()["data"]["by_severity"]["high"]
        assert m["count"] >= 1


# ═══════════════════════════════════════════
# Priority Tests
# ═══════════════════════════════════════════


class TestCasePriority:
    """Test priority field distinct from severity."""

    def test_priority_independent_of_severity(self, client, fresh_cases_db):
        """Priority can differ from severity (VAL-CASES-070)."""
        # Low severity but high priority (e.g., CEO laptop)
        case = make_case(client, title="CEO Issue", severity="low", priority="critical")
        assert case["severity"] == "low"
        assert case["priority"] == "critical"

    def test_list_filter_by_priority(self, client, fresh_cases_db):
        """Filter cases by priority."""
        make_case(client, title="High Pri", priority="high")
        make_case(client, title="Low Pri", priority="low")

        rv = client.get("/api/v2/cases?priority=high")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert all(c["priority"] == "high" for c in data)


# ═══════════════════════════════════════════
# Tagging Tests
# ═══════════════════════════════════════════


class TestCaseTagging:
    """Test case tagging/categorization."""

    def test_case_created_with_tags(self, client, fresh_cases_db):
        """Case can be created with tags."""
        case = make_case(client, title="Tagged Case",
                         tags=["ransomware", "urgent"])
        assert "ransomware" in case["tags"]
        assert "urgent" in case["tags"]

    def test_list_filter_by_tags(self, client, fresh_cases_db):
        """Filter cases by tag."""
        make_case(client, title="Phishing Case", tags=["phishing"])
        make_case(client, title="Malware Case", tags=["malware"])

        rv = client.get("/api/v2/cases?tags=phishing")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert len(data) >= 1
        assert "phishing" in data[0]["tags"]


# ═══════════════════════════════════════════
# Audit Log Tests
# ═══════════════════════════════════════════


class TestCaseAuditLog:
    """Test that case operations are audit-logged."""

    def test_status_change_audited(self, client, fresh_cases_db):
        """Status transitions create audit log entries."""
        case = make_case(client, title="Audit Test")

        client.patch(f"/api/v2/cases/{case['id']}",
                     data=json.dumps({"status": "investigating"}),
                     content_type="application/json")

        db = detection.get_db()
        logs = db.execute(
            "SELECT * FROM case_audit_log WHERE incident_id = ? AND action = 'status_change'",
            (case["id"],),
        ).fetchall()
        assert len(logs) >= 1
        log = dict(logs[0])
        details = json.loads(log.get("details", "{}"))
        assert details["from"] == "new"
        assert details["to"] == "investigating"


# ═══════════════════════════════════════════
# Backward Compatibility Tests
# ═══════════════════════════════════════════


class TestIncidentsBackwardCompat:
    """Ensure new CaseManager tables are compatible with existing incidents system."""

    def test_existing_incidents_routes_work(self, client, fresh_cases_db):
        """Existing /incidents endpoints still work after migration."""
        # Create a case (which adds new columns to incidents table)
        make_case(client, title="Compat Test")

        # Test existing incidents listing still works
        rv = client.get("/api/v2/incidents")
        assert rv.status_code == 200
        data = rv.get_json()["data"]
        assert "incidents" in data

    def test_alert_grouper_still_works(self, client, fresh_cases_db):
        """AlertGrouper still functions after schema migration."""
        from detection import AlertGrouper, get_db
        db = get_db()
        grouper = AlertGrouper(db)

        # Create an alert
        cur = db.execute(
            """INSERT INTO alerts (timestamp, severity, category, title,
               source_host, source_ip, mitre_tactic, mitre_technique, acknowledged)
               VALUES (datetime('now'), 'high', 'brute_force', 'BackCompat Alert',
               'host-backcompat', '10.0.0.1', 'Credential Access',
               'T1110 (Brute Force)', 0)"""
        )
        aid = cur.lastrowid
        db.commit()

        alert = {
            "id": aid,
            "severity": "high",
            "category": "brute_force",
            "title": "BackCompat Alert",
            "source_host": "host-backcompat",
            "source_ip": "10.0.0.1",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "T1110 (Brute Force)",
        }
        grouper.process_alert(alert)

        incidents = grouper.get_incidents()
        assert len(incidents) >= 1
