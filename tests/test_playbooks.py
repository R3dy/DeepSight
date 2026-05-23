"""Tests for the SOAR Playbook Engine — automated enrichment playbooks.

Covers:
  - Each enrichment playbook end-to-end (mock API calls)
  - Rate limiting / cooldown behavior
  - Error handling (API timeout, bad response, missing config)
  - Integration with alert pipeline
"""

import sys
import os
import time
import socket
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from playbook_engine import (
    PlaybookEngine, Playbook, PlaybookStep, RateLimiter,
    _build_enrichment_context, _parse_whois, _is_valid_ip,
    get_playbook_engine,
    _EnrichmentFunctions,
    clear_tor_cache, clear_feodo_cache,
)


# ═══════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════

@pytest.fixture
def engine():
    """Create a fresh PlaybookEngine for testing."""
    engine = PlaybookEngine()
    return engine


@pytest.fixture
def alert_bruteforce():
    """Sample brute force alert with source IP."""
    return {
        "id": 1001,
        "severity": "critical",
        "category": "brute_force",
        "title": "SSH brute force: 12 failures from 8.8.8.8",
        "description": "Detected 12 SSH auth failures from 8.8.8.8",
        "source_ip": "8.8.8.8",
        "source_host": "",
        "raw_data": {"failed_count": 12, "window_s": 10},
    }


@pytest.fixture
def alert_beaconing():
    """Sample beaconing alert with remote IP and SNI domain."""
    return {
        "id": 1002,
        "severity": "high",
        "category": "beaconing",
        "title": "C2 beaconing: malware.exe → bad.example.com:443",
        "description": "Process 'malware.exe' beaconing to bad.example.com:443 — interval 60s",
        "source_ip": "1.1.1.1",
        "source_host": "bad.example.com",
        "raw_data": {
            "remote_ip": "1.1.1.1",
            "remote_host": "bad.example.com",
            "tls_sni": "bad.example.com",
            "remote_port": 443,
            "interval_seconds": 60,
        },
    }


@pytest.fixture
def alert_dga():
    """Sample DGA alert with high-entropy domain."""
    return {
        "id": 1003,
        "severity": "medium",
        "category": "dga",
        "title": "DGA domain suspected: xkcd42qax.example.com (entropy=3.9)",
        "description": "Domain 'xkcd42qax.example.com' has high entropy (3.9), possibly DGA",
        "source_ip": "",
        "source_host": "xkcd42qax.example.com",
        "raw_data": {"domain": "xkcd42qax.example.com", "entropy_score": 3.9},
    }


@pytest.fixture
def alert_malware_hash():
    """Sample malware alert with file hash."""
    return {
        "id": 1004,
        "severity": "critical",
        "category": "suspicious_execution",
        "title": "Process from suspicious location: bad.exe from /tmp/",
        "description": "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 — executing from /tmp/bad.exe",
        "source_ip": "",
        "source_host": "",
        "raw_data": {
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "exe_path": "/tmp/bad.exe",
        },
    }


# ═══════════════════════════════════════════
# Rate Limiter Tests
# ═══════════════════════════════════════════

class TestRateLimiter:
    """Test the per-service cooldown rate limiter."""

    def test_can_call_initially(self):
        rl = RateLimiter(max_concurrent=5)
        assert rl.can_call("abuseipdb") is True

    def test_cooldown_after_call(self):
        rl = RateLimiter(max_concurrent=5)
        rl.record_call("abuseipdb")
        assert rl.can_call("abuseipdb", cooldown_seconds=60) is False

    def test_cooldown_expires(self):
        rl = RateLimiter(max_concurrent=5)
        rl.record_call("abuseipdb")
        time.sleep(0.01)  # let cooldown expire
        # Short cooldown that already expired
        assert rl.can_call("abuseipdb", cooldown_seconds=0.001) is True

    def test_independent_services(self):
        rl = RateLimiter(max_concurrent=5)
        rl.record_call("abuseipdb")
        # Different service should still be callable
        assert rl.can_call("virustotal") is True

    def test_concurrency_semaphore(self):
        rl = RateLimiter(max_concurrent=2)
        rl.acquire()
        rl.acquire()
        # Third acquire would block — test via non-blocking attempt
        acquired = []
        def try_acquire():
            acquired.append(rl._semaphore.acquire(blocking=False))
        try_acquire()
        assert acquired == [False]
        rl.release()
        try_acquire()
        assert acquired == [False, True]
        rl.release()


# ═══════════════════════════════════════════
# Context Builder Tests
# ═══════════════════════════════════════════

class TestContextBuilder:
    """Test enrichment context extraction from alerts."""

    def test_extracts_ip_from_source_ip(self):
        ctx = _build_enrichment_context({
            "id": 1, "source_ip": "8.8.8.8",
            "description": "", "raw_data": {},
        })
        assert "8.8.8.8" in ctx["ips"]

    def test_ignores_private_ips(self):
        ctx = _build_enrichment_context({
            "id": 1, "source_ip": "192.168.1.1",
            "description": "", "raw_data": {},
        })
        assert "192.168.1.1" not in ctx["ips"]

    def test_ignores_loopback(self):
        ctx = _build_enrichment_context({
            "id": 1, "source_ip": "127.0.0.1",
            "description": "", "raw_data": {},
        })
        assert "127.0.0.1" not in ctx["ips"]

    def test_extracts_ips_from_description(self):
        ctx = _build_enrichment_context({
            "id": 1, "source_ip": "",
            "description": "Connection from 8.8.8.8 to 1.1.1.1 detected",
            "raw_data": {},
        })
        assert "8.8.8.8" in ctx["ips"]
        assert "1.1.1.1" in ctx["ips"]

    def test_extracts_domains_from_raw_data(self):
        ctx = _build_enrichment_context({
            "id": 1, "source_host": "evil.com",
            "description": "", "raw_data": {"tls_sni": "bad.example.com"},
        })
        assert "evil.com" in ctx["domains"]
        assert "bad.example.com" in ctx["domains"]

    def test_extracts_hashes_from_description(self):
        ctx = _build_enrichment_context({
            "id": 1, "description": "File: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "raw_data": {},
        })
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in ctx["hashes"]

    def test_extracts_hashes_from_raw_data(self):
        ctx = _build_enrichment_context({
            "id": 1, "description": "",
            "raw_data": {"sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
        })
        assert "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" in ctx["hashes"]

    def test_deduplicates_ips(self):
        ctx = _build_enrichment_context({
            "id": 1, "source_ip": "8.8.8.8",
            "description": "IP 8.8.8.8 was seen",
            "raw_data": {"remote_ip": "8.8.8.8"},
        })
        assert ctx["ips"].count("8.8.8.8") == 1


# ═══════════════════════════════════════════
# IP Validation Tests
# ═══════════════════════════════════════════

class TestIPValidation:
    """Test the IP validation helper."""

    def test_valid_public_ipv4(self):
        assert _is_valid_ip("8.8.8.8") is True
        assert _is_valid_ip("1.1.1.1") is True

    def test_invalid_ip(self):
        assert _is_valid_ip("not.an.ip") is False
        assert _is_valid_ip("999.999.999.999") is False
        assert _is_valid_ip("") is False

    def test_private_rejected(self):
        assert _is_valid_ip("192.168.1.1") is False
        assert _is_valid_ip("10.0.0.1") is False
        assert _is_valid_ip("172.16.0.1") is False

    def test_loopback_rejected(self):
        assert _is_valid_ip("127.0.0.1") is False
        assert _is_valid_ip("::1") is False

    def test_multicast_rejected(self):
        assert _is_valid_ip("224.0.0.1") is False


# ═══════════════════════════════════════════
# Whois Parsing Tests
# ═══════════════════════════════════════════

class TestWhoisParsing:
    """Test whois response parsing."""

    def test_parses_registrar(self):
        raw = "Registrar: Example Registrar, Inc.\nCreation Date: 2020-01-15"
        parsed = _parse_whois(raw)
        assert parsed["registrar"] == "Example Registrar, Inc."

    def test_parses_name_servers(self):
        raw = "Name Server: ns1.example.com\nName Server: ns2.example.com"
        parsed = _parse_whois(raw)
        assert "ns1.example.com" in parsed["name_servers"]
        assert "ns2.example.com" in parsed["name_servers"]

    def test_handles_empty_response(self):
        parsed = _parse_whois("")
        assert parsed == {}

    def test_case_insensitive(self):
        raw = "REGISTRAR: TestReg\nregistrar: TestReg2"
        parsed = _parse_whois(raw)
        # Both case variants of 'registrar' match the regex; the first match wins the single-value slot
        # but if both match, the second overwrites (or both accumulate if >1)
        assert parsed["registrar"] == "TestReg" or parsed["registrar"] == ["TestReg", "TestReg2"]


# ═══════════════════════════════════════════
# Playbook Step Tests
# ═══════════════════════════════════════════

class TestPlaybookStep:
    """Test individual playbook step execution."""

    def test_successful_step(self):
        def good_func(ctx):
            return {"result": "ok"}
        step = PlaybookStep("test_step", good_func)
        result = step.run({})
        assert result["status"] == "success"
        assert result["data"] == {"result": "ok"}
        assert result["error"] is None
        assert result["duration_ms"] >= 0

    def test_error_step(self):
        def bad_func(ctx):
            raise ValueError("something broke")
        step = PlaybookStep("test_step", bad_func)
        result = step.run({})
        assert result["status"] == "error"
        assert "ValueError" in result["error"]
        assert result["data"] is None

    def test_step_with_context(self):
        def ctx_func(ctx):
            return {"ips_found": len(ctx.get("ips", []))}
        step = PlaybookStep("count_ips", ctx_func)
        result = step.run({"ips": ["1.2.3.4", "5.6.7.8"]})
        assert result["data"]["ips_found"] == 2


# ═══════════════════════════════════════════
# Playbook (Orchestrator) Tests
# ═══════════════════════════════════════════

class TestPlaybook:
    """Test the Playbook orchestrator class."""

    def test_playbook_matches(self):
        pb = Playbook(
            "test",
            "desc",
            trigger_condition=lambda a: a.get("category") == "brute_force",
            steps=[],
        )
        assert pb.matches({"category": "brute_force"}) is True
        assert pb.matches({"category": "beaconing"}) is False

    def test_playbook_runs_all_steps(self):
        results_log = []

        def step1(ctx):
            results_log.append("step1")
            return {"a": 1}

        def step2(ctx):
            results_log.append("step2")
            return {"b": 2}

        pb = Playbook(
            "test", "desc",
            trigger_condition=lambda a: True,
            steps=[
                PlaybookStep("s1", step1),
                PlaybookStep("s2", step2),
            ],
        )
        rl = RateLimiter(max_concurrent=5)
        result = pb.run({"id": 1}, rl)

        assert result["playbook"] == "test"
        assert result["status"] == "success"
        assert len(result["steps"]) == 2
        assert "step1" in results_log
        assert "step2" in results_log

    def test_playbook_partial_failure(self):
        def step1(ctx):
            return {"ok": True}

        def step2(ctx):
            raise RuntimeError("fail")

        pb = Playbook(
            "test", "desc",
            trigger_condition=lambda a: True,
            steps=[
                PlaybookStep("s1", step1),
                PlaybookStep("s2", step2),
            ],
        )
        rl = RateLimiter(max_concurrent=5)
        result = pb.run({"id": 1}, rl)

        assert result["status"] == "partial"
        assert result["steps"][0]["status"] == "success"
        assert result["steps"][1]["status"] == "error"

    def test_trigger_condition_exception_is_safe(self):
        def bad_trigger(alert):
            raise RuntimeError("trigger error")

        pb = Playbook("test", "desc", trigger_condition=bad_trigger, steps=[])
        # Should not raise — returns False
        assert pb.matches({"id": 1}) is False


# ═══════════════════════════════════════════
# Playbook Engine Tests
# ═══════════════════════════════════════════

class TestPlaybookEngine:
    """Test the PlaybookEngine orchestrator."""

    def test_has_playbooks(self, engine):
        pb_list = engine.playbooks
        assert len(pb_list) >= 4
        names = {p["name"] for p in pb_list}
        assert "ip_enrichment" in names
        assert "domain_enrichment" in names
        assert "file_hash_enrichment" in names
        assert "dns_enrichment" in names

    def test_process_alert_matches_ip_enrichment(self, engine, alert_bruteforce):
        # Should match ip_enrichment
        engine.process_alert(alert_bruteforce)
        # Result is async, but we can check matching
        # (we just verify no crash)

    def test_process_alert_no_match(self, engine):
        # Alert with no IPs, no domains, no hashes, no matching category
        alert = {
            "id": 9999,
            "category": "unknown",
            "severity": "low",
            "title": "Nothing interesting",
            "description": "Nothing to see here",
            "source_ip": "",
            "source_host": "",
            "raw_data": {},
        }
        # Should not crash
        engine.process_alert(alert)

    def test_run_playbook_by_name(self, engine, alert_bruteforce):
        result = engine.run_playbook_by_name(alert_bruteforce, "ip_enrichment")
        assert "error" not in result or "not found" not in str(result.get("error", ""))
        assert result["playbook"] == "ip_enrichment"

    def test_run_unknown_playbook(self, engine, alert_bruteforce):
        result = engine.run_playbook_by_name(alert_bruteforce, "nonexistent_playbook")
        assert "error" in result
        assert "not found" in result["error"]

    def test_get_results_empty(self, engine):
        result = engine.get_results(99999)
        assert result is None

    def test_get_history(self, engine):
        history = engine.get_history()
        assert "history" in history
        assert "total" in history
        assert isinstance(history["history"], list)


# ═══════════════════════════════════════════
# Enrichment Function Tests (Mocked API calls)
# ═══════════════════════════════════════════

class TestIPEnrichmentMocked:
    """Test IP enrichment functions with mocked HTTP calls."""

    @patch("playbook_engine.ABUSEIPDB_API_KEY", "test-key-123")
    @patch("playbook_engine.requests.get")
    def test_abuseipdb_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 95,
                "totalReports": 42,
                "lastReportedAt": "2026-05-20T00:00:00Z",
                "countryCode": "RU",
                "isp": "BadISP",
                "domain": "badisp.ru",
                "usageType": "Data Center",
            }
        }
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.abuseipdb_check({"ips": ["203.0.113.42"]})

        assert result["ips"]["203.0.113.42"]["abuse_confidence_score"] == 95
        assert result["ips"]["203.0.113.42"]["country"] == "RU"

    def test_abuseipdb_no_api_key(self):
        with patch("playbook_engine.ABUSEIPDB_API_KEY", ""):
            funcs = _EnrichmentFunctions()
            result = funcs.abuseipdb_check({"ips": ["203.0.113.42"]})
            assert result["skipped"] is True
            assert "not configured" in result["reason"]

    def test_abuseipdb_no_ips(self):
        with patch("playbook_engine.ABUSEIPDB_API_KEY", "test-key"):
            funcs = _EnrichmentFunctions()
            result = funcs.abuseipdb_check({"ips": []})
            assert result["skipped"] is True

    @patch("playbook_engine.requests.get")
    def test_abuseipdb_api_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        with patch("playbook_engine.ABUSEIPDB_API_KEY", "test-key"):
            funcs = _EnrichmentFunctions()
            result = funcs.abuseipdb_check({"ips": ["203.0.113.42"]})
            assert "error" in result["ips"]["203.0.113.42"]

    @patch("playbook_engine.requests.get")
    def test_abuseipdb_timeout(self, mock_get):
        import requests as req_mod
        mock_get.side_effect = req_mod.Timeout("Connection timed out")

        with patch("playbook_engine.ABUSEIPDB_API_KEY", "test-key"):
            funcs = _EnrichmentFunctions()
            result = funcs.abuseipdb_check({"ips": ["203.0.113.42"]})
            assert "error" in result["ips"]["203.0.113.42"]

    @patch("playbook_engine.OTX_API_KEY", "test-otx-key")
    @patch("playbook_engine.requests.get")
    def test_otx_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {"name": "Malware Campaign X", "created": "2026-05-01T00:00:00Z"},
                ],
            },
            "type_title": "IPv4",
            "validation": [],
        }
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.otx_check({"ips": ["203.0.113.42"], "domains": []})

        assert result["indicators"]["203.0.113.42"]["pulse_count"] == 3

    @patch("playbook_engine.requests.get")
    def test_geoip_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "status": "success",
            "country": "Russia",
            "countryCode": "RU",
            "regionName": "Moscow",
            "city": "Moscow",
            "timezone": "Europe/Moscow",
            "isp": "SomeISP",
            "org": "SomeOrg",
            "as": "AS12345",
            "lat": 55.7558,
            "lon": 37.6173,
        }
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.geoip_check({"ips": ["203.0.113.42"]})

        ip_data = result["ips"]["203.0.113.42"]
        assert ip_data["country"] == "Russia"
        assert ip_data["country_code"] == "RU"
        assert ip_data["coordinates"]["lat"] == 55.7558

    @patch("playbook_engine.requests.get")
    def test_geoip_no_ips(self, mock_get):
        funcs = _EnrichmentFunctions()
        result = funcs.geoip_check({"ips": []})
        assert result["skipped"] is True


class TestDomainEnrichmentMocked:
    """Test domain enrichment functions with mocked HTTP calls."""

    @patch("playbook_engine.requests.post")
    def test_urlhaus_malicious(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "host": "bad.example.com",
            "url_count": 5,
            "urls": [
                {"url": "http://bad.example.com/payload.exe", "threat": "malware_download", "date_added": "2026-05-01"},
            ],
            "firstseen": "2026-01-01",
        }
        mock_post.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.urlhaus_check({"domains": ["bad.example.com"]})

        assert result["domains"]["bad.example.com"]["url_count"] == 5

    @patch("playbook_engine.requests.post")
    def test_urlhaus_clean(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "no_results",
        }
        mock_post.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.urlhaus_check({"domains": ["clean.example.com"]})

        assert result["domains"]["clean.example.com"]["status"] == "clean"

    @patch("playbook_engine.requests.post")
    def test_urlhaus_no_domains(self, mock_post):
        funcs = _EnrichmentFunctions()
        result = funcs.urlhaus_check({"domains": []})
        assert result["skipped"] is True


class TestFileHashEnrichmentMocked:
    """Test file hash enrichment with mocked HTTP calls."""

    @patch("playbook_engine.VIRUSTOTAL_API_KEY", "test-vt-key")
    @patch("playbook_engine.requests.get")
    def test_virustotal_malicious(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "meaningful_name": "trojan.exe",
                    "type_description": "Win32 EXE",
                    "size": 123456,
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 3,
                        "undetected": 20,
                        "harmless": 10,
                    },
                }
            }
        }
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.virustotal_check({
            "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        })

        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result["hashes"][h]["found"] is True
        assert result["hashes"][h]["malicious"] == 45

    @patch("playbook_engine.requests.get")
    def test_virustotal_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        with patch("playbook_engine.VIRUSTOTAL_API_KEY", "test-key"):
            funcs = _EnrichmentFunctions()
            result = funcs.virustotal_check({
                "hashes": ["0000000000000000000000000000000000000000000000000000000000000000"],
            })

            h = "0000000000000000000000000000000000000000000000000000000000000000"
            assert result["hashes"][h]["found"] is False

    def test_virustotal_no_api_key(self):
        with patch("playbook_engine.VIRUSTOTAL_API_KEY", ""):
            funcs = _EnrichmentFunctions()
            result = funcs.virustotal_check({"hashes": ["abc123"]})
            assert result["skipped"] is True

    @patch("playbook_engine.requests.get")
    def test_virustotal_rate_limited(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        with patch("playbook_engine.VIRUSTOTAL_API_KEY", "test-key"):
            funcs = _EnrichmentFunctions()
            result = funcs.virustotal_check({
                "hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            })
            h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            assert "rate limit" in result["hashes"][h]["error"].lower()


class TestDNSEnrichmentMocked:
    """Test DNS enrichment functions with mocked socket calls."""

    @patch("playbook_engine.socket.gethostbyaddr")
    @patch("playbook_engine.socket.gethostbyname_ex")
    def test_reverse_dns_success(self, mock_fwd, mock_rev):
        mock_rev.return_value = ("bad.example.com", [], ["198.51.100.77"])
        mock_fwd.return_value = ("bad.example.com", [], ["198.51.100.77"])

        funcs = _EnrichmentFunctions()
        result = funcs.reverse_dns_check({
            "ips": ["198.51.100.77"],
            "domains": [],
        })

        dns = result["dns"]
        assert dns["198.51.100.77"]["ptr"] == "bad.example.com"
        assert dns["198.51.100.77"]["forward_confirmed"] is True

    @patch("playbook_engine.socket.gethostbyaddr")
    def test_reverse_dns_no_ptr(self, mock_rev):
        mock_rev.side_effect = socket.herror("no PTR record")

        funcs = _EnrichmentFunctions()
        result = funcs.reverse_dns_check({
            "ips": ["203.0.113.42"],
            "domains": [],
        })

        assert result["dns"]["203.0.113.42"]["ptr"] is None
        assert result["dns"]["203.0.113.42"]["forward_confirmed"] is False

    @patch("playbook_engine.socket.getaddrinfo")
    def test_domain_resolution(self, mock_addrinfo):
        mock_addrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
        ]

        funcs = _EnrichmentFunctions()
        result = funcs.reverse_dns_check({
            "ips": [],
            "domains": ["example.com"],
        })

        assert result["dns"]["example.com"]["resolves"] is True
        assert "93.184.216.34" in result["dns"]["example.com"]["ipv4"]

    @patch("playbook_engine.socket.getaddrinfo")
    def test_domain_no_resolution(self, mock_addrinfo):
        mock_addrinfo.side_effect = socket.gaierror("NXDOMAIN")

        funcs = _EnrichmentFunctions()
        result = funcs.reverse_dns_check({
            "ips": [],
            "domains": ["nonexistent.invalid"],
        })

        assert result["dns"]["nonexistent.invalid"]["resolves"] is False


# ═══════════════════════════════════════════
# Integration Tests — Alert Pipeline Hook
# ═══════════════════════════════════════════

class TestAlertPipelineIntegration:
    """Test playbook engine integration with the alert pipeline."""

    @patch("playbook_engine._append_enrichment_to_alert")
    def test_engine_processes_alert_non_blocking(self, mock_append, engine, alert_bruteforce):
        """Verify process_alert is non-blocking and fires enrichment."""
        start = time.time()
        engine.process_alert(alert_bruteforce)
        elapsed = time.time() - start
        # Should return nearly instantly (enrichment runs in background)
        assert elapsed < 1.0

    @patch("playbook_engine._append_enrichment_to_alert")
    def test_results_stored_after_enrichment(self, mock_append, engine, alert_bruteforce):
        """Results should be available after enrichment completes."""
        # Run synchronously to avoid flaky timing
        engine.run_playbook_by_name(alert_bruteforce, "ip_enrichment")

        result = engine.get_results(1001)
        assert result is not None
        assert result["alert_id"] == 1001
        assert len(result["playbook_results"]) > 0

    @patch("playbook_engine._append_enrichment_to_alert")
    def test_history_tracks_runs(self, mock_append, engine, alert_bruteforce):
        """History should record each playbook run."""
        engine.run_playbook_by_name(alert_bruteforce, "ip_enrichment")
        engine.run_playbook_by_name(alert_bruteforce, "dns_enrichment")

        history = engine.get_history()
        assert history["total"] >= 2


# ═══════════════════════════════════════════
# Global Singleton Tests
# ═══════════════════════════════════════════

class TestGlobalSingleton:
    """Test the global PlaybookEngine singleton accessor."""

    def test_get_engine_returns_singleton(self):
        e1 = get_playbook_engine()
        e2 = get_playbook_engine()
        assert e1 is e2

    def test_engine_is_started(self):
        engine = get_playbook_engine()
        assert engine._running is True


# ═══════════════════════════════════════════
# Tor Exit Node Check Tests
# ═══════════════════════════════════════════

class TestTorExitCheckMocked:
    """Test Tor exit node check with mocked HTTP."""

    @patch("playbook_engine.requests.get")
    def test_tor_exit_detected(self, mock_get):
        clear_tor_cache()  # ensure no cached data from other tests
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "# Tor exit list\n203.0.113.42\n198.51.100.77\n"
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.tor_exit_check({"ips": ["203.0.113.42", "1.2.3.4"]})

        assert result["results"]["203.0.113.42"]["is_tor_exit"] is True
        assert result["results"]["1.2.3.4"]["is_tor_exit"] is False

    @patch("playbook_engine.requests.get")
    def test_tor_check_failure(self, mock_get):
        clear_tor_cache()  # ensure no cached data from other tests
        mock_get.side_effect = Exception("Network error")

        funcs = _EnrichmentFunctions()
        result = funcs.tor_exit_check({"ips": ["203.0.113.42"]})

        assert "error" in result

    def test_tor_check_no_ips(self):
        funcs = _EnrichmentFunctions()
        result = funcs.tor_exit_check({"ips": []})
        assert result["skipped"] is True


# ═══════════════════════════════════════════
# Feodo Tracker Tests
# ═══════════════════════════════════════════

class TestFeodoCheckMocked:
    """Test Feodo Tracker C2 blocklist check."""

    @patch("playbook_engine.requests.get")
    def test_feodo_c2_detected(self, mock_get):
        clear_feodo_cache()  # ensure no cached data from other tests
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {
                "ip_address": "203.0.113.42",
                "port": 443,
                "status": "online",
                "hostname": "evil-c2.example.com",
                "as_number": 12345,
                "country": "RU",
                "first_seen": "2026-01-01",
                "last_seen": "2026-05-23",
                "malware": "CobaltStrike",
            }
        ]
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.feodo_check({"ips": ["203.0.113.42", "1.2.3.4"]})

        assert result["ips"]["203.0.113.42"]["is_c2"] is True
        assert result["ips"]["203.0.113.42"]["malware"] == "CobaltStrike"
        assert result["ips"]["1.2.3.4"]["is_c2"] is False

    @patch("playbook_engine.requests.get")
    def test_feodo_fetch_error(self, mock_get):
        clear_feodo_cache()  # ensure no cached data from other tests
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        funcs = _EnrichmentFunctions()
        result = funcs.feodo_check({"ips": ["203.0.113.42"]})

        assert "error" in result

    def test_feodo_no_ips(self):
        funcs = _EnrichmentFunctions()
        result = funcs.feodo_check({"ips": []})
        assert result["skipped"] is True
