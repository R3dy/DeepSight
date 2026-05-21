"""Tests for the syslog ingestion engine."""

import os
import sys
import json
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSyslogModule:
    """Test syslog_ingest.py loads and parses correctly."""

    def test_import(self):
        """Syslog module imports without error."""
        import syslog_ingest
        assert syslog_ingest is not None

    def test_has_required_attrs(self):
        """Module has expected top-level functions and constants."""
        import syslog_ingest
        assert hasattr(syslog_ingest, 'parse_syslog')
        assert hasattr(syslog_ingest, 'parse_rfc3164')
        assert hasattr(syslog_ingest, 'parse_rfc5424')
        assert hasattr(syslog_ingest, 'load_config')
        assert hasattr(syslog_ingest, 'get_db')
        assert hasattr(syslog_ingest, 'start_server')
        assert hasattr(syslog_ingest, 'stop_server')
        assert hasattr(syslog_ingest, 'is_running')
        assert hasattr(syslog_ingest, 'get_events')
        assert hasattr(syslog_ingest, 'get_distinct_hosts')

    def test_facility_names(self):
        """Facility name table is populated."""
        import syslog_ingest
        assert syslog_ingest.FACILITY_NAMES[0] == "kern"
        assert syslog_ingest.FACILITY_NAMES[16] == "local0"
        assert syslog_ingest.FACILITY_NAMES[23] == "local7"

    def test_severity_names(self):
        """Severity name table is populated."""
        import syslog_ingest
        assert syslog_ingest.SEVERITY_NAMES[0] == "emerg"
        assert syslog_ingest.SEVERITY_NAMES[3] == "err"
        assert syslog_ingest.SEVERITY_NAMES[7] == "debug"


class TestRFC3164Parsing:
    """Test RFC 3164 BSD syslog message parsing."""

    def test_basic_3164(self):
        """Parse a standard RFC 3164 message."""
        import syslog_ingest
        msg = '<134>Oct 11 22:14:15 myrouter su: auth failure for admin on /dev/tty1'
        result = syslog_ingest.parse_rfc3164(msg)
        assert result is not None
        assert result['host'] == 'myrouter'
        assert 'su' in result['message']
        assert 'myrouter' in result['raw']

    def test_3164_facility_severity(self):
        """PRI field correctly extracts facility and severity."""
        import syslog_ingest
        # PRI=13 → facility=1 (user), severity=5 (notice)
        msg = '<13>Mar  1 01:02:03 hostname app: hello world'
        result = syslog_ingest.parse_rfc3164(msg)
        assert result is not None
        assert result['facility_code'] == 1
        assert result['severity_code'] == 5

    def test_3164_authpriv(self):
        """Authpriv facility (10) is correctly parsed."""
        import syslog_ingest
        # PRI=86 → facility=10 (authpriv), severity=6 (info)
        msg = '<86>Dec 25 00:00:01 switch sshd[1234]: Failed password for root from 1.2.3.4 port 22'
        result = syslog_ingest.parse_rfc3164(msg)
        assert result is not None
        assert result['facility_code'] == 10
        assert result['severity_code'] == 6
        assert 'Failed password' in result['message']
        assert '1.2.3.4' in result['message']

    def test_3164_invalid_returns_none(self):
        """Invalid RFC 3164 format returns None."""
        import syslog_ingest
        assert syslog_ingest.parse_rfc3164("this is not a syslog message") is None
        assert syslog_ingest.parse_rfc3164("") is None

    def test_3164_emergency(self):
        """Emergency severity (0) is correctly parsed."""
        import syslog_ingest
        # PRI=8 → facility=1 (user), severity=0 (emerg)
        msg = '<8>Jan  1 00:00:00 panicbox kernel: PANIC: system halted'
        result = syslog_ingest.parse_rfc3164(msg)
        assert result is not None
        assert result['severity_code'] == 0
        assert result['severity'] == 'emerg'
        assert 'PANIC' in result['message']


class TestRFC5424Parsing:
    """Test RFC 5424 IETF syslog message parsing."""

    def test_basic_5424(self):
        """Parse a standard RFC 5424 message."""
        import syslog_ingest
        msg = '<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 [exampleSDID@32473 iut="3"] login failed'
        result = syslog_ingest.parse_rfc5424(msg)
        assert result is not None
        assert result['host'] == 'mymachine.example.com'
        assert 'login failed' in result['message']

    def test_5424_facility_severity(self):
        """PRI correctly extracts facility and severity from RFC 5424."""
        import syslog_ingest
        # PRI=34 → facility=4 (auth), severity=2 (crit)
        msg = '<34>1 2023-01-01T00:00:00Z host app proc msgid - critical event'
        result = syslog_ingest.parse_rfc5424(msg)
        assert result is not None
        assert result['facility_code'] == 4
        assert result['severity_code'] == 2
        assert result['facility'] == 'auth'
        assert result['severity'] == 'crit'

    def test_5424_with_nil_values(self):
        """RFC 5424 with nil (-) values."""
        import syslog_ingest
        msg = '<14>1 2023-06-15T12:00:00Z myhost - - - - just a message'
        result = syslog_ingest.parse_rfc5424(msg)
        assert result is not None
        assert result['host'] == 'myhost'
        assert result['message'] == 'just a message'

    def test_5424_invalid_returns_none(self):
        """Invalid RFC 5424 format returns None."""
        import syslog_ingest
        assert syslog_ingest.parse_rfc5424("garbage without pri") is None

    def test_5424_warning_facility(self):
        """Warning severity and daemon facility from RFC 5424."""
        import syslog_ingest
        # PRI=30 → facility=3 (daemon), severity=6 (info)
        msg = '<30>1 2024-08-01T14:00:00Z server daemon 1234 MSG01 - daemon message'
        result = syslog_ingest.parse_rfc5424(msg)
        assert result is not None
        assert result['facility'] == 'daemon'
        assert result['severity'] == 'info'


class TestAutoDetection:
    """Test auto-detection between RFC 3164 and RFC 5424."""

    def test_auto_detect_3164(self):
        """Auto-detection routes RFC 3164 correctly."""
        import syslog_ingest
        msg = '<134>Oct 11 22:14:15 myhost su: login failed'
        result = syslog_ingest.parse_syslog(msg)
        assert result is not None
        assert result['host'] == 'myhost'

    def test_auto_detect_5424(self):
        """Auto-detection routes RFC 5424 correctly."""
        import syslog_ingest
        msg = '<34>1 2003-10-11T22:14:15Z myhost su - - - login failed'
        result = syslog_ingest.parse_syslog(msg)
        assert result is not None
        assert result['host'] == 'myhost'

    def test_auto_detect_garbage(self):
        """Auto-detection returns None for garbage."""
        import syslog_ingest
        assert syslog_ingest.parse_syslog("not a syslog message at all") is None

    def test_auto_detect_empty(self):
        """Auto-detection returns None for empty string."""
        import syslog_ingest
        assert syslog_ingest.parse_syslog("") is None


class TestConfig:
    """Test configuration loading."""

    def test_example_config_exists(self):
        """Example syslog config file exists."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'syslog.example.toml'
        )
        assert os.path.exists(config_path)

    def test_example_config_parses(self):
        """Example syslog config is valid TOML."""
        import syslog_ingest
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'syslog.example.toml'
        )
        config = syslog_ingest.load_config(config_path)
        assert "server" in config
        assert "port" in config["server"]

    def test_example_config_has_alert_rules(self):
        """Example config has alert_rules section."""
        import syslog_ingest
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'syslog.example.toml'
        )
        config = syslog_ingest.load_config(config_path)
        assert "alert_rules" in config
        assert "firewall_deny_flood" in config["alert_rules"]

    def test_load_config_nonexistent(self):
        """load_config with non-existent path returns empty dict."""
        import syslog_ingest
        config = syslog_ingest.load_config("/tmp/nonexistent_syslog_test.toml")
        assert config == {}


class TestPrivateIP:
    """Test private IP detection helper."""

    def test_private_ip_ranges(self):
        """Known private IPs are detected."""
        import syslog_ingest
        assert syslog_ingest._is_private_ip("10.0.0.1") is True
        assert syslog_ingest._is_private_ip("172.16.0.1") is True
        assert syslog_ingest._is_private_ip("172.31.255.255") is True
        assert syslog_ingest._is_private_ip("192.168.1.1") is True
        assert syslog_ingest._is_private_ip("127.0.0.1") is True

    def test_public_ips(self):
        """Known public IPs are not private."""
        import syslog_ingest
        assert syslog_ingest._is_private_ip("8.8.8.8") is False
        assert syslog_ingest._is_private_ip("1.1.1.1") is False
        assert syslog_ingest._is_private_ip("203.0.113.5") is False

    def test_malformed_ip(self):
        """Malformed IP is treated as private (fail-safe)."""
        import syslog_ingest
        assert syslog_ingest._is_private_ip("not-an-ip") is True


class TestDetectionIntegration:
    """Test detection.py syslog integration."""

    def test_detection_imports_syslog(self):
        """Detection module attempts to import syslog_ingest."""
        import detection
        assert hasattr(detection, 'HAS_SYSLOG')
        # Should be True since we installed syslog_ingest.py
        assert detection.HAS_SYSLOG is True

    def test_detection_has_syslog_helpers(self):
        """Detection module has syslog query helpers."""
        import detection
        assert hasattr(detection, 'get_syslog_events')
        assert hasattr(detection, 'get_syslog_hosts')
        assert hasattr(detection, 'get_syslog_facilities')

    def test_get_syslog_events_returns_list(self):
        """get_syslog_events returns a list."""
        import detection
        events = detection.get_syslog_events(limit=5)
        assert isinstance(events, list)

    def test_get_syslog_hosts_returns_list(self):
        """get_syslog_hosts returns a list."""
        import detection
        hosts = detection.get_syslog_hosts()
        assert isinstance(hosts, list)


class TestServerIntegration:
    """Test server.py has syslog API endpoints."""

    def test_server_has_syslog_routes(self):
        """Server module has syslog API route functions."""
        import server
        assert hasattr(server, 'api_syslog_events')
        assert hasattr(server, 'api_syslog_hosts')

    def test_syslog_route_is_registered(self):
        """Server app has /api/syslog-events route."""
        import server
        # Check the route is registered by looking at URL map
        rules = [r.rule for r in server.app.url_map.iter_rules()]
        assert '/api/syslog-events' in rules
        assert '/api/syslog-hosts' in rules
