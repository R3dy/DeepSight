"""Tests for the notification engine."""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestNotifierModule:
    """Test notifier.py loads and handles missing deps gracefully."""

    def test_import(self):
        """Notifier module imports without error."""
        import notifier
        assert notifier is not None

    def test_has_apprise_flag(self):
        """HAS_APPRISE flag is set."""
        import notifier
        assert hasattr(notifier, 'HAS_APPRISE')

    def test_dispatch_no_config(self):
        """dispatch() with no config returns empty list."""
        import notifier
        if not notifier.HAS_APPRISE:
            pytest.skip("apprise not installed")
        results = notifier.dispatch({"severity": "high", "title": "test"}, {})
        assert results == []

    def test_load_config_no_file(self):
        """load_config() with non-existent path returns empty dict."""
        import notifier
        config = notifier.load_config("/tmp/nonexistent_deepsight_notifier_test.toml")
        assert config == {}

    def test_dispatch_alert_noop(self):
        """dispatch_alert() doesn't crash on None or empty alert."""
        import notifier
        notifier.dispatch_alert(None)
        notifier.dispatch_alert({})

    def test_quiet_hours_parse(self):
        """Quiet hours config is parsed."""
        import notifier
        config = {
            "quiet_hours": {"start": "22:00", "end": "07:00"},
            "routing": {"critical": []},
        }
        # Just test that it doesn't crash
        import notifier
        results = notifier.dispatch(
            {"severity": "critical", "title": "test"}, config
        )
        # Should be suppressed during quiet hours or if no channels configured
        assert isinstance(results, list)


class TestNotifierConfig:
    """Test example config is valid TOML."""

    def test_example_config_exists(self):
        """Example config file exists."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'notifications.example.toml'
        )
        assert os.path.exists(config_path)

    def test_example_config_parses(self):
        """Example config is valid TOML."""
        import notifier
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'notifications.example.toml'
        )
        config = notifier.load_config(config_path)
        assert "discord" in config
        assert "routing" in config
        assert "critical" in config["routing"]

    def test_routing_has_severities(self):
        """Example config has routing for all severities."""
        import notifier
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config', 'notifications.example.toml'
        )
        config = notifier.load_config(config_path)
        routing = config.get("routing", {})
        for sev in ["critical", "high", "medium", "low"]:
            assert sev in routing, f"Missing routing for severity: {sev}"
