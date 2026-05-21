"""Basic smoke tests for DeepSight modules."""

import sys
import os
import json
import tempfile

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDetectionModule:
    """Test detection.py loads and basic functions work."""

    def test_import(self):
        """Detection module imports without error."""
        import detection
        assert detection is not None

    def test_shannon_entropy(self):
        """Entropy calculation returns expected values."""
        import detection
        # Low entropy (repeated chars)
        assert detection.shannon_entropy("aaaa") < 1.0
        # High entropy (random chars)
        assert detection.shannon_entropy("a7fx9k3m2p") > 2.0

    def test_normalized_entropy(self):
        """Normalized entropy is between 0 and 1."""
        import detection
        e = detection.normalized_entropy("google")
        assert 0.0 <= e <= 1.0

    def test_dga_threshold(self):
        """Known DGA-like domain exceeds threshold."""
        import detection
        e = detection.normalized_entropy("xs8f2q9a")
        assert e > 0.5  # High entropy domain


class TestServerModule:
    """Test server.py loads and has expected attributes."""

    def test_import(self):
        """Server module imports without error."""
        import server
        assert server is not None
        assert hasattr(server, 'app')

    def test_app_exists(self):
        """Flask app is configured."""
        import server
        assert server.app is not None
        # Check it's a Flask app
        assert hasattr(server.app, 'route')

    def test_secret_configured(self):
        """Shared secret is set."""
        import server
        assert server.SHARED_SECRET
        assert len(server.SHARED_SECRET) > 0

    def test_stale_seconds(self):
        """Stale threshold is reasonable."""
        import server
        assert server.STALE_SECONDS > 0
        assert server.STALE_SECONDS <= 60


class TestAgentScript:
    """Test static/agent.py is valid and loadable."""

    def test_agent_syntax(self):
        """Agent script can be compiled without syntax errors."""
        agent_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'static', 'agent.py'
        )
        with open(agent_path) as f:
            code = f.read()
        compile(code, agent_path, 'exec')

    def test_agent_has_main(self):
        """Agent script has a main function."""
        agent_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'static', 'agent.py'
        )
        with open(agent_path) as f:
            code = f.read()
        assert 'def main():' in code
        assert 'collect_all()' in code or 'collect_cpu()' in code


class TestDocsBuild:
    """Test VitePress docs config is valid."""

    def test_config_exists(self):
        """VitePress config file exists."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'docs', '.vitepress', 'config.js'
        )
        assert os.path.exists(config_path)

    def test_config_has_base(self):
        """Config sets base path."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'docs', '.vitepress', 'config.js'
        )
        with open(config_path) as f:
            content = f.read()
        assert 'base:' in content
        assert 'outDir:' in content


class TestVersioning:
    """Test versioning infrastructure is consistent."""

    def test_version_file_exists(self):
        """VERSION file exists."""
        version_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'VERSION'
        )
        assert os.path.exists(version_path)

    def test_version_format(self):
        """VERSION follows semver."""
        version_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'VERSION'
        )
        with open(version_path) as f:
            version = f.read().strip()
        parts = version.split('.')
        assert len(parts) == 3
        for p in parts:
            assert p.isdigit(), f"Version component '{p}' is not a digit"

    def test_changelog_exists(self):
        """CHANGELOG.md exists."""
        changelog_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'CHANGELOG.md'
        )
        assert os.path.exists(changelog_path)

    def test_changelog_has_current_version(self):
        """CHANGELOG references the current version."""
        version_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'VERSION'
        )
        changelog_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'CHANGELOG.md'
        )
        with open(version_path) as f:
            version = f.read().strip()
        with open(changelog_path) as f:
            changelog = f.read()
        assert version in changelog, f"Version {version} not found in CHANGELOG.md"
