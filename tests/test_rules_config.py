"""Tests for config security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.config import (
    cfg_001_auto_approve,
    cfg_002_env_committed,
    cfg_003_permissive_cors,
)


class TestCFG001AutoApprove:
    def test_detects_auto_approve(self):
        content = '{"autoApprove": ["read", "write"]}'
        findings = cfg_001_auto_approve(Path("settings.json"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_non_settings(self):
        content = '{"autoApprove": ["read"]}'
        findings = cfg_001_auto_approve(Path("package.json"), content)
        assert len(findings) == 0


class TestCFG002EnvCommitted:
    def test_detects_env_with_secrets(self):
        content = "API_KEY=sk-live-realkey123\nSECRET=myvalue"
        findings = cfg_002_env_committed(Path(".env"), content)
        assert len(findings) == 1

    def test_ignores_env_example(self):
        content = "API_KEY=your-key-here"
        findings = cfg_002_env_committed(Path(".env.example"), content)
        assert len(findings) == 0

    def test_ignores_non_env(self):
        content = "API_KEY=value"
        findings = cfg_002_env_committed(Path("config.txt"), content)
        assert len(findings) == 0


class TestCFG003PermissiveCors:
    def test_detects_wildcard_cors(self):
        content = "Access-Control-Allow-Origin: *"
        findings = cfg_003_permissive_cors(Path("config.json"), content)
        assert len(findings) == 1

    def test_detects_cors_no_options(self):
        content = "app.use(cors())"
        findings = cfg_003_permissive_cors(Path("app.js"), content)
        assert len(findings) == 1

    def test_ignores_specific_origin(self):
        content = "origin: 'https://example.com'"
        findings = cfg_003_permissive_cors(Path("config.js"), content)
        assert len(findings) == 0
