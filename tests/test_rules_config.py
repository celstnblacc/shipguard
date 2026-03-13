"""Tests for config security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.models import Severity
from shipguard.rules.config import (
    cfg_001_auto_approve,
    cfg_002_env_committed,
    cfg_003_permissive_cors,
    cfg_004_weak_tls,
    cfg_005_permissive_ssh,
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


class TestCFG004WeakTls:
    def test_detects_sslv2(self):
        content = "protocol = SSLv2"
        findings = cfg_004_weak_tls(Path("nginx.conf"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "CFG-004"
        assert findings[0].severity == Severity.HIGH

    def test_detects_sslv3(self):
        content = "ssl_protocols SSLv3;"
        findings = cfg_004_weak_tls(Path("nginx.conf"), content)
        assert len(findings) == 1

    def test_detects_tlsv1_0(self):
        content = "ssl_protocols TLSv1 TLSv1.1;"
        findings = cfg_004_weak_tls(Path("ssl.conf"), content)
        assert len(findings) >= 1

    def test_allows_tlsv1_2(self):
        content = "ssl_protocols TLSv1.2 TLSv1.3;"
        findings = cfg_004_weak_tls(Path("nginx.conf"), content)
        assert len(findings) == 0

    def test_skips_comments(self):
        content = "# ssl_protocols SSLv2;\nssl_protocols TLSv1.2 TLSv1.3;"
        findings = cfg_004_weak_tls(Path("nginx.conf"), content)
        assert len(findings) == 0

    def test_detects_in_yaml(self):
        content = "tls_version: TLSv1.0\n"
        findings = cfg_004_weak_tls(Path("config.yml"), content)
        assert len(findings) == 1


class TestCFG005PermissiveSsh:
    def test_detects_permit_root_login_yes(self):
        content = "PermitRootLogin yes\nPasswordAuthentication no\n"
        findings = cfg_005_permissive_ssh(Path("sshd_config"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "CFG-005"
        assert findings[0].severity == Severity.HIGH

    def test_detects_password_authentication_yes(self):
        content = "PermitRootLogin no\nPasswordAuthentication yes\n"
        findings = cfg_005_permissive_ssh(Path("sshd_config"), content)
        assert len(findings) == 1

    def test_detects_permit_empty_passwords(self):
        content = "PermitEmptyPasswords yes\n"
        findings = cfg_005_permissive_ssh(Path("sshd_config"), content)
        assert len(findings) == 1

    def test_passes_secure_config(self):
        content = "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n"
        findings = cfg_005_permissive_ssh(Path("sshd_config"), content)
        assert len(findings) == 0

    def test_skips_non_ssh_files(self):
        content = "PermitRootLogin yes\n"
        findings = cfg_005_permissive_ssh(Path("httpd.conf"), content)
        assert len(findings) == 0

    def test_detects_in_ssh_named_file(self):
        content = "PasswordAuthentication yes\n"
        findings = cfg_005_permissive_ssh(Path("ssh_config"), content)
        assert len(findings) == 1

    def test_skips_comment_lines(self):
        content = "# PermitRootLogin yes\nPermitRootLogin no\n"
        findings = cfg_005_permissive_ssh(Path("sshd_config"), content)
        assert len(findings) == 0
