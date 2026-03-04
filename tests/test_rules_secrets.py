"""Tests for secrets rules (SEC-001, SEC-002, SEC-003)."""

from pathlib import Path

from reposec.models import Severity
from reposec.rules.secrets import (
    _skip_false_positive,
    sec_001_aws_key,
    sec_002_gcp_key,
    sec_003_github_token,
)

FIXTURES = Path(__file__).parent / "fixtures" / "secrets"


class TestSec001AwsKey:
    def test_sec_001_detects_aws_key(self):
        """Test that SEC-001 detects AWS access key pattern."""
        content = "aws_key: AKIA1234567890ABCDEF"
        path = Path("test.yml")
        findings = sec_001_aws_key(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_001_skips_env_vars(self):
        """Test that SEC-001 skips environment variable references."""
        content = "aws_key: ${AWS_ACCESS_KEY_ID}"
        path = Path("test.yml")
        findings = sec_001_aws_key(path, content)
        assert len(findings) == 0

    def test_sec_001_skips_placeholders(self):
        """Test that SEC-001 skips obvious placeholders."""
        content = "aws_key: AKIAIOSFODNN7EXAMPLE_NOT_REAL"
        path = Path("test.yml")
        findings = sec_001_aws_key(path, content)
        assert len(findings) == 0

    def test_sec_001_skips_comments(self):
        """Test that SEC-001 skips commented lines."""
        content = "# old_key: AKIAIOSFODNN7EXAMPLE"
        path = Path("test.yml")
        findings = sec_001_aws_key(path, content)
        assert len(findings) == 0

    def test_sec_001_multiple_keys(self):
        """Test that SEC-001 detects multiple keys in one file."""
        content = """
key1: AKIA1111111111111111
key2: AKIA2222222222222222
safe_ref: ${AWS_KEY}
"""
        path = Path("test.yml")
        findings = sec_001_aws_key(path, content)
        assert len(findings) == 2


class TestSec002GcpKey:
    def test_sec_002_detects_gcp_key(self):
        """Test that SEC-002 detects GCP API key pattern."""
        content = "gcp_key: AIzaZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        path = Path("test.yml")
        findings = sec_002_gcp_key(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-002"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_002_skips_env_vars(self):
        """Test that SEC-002 skips environment variable references."""
        content = "gcp_key: ${{ secrets.GCP_KEY }}"
        path = Path("test.yml")
        findings = sec_002_gcp_key(path, content)
        assert len(findings) == 0

    def test_sec_002_skips_template_syntax(self):
        """Test that SEC-002 skips GitHub Actions template syntax."""
        content = "gcp_key: ${{ env.GCP_API_KEY }}"
        path = Path("test.json")
        findings = sec_002_gcp_key(path, content)
        assert len(findings) == 0

    def test_sec_002_skips_angle_bracket_template(self):
        """Test that SEC-002 skips angle-bracket templates."""
        content = "gcp_key: <API_KEY_PLACEHOLDER>"
        path = Path("test.yml")
        findings = sec_002_gcp_key(path, content)
        assert len(findings) == 0


class TestSec003GitHubToken:
    def test_sec_003_detects_ghp_token(self):
        """Test that SEC-003 detects ghp_ token pattern."""
        content = "github_token: ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        path = Path("test.yml")
        findings = sec_003_github_token(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-003"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_003_detects_gho_token(self):
        """Test that SEC-003 detects gho_ (OAuth) token pattern."""
        content = "oauth_token: gho_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        path = Path("test.yml")
        findings = sec_003_github_token(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-003"

    def test_sec_003_skips_env_vars(self):
        """Test that SEC-003 skips environment variable references."""
        content = "github_token: $GITHUB_TOKEN"
        path = Path("test.yml")
        findings = sec_003_github_token(path, content)
        assert len(findings) == 0

    def test_sec_003_multiple_tokens(self):
        """Test that SEC-003 detects multiple tokens in one file."""
        content = """
token1: ghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
token2: gho_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
safe: $GITHUB_TOKEN
"""
        path = Path("test.yml")
        findings = sec_003_github_token(path, content)
        assert len(findings) == 2


class TestSecretsFixtures:
    def test_vulnerable_fixtures(self):
        """Test that vulnerable fixtures are detected."""
        vulnerable_file = FIXTURES / "vulnerable.yml"
        if vulnerable_file.exists():
            content = vulnerable_file.read_text()
            aws_findings = sec_001_aws_key(vulnerable_file, content)
            gcp_findings = sec_002_gcp_key(vulnerable_file, content)
            github_findings = sec_003_github_token(vulnerable_file, content)
            assert len(aws_findings) > 0
            assert len(gcp_findings) > 0
            assert len(github_findings) > 0

    def test_safe_fixtures(self):
        """Test that safe fixtures don't trigger false positives."""
        safe_file = FIXTURES / "safe.yml"
        if safe_file.exists():
            content = safe_file.read_text()
            aws_findings = sec_001_aws_key(safe_file, content)
            gcp_findings = sec_002_gcp_key(safe_file, content)
            github_findings = sec_003_github_token(safe_file, content)
            assert len(aws_findings) == 0
            assert len(gcp_findings) == 0
            assert len(github_findings) == 0


def test_skip_false_positive_angle_brackets():
    assert _skip_false_positive("token=<SECRET>") is True
