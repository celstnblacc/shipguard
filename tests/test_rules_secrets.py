"""Tests for secrets rules (SEC-001 through SEC-010)."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.secrets import (
    _skip_false_positive,
    sec_001_aws_key,
    sec_002_gcp_key,
    sec_003_github_token,
    sec_004_stripe_key,
    sec_005_openai_key,
    sec_006_anthropic_key,
    sec_007_slack_token,
    sec_008_pem_private_key,
    sec_009_npm_token,
    sec_010_huggingface_token,
    sec_011_azure_storage_key,
    sec_012_twilio_token,
    sec_013_sendgrid_key,
    sec_014_datadog_key,
    sec_015_jwt_secret,
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


class TestSec004StripeKey:
    def test_sec_004_detects_live_key(self):
        content = "STRIPE_SECRET_KEY=sk_live_" + "A" * 24
        findings = sec_004_stripe_key(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-004"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_004_ignores_test_key(self):
        content = "STRIPE_SECRET_KEY=sk_test_AABBCCDDEEFFGGHHIIJJKK"
        findings = sec_004_stripe_key(Path("test.env"), content)
        assert len(findings) == 0

    def test_sec_004_skips_env_var(self):
        content = "key=$STRIPE_SECRET_KEY"
        findings = sec_004_stripe_key(Path("test.yml"), content)
        assert len(findings) == 0


class TestSec005OpenAIKey:
    def test_sec_005_detects_legacy_key(self):
        content = "OPENAI_API_KEY=sk-" + "A" * 20 + "T3Blb" + "kFJ" + "B" * 20  # split to avoid literal key
        findings = sec_005_openai_key(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-005"

    def test_sec_005_detects_project_key(self):
        content = "key=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        findings = sec_005_openai_key(Path("config.py"), content)
        assert len(findings) == 1

    def test_sec_005_skips_env_var(self):
        content = "key=$OPENAI_API_KEY"
        findings = sec_005_openai_key(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec006AnthropicKey:
    def test_sec_006_detects_key(self):
        key = "sk-ant-api03-" + "A" * 80
        content = f"ANTHROPIC_API_KEY={key}"
        findings = sec_006_anthropic_key(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-006"

    def test_sec_006_skips_env_var(self):
        content = "key=$ANTHROPIC_API_KEY"
        findings = sec_006_anthropic_key(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec007SlackToken:
    def test_sec_007_detects_bot_token(self):
        content = "SLACK_TOKEN=" + "xo" + "xb-12345678901-12345678901-AABBCCDDEEFFGGHHIIJJ"  # split to avoid literal token
        findings = sec_007_slack_token(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-007"

    def test_sec_007_detects_user_token(self):
        content = "token=xoxp-12345678901-12345678901-AABBCCDDEEFFGGHHIIJJ"
        findings = sec_007_slack_token(Path("test.yml"), content)
        assert len(findings) == 1

    def test_sec_007_skips_env_var(self):
        content = "token=$SLACK_TOKEN"
        findings = sec_007_slack_token(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec008PemPrivateKey:
    def test_sec_008_detects_rsa_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        findings = sec_008_pem_private_key(Path("id_rsa.pem"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-008"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_008_detects_ec_private_key(self):
        content = "-----BEGIN EC PRIVATE KEY-----"
        findings = sec_008_pem_private_key(Path("key.pem"), content)
        assert len(findings) == 1

    def test_sec_008_detects_openssh_private_key(self):
        content = "-----BEGIN OPENSSH PRIVATE KEY-----"
        findings = sec_008_pem_private_key(Path("id_ed25519"), content)
        assert len(findings) == 1

    def test_sec_008_detects_generic_private_key(self):
        content = "-----BEGIN PRIVATE KEY-----"
        findings = sec_008_pem_private_key(Path("test.key"), content)
        assert len(findings) == 1

    def test_sec_008_skips_public_key(self):
        content = "-----BEGIN PUBLIC KEY-----"
        findings = sec_008_pem_private_key(Path("test.pem"), content)
        assert len(findings) == 0

    def test_sec_008_skips_commented_line(self):
        content = "# -----BEGIN RSA PRIVATE KEY-----"
        findings = sec_008_pem_private_key(Path("test.py"), content)
        assert len(findings) == 0


class TestSec009NpmToken:
    def test_sec_009_detects_npm_token(self):
        content = "NODE_AUTH_TOKEN=npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        findings = sec_009_npm_token(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-009"

    def test_sec_009_skips_env_var(self):
        content = "token=$NODE_AUTH_TOKEN"
        findings = sec_009_npm_token(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec010HuggingFaceToken:
    def test_sec_010_detects_hf_token(self):
        content = "HF_TOKEN=hf_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        findings = sec_010_huggingface_token(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-010"
        assert findings[0].severity == Severity.HIGH

    def test_sec_010_skips_env_var(self):
        content = "token=$HF_TOKEN"
        findings = sec_010_huggingface_token(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec011AzureStorageKey:
    def test_sec_011_detects_connection_string(self):
        key = "A" * 64 + "=="
        content = f"conn=DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey={key}"
        findings = sec_011_azure_storage_key(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-011"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_011_skips_env_var(self):
        content = "conn=$AZURE_STORAGE_CONNECTION_STRING"
        findings = sec_011_azure_storage_key(Path("test.sh"), content)
        assert len(findings) == 0

    def test_sec_011_skips_template_placeholder(self):
        content = "conn=DefaultEndpointsProtocol=https;AccountName=<account>;AccountKey=<key>"
        findings = sec_011_azure_storage_key(Path("test.env"), content)
        assert len(findings) == 0


class TestSec012TwilioToken:
    def test_sec_012_detects_auth_token(self):
        content = "twilio_auth_token=abcdef1234567890abcdef1234567890"
        findings = sec_012_twilio_token(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-012"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_012_detects_camel_case(self):
        content = "authToken: 'abcdef1234567890abcdef1234567890'"
        findings = sec_012_twilio_token(Path("config.yml"), content)
        assert len(findings) == 1

    def test_sec_012_skips_env_var(self):
        content = "auth_token=$TWILIO_AUTH_TOKEN"
        findings = sec_012_twilio_token(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec013SendgridKey:
    def test_sec_013_detects_sendgrid_key(self):
        content = "SENDGRID_API_KEY=SG." + "A" * 22 + "." + "B" * 43
        findings = sec_013_sendgrid_key(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-013"
        assert findings[0].severity == Severity.CRITICAL

    def test_sec_013_skips_short_pattern(self):
        content = "key=SG.short.key"
        findings = sec_013_sendgrid_key(Path("test.env"), content)
        assert len(findings) == 0

    def test_sec_013_skips_env_var(self):
        content = "key=$SENDGRID_API_KEY"
        findings = sec_013_sendgrid_key(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec014DatadogKey:
    def test_sec_014_detects_dd_api_key(self):
        content = "DD_API_KEY=abcdef1234567890abcdef1234567890"
        findings = sec_014_datadog_key(Path("test.env"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-014"
        assert findings[0].severity == Severity.HIGH

    def test_sec_014_detects_datadog_api_key(self):
        content = "DATADOG_API_KEY=abcdef1234567890abcdef1234567890"
        findings = sec_014_datadog_key(Path("test.env"), content)
        assert len(findings) == 1

    def test_sec_014_skips_env_var(self):
        content = "key=$DD_API_KEY"
        findings = sec_014_datadog_key(Path("test.sh"), content)
        assert len(findings) == 0


class TestSec015JwtSecret:
    def test_sec_015_detects_jwt_secret(self):
        content = 'JWT_SECRET="supersecretkey123"'
        findings = sec_015_jwt_secret(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-015"
        assert findings[0].severity == Severity.HIGH

    def test_sec_015_detects_secret_key(self):
        content = "SECRET_KEY='my-django-secret-key-here'"
        findings = sec_015_jwt_secret(Path("settings.py"), content)
        assert len(findings) == 1

    def test_sec_015_skips_env_var_reference(self):
        content = "SECRET_KEY=$SECRET_KEY"
        findings = sec_015_jwt_secret(Path("test.sh"), content)
        assert len(findings) == 0

    def test_sec_015_skips_short_value(self):
        content = 'jwt_key="short"'
        findings = sec_015_jwt_secret(Path("test.py"), content)
        assert len(findings) == 0
