"""Secrets security rules (SEC-001 through SEC-010)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register

SECRETS_EXTS = [
    ".yml", ".yaml", ".json", ".env", ".conf", ".cfg", ".ini", ".toml",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
    ".go", ".rb", ".tf", ".hcl", ".pem", ".key",
]


def _skip_false_positive(line: str) -> bool:
    """Check if a line should be skipped as a false positive."""
    line_upper = line.upper()
    # Skip comments
    if line.lstrip().startswith("#"):
        return True
    # Skip obvious placeholders (with clear markers like _NOT_REAL, _PLACEHOLDER)
    if any(
        keyword in line_upper
        for keyword in ["_NOT_REAL", "_PLACEHOLDER", "YOUR_", "CHANGE_ME", "REPLACE_ME"]
    ):
        return True
    # Skip environment variable references
    if "$" in line or "${" in line or "${{" in line:
        return True
    # Skip template syntax
    if "<" in line or ">" in line:
        return True
    return False


def _make_finding(
    rule_id: str,
    severity: Severity,
    file_path: Path,
    line_number: int,
    line_content: str,
    message: str,
    cwe_id: str,
    fix_hint: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        line_content=line_content,
        message=message,
        cwe_id=cwe_id,
        fix_hint=fix_hint,
    )


@register(
    id="SEC-001",
    name="aws-access-key-id",
    severity=Severity.CRITICAL,
    description="Detects AWS access key ID (AKIA*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_001_aws_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"AKIA[0-9A-Z]{16}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-001", Severity.CRITICAL, file_path, i, line.rstrip(),
                "AWS access key ID detected in file", "CWE-798",
                "Remove the key and rotate it in AWS IAM; use environment variables instead",
            ))
    return findings


@register(
    id="SEC-002",
    name="gcp-api-key",
    severity=Severity.CRITICAL,
    description="Detects GCP API key (AIza*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_002_gcp_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-002", Severity.CRITICAL, file_path, i, line.rstrip(),
                "GCP API key detected in file", "CWE-798",
                "Remove the key and rotate it in GCP Console; use environment variables instead",
            ))
    return findings


@register(
    id="SEC-003",
    name="github-token",
    severity=Severity.CRITICAL,
    description="Detects GitHub personal access tokens (ghp_*, gho_*, ghu_*, ghs_*, ghr_*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_003_github_token(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-003", Severity.CRITICAL, file_path, i, line.rstrip(),
                "GitHub personal access token detected in file", "CWE-798",
                "Revoke the token at github.com/settings/tokens; use GITHUB_TOKEN env var in CI",
            ))
    return findings


@register(
    id="SEC-004",
    name="stripe-live-key",
    severity=Severity.CRITICAL,
    description="Detects Stripe live secret key (sk_live_*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_004_stripe_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"sk_live_[0-9a-zA-Z]{24,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-004", Severity.CRITICAL, file_path, i, line.rstrip(),
                "Stripe live secret key detected in file", "CWE-798",
                "Revoke the key at dashboard.stripe.com/apikeys; use STRIPE_SECRET_KEY env var",
            ))
    return findings


@register(
    id="SEC-005",
    name="openai-api-key",
    severity=Severity.CRITICAL,
    description="Detects OpenAI API keys (legacy sk- and new sk-proj-/sk-user-/sk-svcacct- formats)",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_005_openai_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # New project/user/service-account keys: sk-proj-*, sk-user-*, sk-svcacct-*
    # Legacy keys contain the base64 marker T3BlbkFJ in the middle
    pattern = re.compile(
        r"sk-(?:proj|user|svcacct)-[A-Za-z0-9_\-]{50,}"
        r"|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"
    )
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-005", Severity.CRITICAL, file_path, i, line.rstrip(),
                "OpenAI API key detected in file", "CWE-798",
                "Revoke the key at platform.openai.com/api-keys; use OPENAI_API_KEY env var",
            ))
    return findings


@register(
    id="SEC-006",
    name="anthropic-api-key",
    severity=Severity.CRITICAL,
    description="Detects Anthropic/Claude API keys (sk-ant-*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_006_anthropic_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"sk-ant-(?:api\d+-|admin\d+-)?[A-Za-z0-9_\-]{80,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-006", Severity.CRITICAL, file_path, i, line.rstrip(),
                "Anthropic API key detected in file", "CWE-798",
                "Revoke the key at console.anthropic.com/settings/keys; use ANTHROPIC_API_KEY env var",
            ))
    return findings


@register(
    id="SEC-007",
    name="slack-token",
    severity=Severity.CRITICAL,
    description="Detects Slack bot/user/app tokens (xoxb-*, xoxp-*, xoxa-*, etc.) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_007_slack_token(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"(xoxb|xoxp|xoxa|xoxe|xoxr|xoxs)-[0-9A-Za-z\-]{10,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-007", Severity.CRITICAL, file_path, i, line.rstrip(),
                "Slack token detected in file", "CWE-798",
                "Revoke the token at api.slack.com/apps; use SLACK_TOKEN env var",
            ))
    return findings


@register(
    id="SEC-008",
    name="private-key-header",
    severity=Severity.CRITICAL,
    description="Detects PEM private key headers (RSA, EC, DSA, OPENSSH) embedded in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-312",
)
def sec_008_pem_private_key(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
    )
    for i, line in enumerate(content.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(_make_finding(
                "SEC-008", Severity.CRITICAL, file_path, i, line.rstrip(),
                "Private key material detected in file", "CWE-312",
                "Never commit private keys; supply the key path via an environment variable or secrets manager",
            ))
    return findings


@register(
    id="SEC-009",
    name="npm-access-token",
    severity=Severity.CRITICAL,
    description="Detects npm access tokens (npm_*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_009_npm_token(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"npm_[A-Za-z0-9]{36,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-009", Severity.CRITICAL, file_path, i, line.rstrip(),
                "npm access token detected in file", "CWE-798",
                "Revoke the token at npmjs.com/settings/tokens; use NODE_AUTH_TOKEN env var in CI",
            ))
    return findings


@register(
    id="SEC-010",
    name="huggingface-token",
    severity=Severity.HIGH,
    description="Detects HuggingFace API tokens (hf_*) in files",
    extensions=SECRETS_EXTS,
    cwe_id="CWE-798",
)
def sec_010_huggingface_token(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"hf_[A-Za-z0-9]{34,}")
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in pattern.finditer(line):
            findings.append(_make_finding(
                "SEC-010", Severity.HIGH, file_path, i, line.rstrip(),
                "HuggingFace API token detected in file", "CWE-798",
                "Revoke the token at huggingface.co/settings/tokens; use HUGGING_FACE_HUB_TOKEN env var",
            ))
    return findings
