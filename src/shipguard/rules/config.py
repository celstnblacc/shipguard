"""Configuration security rules (CFG-001 through CFG-003)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register


@register(
    id="CFG-001",
    name="directory-auto-approve",
    severity=Severity.HIGH,
    description="Detects directory-level auto-approval in IDE settings",
    extensions=[".json"],
    cwe_id="CWE-862",
)
def cfg_001_auto_approve(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Only check VS Code / IDE settings files
    name = file_path.name.lower()
    if name not in ("settings.json", ".claude.json", "mcp.json"):
        return findings

    patterns = [
        re.compile(r'"auto[Aa]pprove"', re.IGNORECASE),
        re.compile(r'"allowedDirectories"', re.IGNORECASE),
        re.compile(r'"autoApprovePatterns"', re.IGNORECASE),
    ]
    for i, line in enumerate(content.splitlines(), 1):
        for pat in patterns:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id="CFG-001",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Directory-level auto-approval may allow unreviewed operations",
                        cwe_id="CWE-862",
                        fix_hint="Review and restrict auto-approve patterns; prefer explicit approval",
                    )
                )
                break
    return findings


@register(
    id="CFG-002",
    name="env-file-committed",
    severity=Severity.HIGH,
    description="Detects .env files that may not be in .gitignore",
    extensions=[".env"],
    cwe_id="CWE-312",
)
def cfg_002_env_committed(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    name = file_path.name
    if not name.startswith(".env"):
        return findings
    # .env.example is OK
    if "example" in name.lower() or "template" in name.lower() or "sample" in name.lower():
        return findings

    # Check for actual secret-looking content
    secret_pattern = re.compile(
        r"^\s*(?:API_KEY|SECRET|TOKEN|PASSWORD|DATABASE_URL|AWS_|PRIVATE_KEY)\s*=\s*\S+",
        re.IGNORECASE | re.MULTILINE,
    )
    if secret_pattern.search(content):
        findings.append(
            Finding(
                rule_id="CFG-002",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                line_content=f"({name} contains secret-looking values)",
                message=".env file with secrets should not be committed to version control",
                cwe_id="CWE-312",
                fix_hint="Add .env to .gitignore and use .env.example for templates",
            )
        )
    return findings


@register(
    id="CFG-003",
    name="overly-permissive-cors",
    severity=Severity.MEDIUM,
    description="Detects Access-Control-Allow-Origin: * in configuration files",
    extensions=[".json", ".yml", ".yaml", ".toml", ".conf", ".cfg", ".ini", ".js", ".ts", ".py"],
    cwe_id="CWE-942",
)
def cfg_003_permissive_cors(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        re.compile(r"""Access-Control-Allow-Origin['":\s]+\*""", re.IGNORECASE),
        re.compile(r"""cors\s*\(\s*\)""", re.IGNORECASE),  # cors() with no options
        re.compile(r"""origin\s*:\s*(?:true|['"]?\*['"]?)""", re.IGNORECASE),
    ]
    for i, line in enumerate(content.splitlines(), 1):
        for pat in patterns:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id="CFG-003",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Overly permissive CORS allows any origin to access resources",
                        cwe_id="CWE-942",
                        fix_hint="Restrict origins to specific trusted domains",
                    )
                )
                break
    return findings
