"""GitHub Actions security rules (GHA-001 through GHA-005)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register

GHA_EXTS = [".yml", ".yaml"]


def _is_github_workflow(file_path: Path, content: str) -> bool:
    """Check if a YAML file is a GitHub Actions workflow."""
    parts = file_path.parts
    if ".github" in parts and "workflows" in parts:
        return True
    return bool(re.search(r"^on\s*:|^jobs\s*:", content, re.MULTILINE))


@register(
    id="GHA-001",
    name="workflow-injection",
    severity=Severity.CRITICAL,
    description="Detects injection of untrusted GitHub event data in run blocks",
    extensions=GHA_EXTS,
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1", "PCI-6.3"],
)
def gha_001_workflow_injection(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    if not _is_github_workflow(file_path, content):
        return []
    findings: list[Finding] = []
    # Dangerous expressions in run blocks
    dangerous = re.compile(
        r"\$\{\{\s*github\.event\."
        r"(?:issue|pull_request|comment|review|discussion|head_commit)"
        r"\.(?:body|title|head\.ref|label\.name|name)"
    )
    in_run = False
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        # Detect run: blocks — may appear as "run:" or "- run:" in step lists
        if re.match(r"^-?\s*run\s*[:|\s]", stripped):
            in_run = True
        elif in_run and re.match(r"^\s*[a-zA-Z_-]+\s*:", stripped) and not stripped.startswith("-"):
            in_run = False

        if (in_run or re.match(r"^-?\s*run\s*:", stripped)) and dangerous.search(line):
            findings.append(
                Finding(
                    rule_id="GHA-001",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Untrusted GitHub event data in run block enables command injection",
                    cwe_id="CWE-78",
                    fix_hint="Pass untrusted data via environment variables instead of inline expressions",
                )
            )
    return findings


@register(
    id="GHA-002",
    name="unpinned-action",
    severity=Severity.HIGH,
    description="Detects actions pinned to branches instead of commit SHAs",
    extensions=GHA_EXTS,
    cwe_id="CWE-829",
    compliance_tags=["SOC2-CC6.1", "PCI-6.3"],
)
def gha_002_unpinned_action(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    if not _is_github_workflow(file_path, content):
        return []
    findings: list[Finding] = []
    # uses: owner/repo@ref where ref is not a SHA (40 hex chars)
    uses_pattern = re.compile(r"uses:\s*([^\s#]+)")
    sha_pattern = re.compile(r"@[0-9a-f]{40}$")

    for i, line in enumerate(content.splitlines(), 1):
        m = uses_pattern.search(line)
        if m:
            action_ref = m.group(1)
            if "@" in action_ref and "/" in action_ref:
                if not sha_pattern.search(action_ref):
                    findings.append(
                        Finding(
                            rule_id="GHA-002",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=i,
                            line_content=line.rstrip(),
                            message=f"Action '{action_ref}' not pinned to a commit SHA",
                            cwe_id="CWE-829",
                            fix_hint="Pin to a full commit SHA: uses: owner/repo@<sha>",
                        )
                    )
    return findings


@register(
    id="GHA-003",
    name="excessive-permissions",
    severity=Severity.MEDIUM,
    description="Detects overly broad permissions in GitHub Actions workflows",
    extensions=GHA_EXTS,
    cwe_id="CWE-250",
    compliance_tags=["SOC2-CC6.1", "PCI-6.3"],
)
def gha_003_excessive_permissions(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    if not _is_github_workflow(file_path, content):
        return []
    findings: list[Finding] = []
    # write-all or no permissions block
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(r"permissions\s*:\s*write-all", line):
            findings.append(
                Finding(
                    rule_id="GHA-003",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Workflow uses write-all permissions (overly permissive)",
                    cwe_id="CWE-250",
                    fix_hint="Use least-privilege permissions, e.g., contents: read",
                )
            )
    return findings


@register(
    id="GHA-004",
    name="secrets-in-log",
    severity=Severity.MEDIUM,
    description="Detects secrets being echoed to logs in GitHub Actions",
    extensions=GHA_EXTS,
    cwe_id="CWE-532",
    compliance_tags=["SOC2-CC6.1", "PCI-6.3"],
)
def gha_004_secrets_in_log(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    if not _is_github_workflow(file_path, content):
        return []
    findings: list[Finding] = []
    pattern = re.compile(r"""echo\s+.*\$\{\{\s*secrets\.""")
    for i, line in enumerate(content.splitlines(), 1):
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="GHA-004",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Secret value echoed to logs may be exposed",
                    cwe_id="CWE-532",
                    fix_hint="Never echo secrets; use them only as env vars or in masked outputs",
                )
            )
    return findings


@register(
    id="GHA-005",
    name="pull-request-target",
    severity=Severity.HIGH,
    description="Detects pull_request_target with checkout of PR head (code injection risk)",
    extensions=GHA_EXTS,
    cwe_id="CWE-829",
    compliance_tags=["SOC2-CC6.1", "PCI-6.3"],
)
def gha_005_pr_target(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    if not _is_github_workflow(file_path, content):
        return []
    findings: list[Finding] = []
    has_pr_target = bool(re.search(r"\bpull_request_target\b", content))
    if not has_pr_target:
        return findings

    # Check for checkout of PR head ref
    checkout_pr = re.compile(
        r"github\.event\.pull_request\.head\.(sha|ref)"
    )
    for i, line in enumerate(content.splitlines(), 1):
        if checkout_pr.search(line):
            findings.append(
                Finding(
                    rule_id="GHA-005",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="pull_request_target with PR head checkout allows arbitrary code execution",
                    cwe_id="CWE-829",
                    fix_hint="Use pull_request event instead, or avoid checking out PR head code",
                )
            )
    return findings
