"""Supply chain security rules (SC-001 through SC-003)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register


@register(
    id="SC-001",
    name="docker-latest-tag",
    severity=Severity.HIGH,
    description="Detects Dockerfile FROM with :latest tag (unpinned base images)",
    extensions=["Dockerfile", ".dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    cwe_id="CWE-829",
)
def sc_001_docker_latest(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"FROM\s+\S+:latest", re.IGNORECASE)
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SC-001",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Base image uses :latest tag; unpinned versions can introduce unexpected changes",
                    cwe_id="CWE-829",
                    fix_hint="Pin the image to a specific version tag (e.g., FROM ubuntu:22.04)",
                )
            )
    return findings


@register(
    id="SC-002",
    name="unpinned-python-dependency",
    severity=Severity.MEDIUM,
    description="Detects Python dependencies without version pins in requirements files",
    extensions=[".txt"],
    cwe_id="CWE-829",
)
def sc_002_unpinned_python_dep(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Only check files matching requirements*.txt pattern
    name = file_path.name.lower()
    if not name.startswith("requirements") or not name.endswith(".txt"):
        return findings

    # Pattern: bare package name with no version specifier (==, ~=, >=, <=, etc.)
    # Should match: "requests", "flask", etc.
    # Should NOT match: "requests==2.31.0", "flask>=3.0", etc.
    pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*\s*$")

    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        # Skip empty lines
        if not line:
            continue
        # Skip comments
        if line.startswith("#"):
            continue
        # Skip option lines (-r, -i, --index-url, etc.)
        if line.startswith("-"):
            continue
        # Check if line is a bare package name (no version spec)
        if pattern.match(line):
            findings.append(
                Finding(
                    rule_id="SC-002",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line,
                    message="Dependency has no version pin; this allows unpredictable updates",
                    cwe_id="CWE-829",
                    fix_hint="Pin the version with == (e.g., requests==2.31.0) or use ~= for compatible releases",
                )
            )
    return findings


@register(
    id="SC-003",
    name="npm-install-without-frozen-lockfile",
    severity=Severity.MEDIUM,
    description="Detects npm/pnpm install without --frozen-lockfile or --ci flags in scripts",
    extensions=[".sh", ".yml", ".yaml"],
    cwe_id="CWE-829",
)
def sc_003_npm_frozen_lockfile(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Match npm install or pnpm install/pnpm i that doesn't have frozen-lockfile or ci flags
    pattern = re.compile(
        r"(npm\s+install|pnpm\s+(?:install|i))\b(?!.*(?:--frozen-lockfile|--ci|--immutable))"
    )

    for i, line in enumerate(content.splitlines(), 1):
        # Skip comments
        if line.lstrip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SC-003",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="npm/pnpm install without frozen-lockfile/ci flag risks inconsistent installs",
                    cwe_id="CWE-829",
                    fix_hint="Add --frozen-lockfile (npm) or --ci/--immutable (pnpm) to prevent unexpected upgrades",
                )
            )
    return findings


# Required .gitignore entries that guard against secret commits
_REQUIRED_GITIGNORE_ENTRIES = [".env", "*.key", "*.pem", "*.p12", "*.pfx"]


@register(
    id="SC-004",
    name="missing-gitignore-secret-entries",
    severity=Severity.HIGH,
    description="Detects .gitignore files missing baseline entries that protect against committing secrets",
    extensions=[".gitignore"],
    cwe_id="CWE-312",
)
def sc_004_missing_gitignore_entries(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    if file_path.name != ".gitignore":
        return findings

    existing = set(content.splitlines())
    missing = [
        entry for entry in _REQUIRED_GITIGNORE_ENTRIES
        if not any(entry in line for line in existing)
    ]
    if missing:
        findings.append(
            Finding(
                rule_id="SC-004",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                line_content=f"Missing entries: {', '.join(missing)}",
                message=f".gitignore is missing secret-protection entries: {', '.join(missing)}",
                cwe_id="CWE-312",
                fix_hint=f"Add the following to .gitignore: {chr(10).join(missing)}",
            )
        )
    return findings
