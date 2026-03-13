"""TruffleHog integration for ShipGuard."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from shipguard.models import Finding, Severity

def _find_binary() -> str | None:
    env = os.environ.get("SHIPGUARD_TRUFFLEHOG_BIN")
    if env:
        return env
    return shutil.which("trufflehog")

def run_trufflehog(target_dir: Path, only_verified: bool = False) -> list[Finding]:
    binary = _find_binary()
    if not binary:
        return []
    # Respect env var override for CI
    if os.environ.get("SHIPGUARD_TRUFFLEHOG_VERIFY", "").lower() == "true":
        only_verified = True
    cmd = [binary, "filesystem", "--json", str(target_dir)]
    if only_verified:
        cmd.append("--only-verified")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return []

    findings: list[Finding] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = item.get("DetectorName", "unknown")
        source_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        file_path = Path(source_meta.get("file", "unknown"))
        line_num = source_meta.get("line", 1)
        findings.append(Finding(
            rule_id=f"TRUFFLEHOG-{detector}",
            severity=Severity.CRITICAL,
            file_path=file_path,
            line_number=line_num,
            line_content="[redacted]",
            message=f"TruffleHog detected {detector} secret",
            cwe_id="CWE-798",
            fix_hint="Rotate the secret immediately; remove from git history with git-filter-repo",
        ))
    return findings
