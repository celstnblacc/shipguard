"""Trivy integration for ShipGuard."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from shipguard.models import Finding, Severity

_LEVEL_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.LOW,
}

def _find_binary() -> str | None:
    env = os.environ.get("SHIPGUARD_TRIVY_BIN")
    if env:
        return env
    return shutil.which("trivy")

def run_trivy(target_dir: Path) -> list[Finding]:
    binary = _find_binary()
    if not binary:
        return []
    try:
        proc = subprocess.run(
            [binary, "fs", "--format", "json", "--scanners", "vuln,misconfig,secret",
             str(target_dir)],
            capture_output=True, text=True, timeout=180
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    findings: list[Finding] = []
    for result in data.get("Results", []):
        target = Path(result.get("Target", "unknown"))
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID", "UNKNOWN")
            severity = _LEVEL_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.LOW)
            findings.append(Finding(
                rule_id=f"TRIVY-{vid}",
                severity=severity,
                file_path=target,
                line_number=1,
                line_content=vuln.get("PkgName", ""),
                message=f"Trivy {vid}: {vuln.get('Title', vuln.get('Description', '')[:100])}",
                cwe_id="CWE-937",
                fix_hint=f"Upgrade {vuln.get('PkgName', '')} to {vuln.get('FixedVersion', 'latest fixed version')}",
            ))
        for misc in result.get("Misconfigurations") or []:
            mid = misc.get("ID", "UNKNOWN")
            severity = _LEVEL_MAP.get(misc.get("Severity", "UNKNOWN"), Severity.LOW)
            findings.append(Finding(
                rule_id=f"TRIVY-CFG-{mid}",
                severity=severity,
                file_path=target,
                line_number=1,
                line_content="",
                message=f"Trivy misconfiguration {mid}: {misc.get('Title', '')}",
                cwe_id="CWE-16",
                fix_hint=misc.get("Resolution", "Review and fix misconfiguration"),
            ))
    return findings
