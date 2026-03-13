"""Semgrep integration for ShipGuard."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from shipguard.models import Finding, Severity

_LEVEL_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

def _find_binary() -> str | None:
    env = os.environ.get("SHIPGUARD_SEMGREP_BIN")
    if env:
        return env
    return shutil.which("semgrep")

def run_semgrep(target_dir: Path, config_spec: str = "auto") -> list[Finding]:
    binary = _find_binary()
    if not binary:
        return []
    try:
        proc = subprocess.run(
            [binary, "--config", config_spec, "--json", str(target_dir)],
            capture_output=True, text=True, timeout=120
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    findings: list[Finding] = []
    for result in data.get("results", []):
        extra = result.get("extra", {})
        severity = _LEVEL_MAP.get(extra.get("severity", "WARNING"), Severity.MEDIUM)
        check_id = result.get("check_id", "unknown")[:50]
        path = Path(result.get("path", "unknown"))
        line = result.get("start", {}).get("line", 1)
        message = extra.get("message", check_id)
        cwe = ""
        if isinstance(extra.get("metadata"), dict):
            cwe_list = extra["metadata"].get("cwe", [])
            cwe = cwe_list[0] if cwe_list else ""
        findings.append(Finding(
            rule_id=f"SEMGREP-{check_id}",
            severity=severity,
            file_path=path,
            line_number=line,
            line_content=extra.get("lines", ""),
            message=f"Semgrep {check_id}: {message}",
            cwe_id=cwe or "CWE-0",
            fix_hint=extra.get("metadata", {}).get("fix", "") if isinstance(extra.get("metadata"), dict) else "",
        ))
    return findings
