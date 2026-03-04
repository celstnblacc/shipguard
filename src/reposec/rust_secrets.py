"""Optional Rust-backed secrets scanner integration."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from reposec.models import Finding, Severity

SECRETS_EXTS = {".yml", ".yaml", ".json", ".env", ".conf", ".cfg", ".ini", ".toml"}


def _find_rust_binary(target_dir: Path) -> str | None:
    """Find Rust scanner binary from env, PATH, or local build output."""
    env_bin = os.getenv("REPOSEC_RUST_SECRETS_BIN")
    if env_bin:
        return env_bin

    path_bin = shutil.which("reposec-secrets")
    if path_bin:
        return path_bin

    local = target_dir / "rust" / "reposec-secrets" / "target" / "release" / "reposec-secrets"
    if local.is_file():
        return str(local)
    return None


def run_rust_secrets_scan(files: list[Path], target_dir: Path) -> list[Finding]:
    """Run Rust secrets scanner; returns [] on missing binary or execution failure."""
    bin_path = _find_rust_binary(target_dir)
    if not bin_path:
        return []

    candidate_files = [str(p) for p in files if p.suffix.lower() in SECRETS_EXTS]
    if not candidate_files:
        return []

    payload = json.dumps({"files": candidate_files})
    try:
        proc = subprocess.run(
            [bin_path],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if proc.returncode != 0:
        return []

    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in data.get("findings", []):
        try:
            findings.append(
                Finding(
                    rule_id=item["rule_id"],
                    severity=Severity(item.get("severity", "critical")),
                    file_path=Path(item["file_path"]),
                    line_number=int(item["line_number"]),
                    line_content=item.get("line_content", ""),
                    message=item["message"],
                    cwe_id=item.get("cwe_id"),
                    fix_hint=item.get("fix_hint"),
                )
            )
        except (KeyError, ValueError, TypeError):
            continue
    return findings
