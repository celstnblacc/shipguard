"""Golden snapshot tests for formatter outputs."""

from __future__ import annotations

import os
from pathlib import Path

from reposec.formatters import format_json, format_markdown, format_terminal
from reposec.models import Finding, ScanResult, Severity

SNAP_DIR = Path(__file__).parent / "snapshots"


def _sample_result() -> ScanResult:
    findings = [
        Finding(
            rule_id="PY-003",
            severity=Severity.CRITICAL,
            file_path=Path("src/app.py"),
            line_number=10,
            line_content="result = eval(user_input)",
            message="eval() can execute arbitrary code if input is untrusted",
            cwe_id="CWE-95",
            fix_hint="Replace eval() with ast.literal_eval() or a safe parser",
        ),
        Finding(
            rule_id="SEC-001",
            severity=Severity.HIGH,
            file_path=Path("config/secrets.env"),
            line_number=2,
            line_content="aws_key=AKIA1234567890ABCDEF",
            message="AWS access key ID detected in file",
            cwe_id="CWE-798",
            fix_hint="Remove the key and rotate it in AWS IAM; use environment variables instead",
        ),
    ]
    result = ScanResult(
        findings=findings,
        files_scanned=3,
        files_skipped=1,
        rules_applied=40,
    )
    result.duration_seconds = 1.234
    return result


def _assert_or_update_snapshot(name: str, text: str) -> None:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    path = SNAP_DIR / name
    if os.getenv("UPDATE_SNAPSHOTS") == "1":
        path.write_text(text)
        return
    assert path.exists(), f"Missing snapshot {path}. Run with UPDATE_SNAPSHOTS=1 to create it."
    assert path.read_text() == text


def test_golden_json_snapshot():
    output = format_json(_sample_result())
    _assert_or_update_snapshot("format_json.snap", output)


def test_golden_markdown_snapshot():
    output = format_markdown(_sample_result())
    _assert_or_update_snapshot("format_markdown.snap", output)


def test_golden_terminal_snapshot():
    output = format_terminal(_sample_result(), console=None)
    _assert_or_update_snapshot("format_terminal.snap", output)
