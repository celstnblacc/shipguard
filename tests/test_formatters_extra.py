"""Additional formatter tests for branch coverage."""

from pathlib import Path

from shipguard.formatters.markdown import format_markdown
from shipguard.formatters.terminal import format_terminal
from shipguard.models import Finding, ScanResult, Severity


def test_markdown_no_findings_message():
    result = ScanResult(findings=[], files_scanned=1)
    result.finish()
    out = format_markdown(result)
    assert "No security findings detected." in out


def test_terminal_recording_console_path():
    finding = Finding(
        rule_id="PY-003",
        severity=Severity.CRITICAL,
        file_path=Path("app.py"),
        line_number=1,
        line_content="eval(x)",
        message="eval usage",
        fix_hint="avoid eval",
    )
    result = ScanResult(findings=[finding], files_scanned=1)
    result.finish()
    out = format_terminal(result, console=None)
    assert "Security Findings" in out
