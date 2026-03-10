"""Markdown formatter for ShipGuard scan results."""

from __future__ import annotations

from shipguard.models import ScanResult, Severity


def format_markdown(result: ScanResult, **_kwargs) -> str:
    """Format scan results as a Markdown report."""
    lines: list[str] = []
    lines.append("# ShipGuard Security Report\n")

    summary = result.summary
    lines.append("## Summary\n")
    lines.append(f"- **Files scanned:** {result.files_scanned}")
    lines.append(f"- **Total findings:** {len(result.findings)}")
    lines.append(f"- **Critical:** {summary['critical']}")
    lines.append(f"- **High:** {summary['high']}")
    lines.append(f"- **Medium:** {summary['medium']}")
    lines.append(f"- **Low:** {summary['low']}")
    lines.append(f"- **Duration:** {result.duration_seconds:.2f}s\n")

    if not result.findings:
        lines.append("**No security findings detected.**\n")
        return "\n".join(lines)

    # Group by severity
    for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        findings = [f for f in result.findings if f.severity == severity]
        if not findings:
            continue

        lines.append(f"## {severity.value.upper()} ({len(findings)})\n")
        lines.append("| Rule | File | Line | Message |")
        lines.append("|------|------|------|---------|")
        for f in findings:
            msg = f.message.replace("|", "\\|")
            file_str = str(f.file_path).replace("|", "\\|")
            lines.append(f"| {f.rule_id} | `{file_str}` | {f.line_number} | {msg} |")
        lines.append("")

    # Fix hints
    hints_shown: set[str] = set()
    hint_lines: list[str] = []
    for finding in result.findings:
        if finding.fix_hint and finding.rule_id not in hints_shown:
            hint_lines.append(f"- **{finding.rule_id}**: {finding.fix_hint}")
            hints_shown.add(finding.rule_id)

    if hint_lines:
        lines.append("## Fix Hints\n")
        lines.extend(hint_lines)
        lines.append("")

    return "\n".join(lines)
