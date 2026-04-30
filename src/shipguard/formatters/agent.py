"""Agent-optimized 'Token-Diet' formatter."""

from shipguard.models import ScanResult

def format_agent(result: ScanResult, **kwargs) -> str:
    """Returns a highly compressed representation of findings for AI agents.
    Inspired by RTK token savings: strips whitespace, groups by rule, omits UI boilerplate.
    """
    if not result.findings:
        return "OK"

    grouped = {}
    for f in result.findings:
        grouped.setdefault(f.rule_id, []).append(f)

    lines = [f"FAIL:{len(result.findings)}"]
    for rule_id, findings in grouped.items():
        lines.append(f"{rule_id}:")
        for f in findings:
            # Minimal mapping: path:line|content
            # Optionally adding [T] for true positive or [F] if false positive (though filtered)
            content = f.line_content.strip()[:60]
            lines.append(f"  {f.file_path}:{f.line_number}|{content}")

    return "\n".join(lines)
