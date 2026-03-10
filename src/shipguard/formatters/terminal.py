"""Rich terminal formatter for ShipGuard scan results."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from shipguard.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def format_terminal(result: ScanResult, console: Console | None = None) -> str:
    """Format scan results for terminal output using Rich.

    If console is provided, prints directly to it and returns "".
    If console is None, creates a recording console and returns the text.
    """
    recording = console is None
    if recording:
        console = Console(record=True)

    if not result.findings:
        console.print("\n[bold green]No security findings detected.[/bold green]\n")
        _print_summary(result, console)
        return console.export_text() if recording else ""

    table = Table(title="Security Findings", show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=12)
    table.add_column("File", width=40)
    table.add_column("Line", justify="right", width=5)
    table.add_column("Message", min_width=40)

    for finding in result.findings:
        color = SEVERITY_COLORS[finding.severity]
        table.add_row(
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.rule_id,
            str(finding.file_path),
            str(finding.line_number),
            finding.message,
        )

    console.print()
    console.print(table)

    # Print fix hints
    hints_shown: set[str] = set()
    has_hints = False
    for finding in result.findings:
        if finding.fix_hint and finding.rule_id not in hints_shown:
            if not has_hints:
                console.print("\n[bold]Fix hints:[/bold]")
                has_hints = True
            console.print(f"  [dim]{finding.rule_id}[/dim]: {finding.fix_hint}")
            hints_shown.add(finding.rule_id)

    console.print()
    _print_summary(result, console)
    return console.export_text() if recording else ""


def _print_summary(result: ScanResult, console: Console) -> None:
    """Print scan summary."""
    summary = result.summary
    console.print(
        f"[bold]Scan complete:[/bold] "
        f"{result.files_scanned} files scanned, "
        f"{len(result.findings)} findings "
        f"({summary['critical']} critical, {summary['high']} high, "
        f"{summary['medium']} medium, {summary['low']} low) "
        f"in {result.duration_seconds:.2f}s"
    )
