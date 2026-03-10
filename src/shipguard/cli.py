"""Typer CLI for ShipGuard security scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from shipguard import __version__
from shipguard.config import DEFAULT_CONFIG_TEMPLATE, load_config
from shipguard.engine import scan
from shipguard.formatters import get_formatter
from shipguard.models import Severity
from shipguard.rules import get_registry, load_builtin_rules, load_custom_rules

app = typer.Typer(
    name="shipguard",
    help="ShipGuard — Security audit tool for any repository.",
    no_args_is_help=True,
)
console = Console()


def _parse_rule_csv(raw: Optional[str]) -> set[str]:
    """Parse comma-separated rule IDs."""
    if not raw:
        return set()
    return {item.strip().upper() for item in raw.split(",") if item.strip()}


def _resolve_custom_rule_dirs(target_dir: Path, configured_dirs: list[str]) -> list[Path]:
    """Resolve custom rule directories against scan target dir."""
    resolved: list[Path] = []
    for rule_dir in configured_dirs:
        p = Path(rule_dir)
        resolved.append(p if p.is_absolute() else (target_dir / p))
    return resolved


def version_callback(value: bool) -> None:
    if value:
        console.print(f"shipguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """ShipGuard — Security audit tool for any repository."""


@app.command("scan")
def scan_cmd(
    path: Path = typer.Argument(
        ".", help="Directory to scan.", exists=True, file_okay=False, resolve_path=True,
    ),
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, markdown.",
    ),
    severity: str = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity: critical, high, medium, low. Overrides config.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file instead of stdout.",
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to config file.",
    ),
    rust_secrets: Optional[bool] = typer.Option(
        None,
        "--rust-secrets/--no-rust-secrets",
        help="Use optional Rust-accelerated secrets scanning for SEC-* rules.",
    ),
    include_rules: Optional[str] = typer.Option(
        None,
        "--include-rules",
        help="Comma-separated rule IDs to include (e.g., PY-003,SEC-001).",
    ),
    exclude_rules: Optional[str] = typer.Option(
        None,
        "--exclude-rules",
        help="Comma-separated rule IDs to exclude.",
    ),
) -> None:
    """Scan a directory for security vulnerabilities."""
    format = format.lower()
    config = load_config(config_path=config_file, target_dir=path)
    if rust_secrets is not None:
        config.use_rust_secrets = rust_secrets

    threshold = None
    if severity:
        try:
            threshold = Severity(severity.lower())
        except ValueError:
            console.print(f"[red]Invalid severity: {severity}[/red]")
            raise typer.Exit(code=1)

    include_rule_ids = _parse_rule_csv(include_rules)
    exclude_rule_ids = _parse_rule_csv(exclude_rules)

    # Validate rule IDs against loaded registry (builtin + configured custom rules).
    load_builtin_rules()
    load_custom_rules(_resolve_custom_rule_dirs(path, config.custom_rules_dirs))
    known_ids = set(get_registry().keys())
    unknown_ids = sorted((include_rule_ids | exclude_rule_ids) - known_ids)
    if unknown_ids:
        console.print(
            f"[red]Unknown rule ID(s): {', '.join(unknown_ids)}[/red]"
        )
        raise typer.Exit(code=1)

    result = scan(
        target_dir=path,
        config=config,
        severity_threshold=threshold,
        include_rules=include_rule_ids,
        exclude_rules=exclude_rule_ids,
    )

    try:
        formatter = get_formatter(format)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)
    if format == "terminal":
        if output:
            # Need recorded output for file
            text = formatter(result)
            output.write_text(text)
            console.print(f"Report written to {output}")
        else:
            formatter(result, console=console)
    else:
        text = formatter(result)
        if output:
            output.write_text(text)
            console.print(f"Report written to {output}")
        else:
            typer.echo(text)

    if result.findings:
        raise typer.Exit(code=1)


@app.command("list-rules")
def list_rules(
    format: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json.",
    ),
) -> None:
    """List all available security rules."""
    format = format.lower()
    if format not in {"terminal", "json"}:
        console.print(f"[red]Unknown format: {format!r}. Choose from: terminal, json[/red]")
        raise typer.Exit(code=1)

    load_builtin_rules()
    registry = get_registry()

    if format == "json":
        import json
        rules = [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "description": r.description,
                "extensions": r.extensions,
                "cwe_id": r.cwe_id,
            }
            for r in sorted(registry.values(), key=lambda r: r.id)
        ]
        typer.echo(json.dumps(rules, indent=2))
        return

    table = Table(title=f"ShipGuard Rules ({len(registry)} total)")
    table.add_column("ID", style="bold", width=12)
    table.add_column("Name", width=30)
    table.add_column("Severity", width=10)
    table.add_column("Description", min_width=40)
    table.add_column("CWE", width=10)

    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
    }

    for rule in sorted(registry.values(), key=lambda r: r.id):
        color = severity_colors[rule.severity]
        table.add_row(
            rule.id,
            rule.name,
            f"[{color}]{rule.severity.value.upper()}[/{color}]",
            rule.description,
            rule.cwe_id or "",
        )

    console.print(table)


@app.command()
def init(
    path: Path = typer.Argument(
        ".", help="Directory to create .shipguard.yml in.", exists=True,
    ),
) -> None:
    """Generate a .shipguard.yml configuration template."""
    config_path = Path(path) / ".shipguard.yml"
    if config_path.exists():
        console.print(f"[yellow]{config_path} already exists.[/yellow]")
        raise typer.Exit(code=1)
    config_path.write_text(DEFAULT_CONFIG_TEMPLATE)
    console.print(f"[green]Created {config_path}[/green]")
