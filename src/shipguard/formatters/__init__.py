"""Output formatters for ShipGuard scan results."""

from __future__ import annotations

from shipguard.formatters.json_fmt import format_json
from shipguard.formatters.markdown import format_markdown
from shipguard.formatters.sarif import format_sarif
from shipguard.formatters.terminal import format_terminal

__all__ = ["format_terminal", "format_json", "format_markdown", "format_sarif", "get_formatter"]

FORMATTERS = {
    "terminal": format_terminal,
    "json": format_json,
    "markdown": format_markdown,
    "sarif": format_sarif,
}


def get_formatter(name: str):
    """Get a formatter function by name."""
    if name not in FORMATTERS:
        raise ValueError(f"Unknown format: {name!r}. Choose from: {', '.join(FORMATTERS)}")
    return FORMATTERS[name]
