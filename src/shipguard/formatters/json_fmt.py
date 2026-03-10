"""JSON formatter for ShipGuard scan results."""

from __future__ import annotations

import json

from shipguard.models import ScanResult


def format_json(result: ScanResult, **_kwargs) -> str:
    """Format scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2)
