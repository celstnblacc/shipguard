"""SARIF 2.1.0 formatter for ShipGuard scan results."""

from __future__ import annotations

import json

from shipguard.models import ScanResult, Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)


def _severity_to_level(severity: Severity) -> str:
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def format_sarif(result: ScanResult, **_kwargs) -> str:
    """Format scan results as SARIF 2.1.0 JSON."""
    try:
        from shipguard import __version__ as version
    except Exception:
        version = "unknown"

    # Build unique rules list from findings
    seen_rules: dict[str, str] = {}
    for finding in result.findings:
        if finding.rule_id not in seen_rules:
            seen_rules[finding.rule_id] = finding.message

    sarif_rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": message},
            "properties": {"tags": ["security"]},
        }
        for rule_id, message in seen_rules.items()
    ]

    sarif_results = []
    for finding in result.findings:
        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "level": _severity_to_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding.file_path),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line_number,
                            },
                        }
                    }
                ],
            }
        )

    sarif_output = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "shipguard",
                        "version": version,
                        "informationUri": "https://github.com/celstnblacc/shipguard",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_output, indent=2)
