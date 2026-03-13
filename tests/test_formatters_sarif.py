"""Tests for the SARIF 2.1.0 formatter."""

from __future__ import annotations

import json
from pathlib import Path

from shipguard.formatters.sarif import format_sarif
from shipguard.models import Finding, ScanResult, Severity

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)


def _make_result(*findings: Finding) -> ScanResult:
    result = ScanResult()
    result.findings = list(findings)
    result.files_scanned = 3
    result.rules_applied = 10
    result.finish()
    return result


def _make_finding(
    rule_id: str = "PY-001",
    severity: Severity = Severity.CRITICAL,
    message: str = "Test finding",
    line: int = 5,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        file_path=Path("src/app.py"),
        line_number=line,
        line_content="bad_code()",
        message=message,
        cwe_id="CWE-22",
        fix_hint="Fix it",
    )


class TestSarifFormat:
    def test_returns_valid_json(self):
        result = _make_result(_make_finding())
        output = format_sarif(result)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_contains_schema_key(self):
        result = _make_result(_make_finding())
        output = format_sarif(result)
        data = json.loads(output)
        assert "$schema" in data
        assert "sarif-schema-2.1.0" in data["$schema"]

    def test_driver_name_is_shipguard(self):
        result = _make_result(_make_finding())
        output = format_sarif(result)
        data = json.loads(output)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "shipguard"

    def test_one_result_per_finding(self):
        findings = [
            _make_finding("PY-001", Severity.CRITICAL, "msg1", 1),
            _make_finding("PY-002", Severity.HIGH, "msg2", 2),
            _make_finding("PY-003", Severity.MEDIUM, "msg3", 3),
        ]
        result = _make_result(*findings)
        output = format_sarif(result)
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 3

    def test_severity_critical_maps_to_error(self):
        result = _make_result(_make_finding("PY-001", Severity.CRITICAL))
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_severity_high_maps_to_error(self):
        result = _make_result(_make_finding("PY-001", Severity.HIGH))
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["results"][0]["level"] == "error"

    def test_severity_medium_maps_to_warning(self):
        result = _make_result(_make_finding("PY-001", Severity.MEDIUM))
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["results"][0]["level"] == "warning"

    def test_severity_low_maps_to_note(self):
        result = _make_result(_make_finding("PY-001", Severity.LOW))
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["results"][0]["level"] == "note"

    def test_rules_contains_unique_entries(self):
        findings = [
            _make_finding("PY-001", Severity.CRITICAL, "msg1", 1),
            _make_finding("PY-001", Severity.CRITICAL, "msg1", 2),  # duplicate rule
            _make_finding("PY-002", Severity.HIGH, "msg2", 3),
        ]
        result = _make_result(*findings)
        data = json.loads(format_sarif(result))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        # Should be unique
        assert len(rule_ids) == len(set(rule_ids))
        assert "PY-001" in rule_ids
        assert "PY-002" in rule_ids

    def test_empty_result(self):
        result = ScanResult()
        result.finish()
        data = json.loads(format_sarif(result))
        assert data["runs"][0]["results"] == []
        assert data["runs"][0]["tool"]["driver"]["rules"] == []

    def test_location_fields(self):
        result = _make_result(_make_finding("PY-001", Severity.HIGH, "msg", 42))
        data = json.loads(format_sarif(result))
        loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 42
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"

    def test_information_uri(self):
        result = _make_result(_make_finding())
        data = json.loads(format_sarif(result))
        assert "shipguard" in data["runs"][0]["tool"]["driver"]["informationUri"]
