"""CLI contract tests focused on stable behavior and exit semantics."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from reposec.cli import app

runner = CliRunner()


def _write_vulnerable_python_file(tmp_path: Path) -> Path:
    p = tmp_path / "vuln.py"
    p.write_text("result = eval(user_input)\n")
    return p


def test_scan_contract_exit_0_on_clean_repo(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No security findings detected." in result.output


def test_scan_contract_exit_1_on_findings_json(tmp_path):
    _write_vulnerable_python_file(tmp_path)
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1

    payload = json.loads(result.output)
    assert "findings" in payload
    assert "summary" in payload
    assert payload["summary"]["total"] >= 1


def test_scan_contract_severity_filter_critical_only(tmp_path):
    _write_vulnerable_python_file(tmp_path)
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--severity", "critical", "--format", "json"],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["summary"]["total"] >= 1
    assert all(item["severity"] == "critical" for item in payload["findings"])


def test_scan_contract_invalid_severity_returns_exit_1(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--severity", "invalid-level"])
    assert result.exit_code == 1
    assert "Invalid severity" in result.output


def test_scan_contract_invalid_format_returns_exit_1(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "not-a-format"])
    assert result.exit_code == 1
    assert "Unknown format" in result.output


def test_scan_contract_output_file_reports_path_and_writes_file(tmp_path):
    _write_vulnerable_python_file(tmp_path)
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--format", "json", "--output", str(out)],
    )
    assert result.exit_code == 1
    assert out.exists()
    assert "Report written to" in result.output
    assert str(out) in result.output.replace("\n", "")

    payload = json.loads(out.read_text())
    assert payload["summary"]["total"] >= 1


def test_list_rules_contract_json_schema():
    result = runner.invoke(app, ["list-rules", "--format", "json"])
    assert result.exit_code == 0
    rules = json.loads(result.output)
    assert len(rules) >= 40
    for rule in rules:
        assert "id" in rule
        assert "severity" in rule
        assert "description" in rule
        assert "extensions" in rule


def test_init_contract_creates_template_with_expected_keys(tmp_path):
    result = runner.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0
    cfg = (tmp_path / ".reposec.yml").read_text()
    assert "severity_threshold:" in cfg
    assert "exclude_paths:" in cfg
    assert "use_rust_secrets:" in cfg
