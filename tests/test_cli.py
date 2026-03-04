"""Tests for the RepoSec CLI."""

from pathlib import Path

from typer.testing import CliRunner

from reposec.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


class TestScanCommand:
    def test_scan_finds_vulnerabilities(self):
        result = runner.invoke(app, ["scan", str(FIXTURES)])
        # Exit code 1 means findings were found
        assert result.exit_code == 1

    def test_scan_json_format(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "json"])
        assert result.exit_code == 1
        assert '"findings"' in result.output
        assert '"summary"' in result.output

    def test_scan_markdown_format(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "markdown"])
        assert result.exit_code == 1
        assert "# RepoSec Security Report" in result.output

    def test_scan_severity_filter(self):
        result = runner.invoke(
            app, ["scan", str(FIXTURES), "--severity", "critical", "--format", "json"]
        )
        # May find critical issues
        import json
        data = json.loads(result.output)
        for finding in data["findings"]:
            assert finding["severity"] == "critical"

    def test_scan_empty_dir(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_output_file(self, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["scan", str(FIXTURES), "--format", "json", "--output", str(out)]
        )
        assert out.exists()
        assert '"findings"' in out.read_text()

    def test_scan_output_file_terminal_format(self, tmp_path):
        out = tmp_path / "report.txt"
        result = runner.invoke(
            app, ["scan", str(FIXTURES), "--format", "terminal", "--output", str(out)]
        )
        assert result.exit_code == 1
        assert out.exists()
        assert "Security Findings" in out.read_text()

    def test_scan_invalid_severity(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--severity", "bogus"])
        assert result.exit_code == 1

    def test_scan_invalid_format(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "bogus"])
        assert result.exit_code == 1
        assert "Unknown format" in result.output

    def test_scan_accepts_rust_secrets_flag(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--rust-secrets", "--format", "json"])
        assert result.exit_code == 1


class TestListRulesCommand:
    def test_list_rules_terminal(self):
        result = runner.invoke(app, ["list-rules"])
        assert result.exit_code == 0
        assert "SHELL-001" in result.output
        assert "PY-001" in result.output

    def test_list_rules_json(self):
        result = runner.invoke(app, ["list-rules", "--format", "json"])
        assert result.exit_code == 0
        import json
        rules = json.loads(result.output)
        assert len(rules) == 40
        ids = {r["id"] for r in rules}
        assert "SHELL-001" in ids
        assert "CFG-003" in ids
        assert "SEC-001" in ids
        assert "SC-001" in ids

    def test_list_rules_invalid_format(self):
        result = runner.invoke(app, ["list-rules", "--format", "bogus"])
        assert result.exit_code == 1
        assert "Unknown format" in result.output


class TestInitCommand:
    def test_init_creates_config(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".reposec.yml").exists()

    def test_init_refuses_overwrite(self, tmp_path):
        (tmp_path / ".reposec.yml").write_text("existing")
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 1


class TestVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "reposec" in result.output
