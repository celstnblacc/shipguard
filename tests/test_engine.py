"""Tests for the RepoSec scanner engine."""

from pathlib import Path

from reposec.config import Config
from reposec.engine import _get_suppressed_rules, scan
from reposec.models import Finding, Severity


class TestSuppression:
    def test_suppresses_rule_on_same_line(self):
        content = 'eval(data)  # reposec:ignore PY-003'
        suppressed = _get_suppressed_rules(content, 1)
        assert "PY-003" in suppressed

    def test_suppresses_rule_on_line_above(self):
        content = '# reposec:ignore PY-003\neval(data)'
        suppressed = _get_suppressed_rules(content, 2)
        assert "PY-003" in suppressed

    def test_suppresses_multiple_rules(self):
        content = '# reposec:ignore PY-003, PY-006'
        suppressed = _get_suppressed_rules(content, 1)
        assert "PY-003" in suppressed
        assert "PY-006" in suppressed

    def test_no_suppression_without_comment(self):
        content = 'eval(data)'
        suppressed = _get_suppressed_rules(content, 1)
        assert len(suppressed) == 0


class TestScan:
    def test_scan_fixtures(self):
        fixtures = Path(__file__).parent / "fixtures"
        result = scan(fixtures, severity_threshold=Severity.LOW)
        assert result.files_scanned > 0
        assert result.rules_applied > 0
        assert len(result.findings) > 0
        assert result.duration_seconds >= 0

    def test_scan_with_severity_filter(self):
        fixtures = Path(__file__).parent / "fixtures"
        result_all = scan(fixtures, severity_threshold=Severity.LOW)
        result_critical = scan(fixtures, severity_threshold=Severity.CRITICAL)
        assert len(result_critical.findings) <= len(result_all.findings)
        assert all(f.severity == Severity.CRITICAL for f in result_critical.findings)

    def test_scan_with_disabled_rules(self):
        fixtures = Path(__file__).parent / "fixtures"
        config = Config(disable_rules=["PY-003", "JS-001"])
        result = scan(fixtures, config=config, severity_threshold=Severity.LOW)
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-003" not in rule_ids
        assert "JS-001" not in rule_ids

    def test_scan_empty_dir(self, tmp_path):
        result = scan(tmp_path, severity_threshold=Severity.LOW)
        assert result.files_scanned == 0
        assert len(result.findings) == 0

    def test_scan_result_summary(self):
        fixtures = Path(__file__).parent / "fixtures"
        result = scan(fixtures, severity_threshold=Severity.LOW)
        summary = result.summary
        assert "critical" in summary
        assert "high" in summary
        assert "medium" in summary
        assert "low" in summary

    def test_scan_result_to_dict(self):
        fixtures = Path(__file__).parent / "fixtures"
        result = scan(fixtures, severity_threshold=Severity.LOW)
        d = result.to_dict()
        assert "findings" in d
        assert "summary" in d
        assert "total" in d["summary"]

    def test_scan_loads_custom_rules(self, tmp_path):
        rule_dir = tmp_path / "custom_rules"
        rule_dir.mkdir()
        (rule_dir / "custom_rule.py").write_text(
            """
from reposec.models import Finding, Severity
from reposec.rules import register

@register(
    id="CUST-001",
    name="custom-test-rule",
    severity=Severity.LOW,
    description="Custom rule for tests",
    extensions=[".txt"],
)
def custom_rule(file_path, content, config=None):
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        if "danger" in line:
            findings.append(
                Finding(
                    rule_id="CUST-001",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="custom danger marker found",
                )
            )
    return findings
""".strip()
        )
        (tmp_path / "sample.txt").write_text("ok\ndanger\n")

        config = Config(custom_rules_dirs=["custom_rules"])
        result = scan(tmp_path, config=config, severity_threshold=Severity.LOW)
        assert any(f.rule_id == "CUST-001" for f in result.findings)

    def test_scan_deduplicates_py005_and_shell009(self, tmp_path):
        p = tmp_path / "app.py"
        p.write_text(
            "import subprocess\nsubprocess.run('ls', shell=True)\n",
        )
        result = scan(tmp_path, severity_threshold=Severity.LOW)
        shell_009 = [f for f in result.findings if f.rule_id == "SHELL-009"]
        py_005 = [f for f in result.findings if f.rule_id == "PY-005"]
        assert len(py_005) == 1
        assert len(shell_009) == 0

    def test_scan_uses_rust_secrets_when_enabled(self, tmp_path, monkeypatch):
        p = tmp_path / "secrets.yml"
        p.write_text("aws_key: AKIA1234567890ABCDEF\n")

        def _mock_rust(files, target_dir):
            return [
                Finding(
                    rule_id="SEC-001",
                    severity=Severity.CRITICAL,
                    file_path=p,
                    line_number=1,
                    line_content="aws_key: AKIA1234567890ABCDEF",
                    message="AWS access key ID detected in file",
                    cwe_id="CWE-798",
                )
            ]

        monkeypatch.setattr("reposec.engine.run_rust_secrets_scan", _mock_rust)
        result = scan(tmp_path, config=Config(use_rust_secrets=True), severity_threshold=Severity.LOW)
        sec_findings = [f for f in result.findings if f.rule_id == "SEC-001"]
        assert len(sec_findings) == 1

    def test_scan_skips_python_secret_rules_when_rust_enabled(self, tmp_path, monkeypatch):
        p = tmp_path / "secrets.yml"
        p.write_text("aws_key: AKIA1234567890ABCDEF\n")
        monkeypatch.setattr("reposec.engine.run_rust_secrets_scan", lambda files, target_dir: [])

        result = scan(tmp_path, config=Config(use_rust_secrets=True), severity_threshold=Severity.LOW)
        sec_findings = [f for f in result.findings if f.rule_id.startswith("SEC-")]
        assert len(sec_findings) == 0
