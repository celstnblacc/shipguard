"""Tests for optional Rust secrets scanner integration."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from reposec.models import Severity
from reposec.rust_secrets import _find_rust_binary, run_rust_secrets_scan


class TestFindRustBinary:
    def test_prefers_env_var(self, tmp_path, monkeypatch):
        fake_bin = tmp_path / "scanner"
        monkeypatch.setenv("REPOSEC_RUST_SECRETS_BIN", str(fake_bin))
        monkeypatch.setattr("shutil.which", lambda _: None)
        assert _find_rust_binary(tmp_path) == str(fake_bin)

    def test_uses_path_when_env_missing(self, tmp_path, monkeypatch):
        monkeypatch.delenv("REPOSEC_RUST_SECRETS_BIN", raising=False)
        monkeypatch.setattr("shutil.which", lambda _: "/usr/local/bin/reposec-secrets")
        assert _find_rust_binary(tmp_path) == "/usr/local/bin/reposec-secrets"

    def test_uses_local_build_output(self, tmp_path, monkeypatch):
        monkeypatch.delenv("REPOSEC_RUST_SECRETS_BIN", raising=False)
        monkeypatch.setattr("shutil.which", lambda _: None)
        local = tmp_path / "rust" / "reposec-secrets" / "target" / "release" / "reposec-secrets"
        local.parent.mkdir(parents=True)
        local.write_text("")
        assert _find_rust_binary(tmp_path) == str(local)


class TestRunRustSecretsScan:
    def test_returns_empty_when_binary_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr("reposec.rust_secrets._find_rust_binary", lambda _: None)
        findings = run_rust_secrets_scan([tmp_path / "x.yml"], tmp_path)
        assert findings == []

    def test_returns_empty_when_no_candidate_extensions(self, tmp_path, monkeypatch):
        monkeypatch.setattr("reposec.rust_secrets._find_rust_binary", lambda _: "/bin/reposec-secrets")
        findings = run_rust_secrets_scan([tmp_path / "main.py"], tmp_path)
        assert findings == []

    def test_returns_empty_on_nonzero_exit(self, tmp_path, monkeypatch):
        monkeypatch.setattr("reposec.rust_secrets._find_rust_binary", lambda _: "/bin/reposec-secrets")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""),
        )
        findings = run_rust_secrets_scan([tmp_path / "secrets.yml"], tmp_path)
        assert findings == []

    def test_returns_empty_when_subprocess_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr("reposec.rust_secrets._find_rust_binary", lambda _: "/bin/reposec-secrets")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("boom")),
        )
        findings = run_rust_secrets_scan([tmp_path / "secrets.yml"], tmp_path)
        assert findings == []

    def test_returns_empty_on_invalid_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr("reposec.rust_secrets._find_rust_binary", lambda _: "/bin/reposec-secrets")
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="{not-json"),
        )
        findings = run_rust_secrets_scan([tmp_path / "secrets.yml"], tmp_path)
        assert findings == []

    def test_parses_findings_and_skips_malformed_entries(self, tmp_path, monkeypatch):
        monkeypatch.setattr("reposec.rust_secrets._find_rust_binary", lambda _: "/bin/reposec-secrets")
        payload = """
{
  "findings": [
    {
      "rule_id": "SEC-001",
      "severity": "critical",
      "file_path": "/tmp/a.yml",
      "line_number": 3,
      "line_content": "aws_key: AKIA1234567890ABCDEF",
      "message": "AWS access key ID detected in file",
      "cwe_id": "CWE-798",
      "fix_hint": "rotate"
    },
    {
      "rule_id": "SEC-002",
      "severity": "critical"
    }
  ]
}
""".strip()
        monkeypatch.setattr(
            "subprocess.run",
            lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=payload),
        )

        findings = run_rust_secrets_scan([tmp_path / "secrets.yml"], tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "SEC-001"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].line_number == 3
        assert findings[0].file_path == Path("/tmp/a.yml")
