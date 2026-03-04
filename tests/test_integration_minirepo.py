"""End-to-end integration tests using temporary mini repositories."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from reposec.cli import app

runner = CliRunner()


def test_minirepo_scan_respects_gitignore_and_detects_vulns(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.py\n")
    (tmp_path / "ignored.py").write_text("eval(untrusted)\n")
    (tmp_path / "vuln.py").write_text("eval(untrusted)\n")
    (tmp_path / "safe.py").write_text("print('ok')\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    files = {Path(f["file_path"]).name for f in payload["findings"]}
    assert "vuln.py" in files
    assert "ignored.py" not in files


def test_minirepo_scan_respects_reposec_config_excludes(tmp_path):
    (tmp_path / ".reposec.yml").write_text('exclude_paths:\n  - "skipme/**"\n')
    skip = tmp_path / "skipme"
    skip.mkdir()
    (skip / "vuln.py").write_text("eval(untrusted)\n")
    (tmp_path / "vuln.py").write_text("eval(untrusted)\n")

    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    files = {Path(f["file_path"]).name for f in payload["findings"]}
    assert "vuln.py" in files
