"""Tests for the Auto-Remediation Fixer feature."""

import os
from pathlib import Path
from typer.testing import CliRunner

from shipguard.cli import app

runner = CliRunner()

def test_auto_remediation_fixes_vulnerability(tmp_path):
    # Setup vulnerable file
    vuln_file = tmp_path / "target.py"
    vuln_file.write_text("def calculate(expression):\n    return eval(expression)\n")
    
    # Run the fix command with mock AI
    os.environ["MOCK_AI_FIXER"] = "1"
    
    result = runner.invoke(app, ["fix", str(tmp_path), "--id", "PY-003", "--apply"])
    
    assert result.exit_code == 0
    assert "Fixed 1 finding(s)" in result.stdout
    
    fixed_content = vuln_file.read_text()
    assert "ast.literal_eval(expression)" in fixed_content
    assert "import ast" in fixed_content
