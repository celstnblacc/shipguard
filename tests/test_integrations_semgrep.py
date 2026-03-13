"""Tests for Semgrep integration."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipguard.integrations.semgrep import run_semgrep
from shipguard.models import Severity


class TestRunSemgrep:
    def test_returns_empty_when_binary_missing(self, tmp_path):
        """Gracefully returns empty list when semgrep not found."""
        with patch("shipguard.integrations.semgrep._find_binary", return_value=None):
            result = run_semgrep(tmp_path)
        assert result == []

    def test_parses_semgrep_json_output(self, tmp_path):
        """Correctly parses semgrep JSON output."""
        mock_output = json.dumps({
            "results": [
                {
                    "check_id": "python.security.audit.eval",
                    "path": "src/app.py",
                    "start": {"line": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Use of eval() detected",
                        "lines": "eval(user_input)",
                        "metadata": {
                            "cwe": ["CWE-95"],
                        }
                    }
                }
            ]
        })

        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.semgrep._find_binary", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_semgrep(tmp_path)

        assert len(result) == 1
        assert "SEMGREP-python.security.audit.eval" in result[0].rule_id
        assert result[0].severity == Severity.HIGH
        assert result[0].line_number == 10
        assert result[0].cwe_id == "CWE-95"

    def test_graceful_on_timeout(self, tmp_path):
        """Returns empty list on subprocess timeout."""
        import subprocess
        with patch("shipguard.integrations.semgrep._find_binary", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 120)):
                result = run_semgrep(tmp_path)
        assert result == []

    def test_graceful_on_json_error(self, tmp_path):
        """Returns empty list on invalid JSON output."""
        mock_proc = MagicMock()
        mock_proc.stdout = "not valid json"

        with patch("shipguard.integrations.semgrep._find_binary", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_semgrep(tmp_path)
        assert result == []

    def test_severity_warning_maps_to_medium(self, tmp_path):
        """Maps semgrep WARNING to Severity.MEDIUM."""
        mock_output = json.dumps({
            "results": [{
                "check_id": "test.rule",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {
                    "severity": "WARNING",
                    "message": "Warning message",
                    "lines": "",
                    "metadata": {}
                }
            }]
        })
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.semgrep._find_binary", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_semgrep(tmp_path)

        assert result[0].severity == Severity.MEDIUM

    def test_empty_results(self, tmp_path):
        """Handles empty results gracefully."""
        mock_proc = MagicMock()
        mock_proc.stdout = json.dumps({"results": []})

        with patch("shipguard.integrations.semgrep._find_binary", return_value="/usr/bin/semgrep"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_semgrep(tmp_path)
        assert result == []
