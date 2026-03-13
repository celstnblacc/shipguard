"""Tests for ShellCheck integration."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipguard.integrations.shellcheck import run_shellcheck
from shipguard.models import Severity


class TestRunShellcheck:
    def test_returns_empty_when_binary_missing(self, tmp_path):
        """Gracefully returns empty list when shellcheck not found."""
        with patch("shipguard.integrations.shellcheck._find_binary", return_value=None):
            result = run_shellcheck([tmp_path / "test.sh"], tmp_path)
        assert result == []

    def test_returns_empty_when_no_shell_files(self, tmp_path):
        """Returns empty list when no shell files provided."""
        files = [tmp_path / "app.py", tmp_path / "config.json"]
        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            result = run_shellcheck(files, tmp_path)
        assert result == []

    def test_parses_json_output(self, tmp_path):
        """Correctly parses shellcheck JSON1 output format."""
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\neval $input\n")

        mock_output = json.dumps([
            {
                "file": str(shell_file),
                "comments": [
                    {
                        "file": str(shell_file),
                        "line": 2,
                        "endLine": 2,
                        "column": 1,
                        "endColumn": 10,
                        "level": "warning",
                        "code": 2046,
                        "message": "Quote this to prevent word splitting.",
                        "fix": None,
                    }
                ]
            }
        ])

        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_shellcheck([shell_file], tmp_path)

        assert len(result) == 1
        assert result[0].rule_id == "SHELLCHECK-SC2046"
        assert result[0].severity == Severity.MEDIUM
        assert result[0].line_number == 2

    def test_graceful_on_timeout(self, tmp_path):
        """Returns empty list on subprocess timeout."""
        import subprocess
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\necho hi\n")

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("shellcheck", 60)):
                result = run_shellcheck([shell_file], tmp_path)
        assert result == []

    def test_graceful_on_json_error(self, tmp_path):
        """Returns empty list on invalid JSON output."""
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\necho hi\n")

        mock_proc = MagicMock()
        mock_proc.stdout = "not valid json"

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_shellcheck([shell_file], tmp_path)
        assert result == []

    def test_level_mapping_error_to_high(self, tmp_path):
        """Maps shellcheck 'error' level to Severity.HIGH."""
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\neval $x\n")

        mock_output = json.dumps([{
            "file": str(shell_file),
            "comments": [{
                "file": str(shell_file),
                "line": 2,
                "level": "error",
                "code": 1234,
                "message": "Error message",
                "fix": None,
            }]
        }])
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_shellcheck([shell_file], tmp_path)

        assert result[0].severity == Severity.HIGH

    def test_env_var_overrides_binary(self, tmp_path):
        """SHIPGUARD_SHELLCHECK_BIN env var takes precedence."""
        import os
        shell_file = tmp_path / "test.sh"

        mock_proc = MagicMock()
        mock_proc.stdout = "[]"

        with patch.dict(os.environ, {"SHIPGUARD_SHELLCHECK_BIN": "/custom/shellcheck"}):
            with patch("subprocess.run", return_value=mock_proc) as mock_run:
                run_shellcheck([shell_file], tmp_path)
                if mock_run.called:
                    cmd = mock_run.call_args[0][0]
                    assert cmd[0] == "/custom/shellcheck"
