"""Tests for TruffleHog integration."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipguard.integrations.trufflehog import run_trufflehog
from shipguard.models import Severity


class TestRunTrufflehog:
    def test_returns_empty_when_binary_missing(self, tmp_path):
        """Gracefully returns empty list when trufflehog not found."""
        with patch("shipguard.integrations.trufflehog._find_binary", return_value=None):
            result = run_trufflehog(tmp_path)
        assert result == []

    def test_parses_line_by_line_json(self, tmp_path):
        """Correctly parses TruffleHog newline-delimited JSON output."""
        finding1 = json.dumps({
            "DetectorName": "AWS",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "config/secrets.env",
                        "line": 3,
                    }
                }
            }
        })
        finding2 = json.dumps({
            "DetectorName": "GitHub",
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": "src/app.py",
                        "line": 15,
                    }
                }
            }
        })

        mock_proc = MagicMock()
        mock_proc.stdout = f"{finding1}\n{finding2}\n"

        with patch("shipguard.integrations.trufflehog._find_binary", return_value="/usr/bin/trufflehog"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trufflehog(tmp_path)

        assert len(result) == 2
        assert result[0].rule_id == "TRUFFLEHOG-AWS"
        assert result[0].severity == Severity.CRITICAL
        assert result[0].line_number == 3
        assert result[1].rule_id == "TRUFFLEHOG-GitHub"
        assert result[1].line_number == 15

    def test_skips_non_json_lines(self, tmp_path):
        """Skips non-JSON lines in output gracefully."""
        valid = json.dumps({
            "DetectorName": "Stripe",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "f.py", "line": 1}}}
        })
        mock_proc = MagicMock()
        mock_proc.stdout = f"not json\n{valid}\nalso not json\n"

        with patch("shipguard.integrations.trufflehog._find_binary", return_value="/usr/bin/trufflehog"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trufflehog(tmp_path)

        assert len(result) == 1
        assert result[0].rule_id == "TRUFFLEHOG-Stripe"

    def test_only_verified_flag(self, tmp_path):
        """Passes --only-verified when flag is True."""
        mock_proc = MagicMock()
        mock_proc.stdout = ""

        with patch("shipguard.integrations.trufflehog._find_binary", return_value="/usr/bin/trufflehog"):
            with patch("subprocess.run", return_value=mock_proc) as mock_run:
                run_trufflehog(tmp_path, only_verified=True)
                cmd = mock_run.call_args[0][0]
                assert "--only-verified" in cmd

    def test_only_verified_not_added_by_default(self, tmp_path):
        """Does not pass --only-verified by default."""
        mock_proc = MagicMock()
        mock_proc.stdout = ""

        with patch("shipguard.integrations.trufflehog._find_binary", return_value="/usr/bin/trufflehog"):
            with patch("subprocess.run", return_value=mock_proc) as mock_run:
                run_trufflehog(tmp_path, only_verified=False)
                cmd = mock_run.call_args[0][0]
                assert "--only-verified" not in cmd

    def test_graceful_on_timeout(self, tmp_path):
        """Returns empty list on subprocess timeout."""
        import subprocess
        with patch("shipguard.integrations.trufflehog._find_binary", return_value="/usr/bin/trufflehog"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("trufflehog", 120)):
                result = run_trufflehog(tmp_path)
        assert result == []

    def test_all_findings_are_critical(self, tmp_path):
        """All TruffleHog findings are CRITICAL severity."""
        finding = json.dumps({
            "DetectorName": "GenericSecret",
            "SourceMetadata": {"Data": {"Filesystem": {"file": "f.py", "line": 1}}}
        })
        mock_proc = MagicMock()
        mock_proc.stdout = finding + "\n"

        with patch("shipguard.integrations.trufflehog._find_binary", return_value="/usr/bin/trufflehog"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trufflehog(tmp_path)

        assert all(f.severity == Severity.CRITICAL for f in result)
