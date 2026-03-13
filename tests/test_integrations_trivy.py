"""Tests for Trivy integration."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipguard.integrations.trivy import run_trivy
from shipguard.models import Severity


class TestRunTrivy:
    def test_returns_empty_when_binary_missing(self, tmp_path):
        """Gracefully returns empty list when trivy not found."""
        with patch("shipguard.integrations.trivy._find_binary", return_value=None):
            result = run_trivy(tmp_path)
        assert result == []

    def test_parses_vulnerability_output(self, tmp_path):
        """Correctly parses trivy JSON vulnerability output."""
        mock_output = json.dumps({
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "PkgName": "requests",
                            "Severity": "HIGH",
                            "Title": "Deserialization vulnerability",
                            "FixedVersion": "2.32.0",
                        }
                    ],
                    "Misconfigurations": None,
                }
            ]
        })

        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trivy(tmp_path)

        assert len(result) == 1
        assert result[0].rule_id == "TRIVY-CVE-2023-1234"
        assert result[0].severity == Severity.HIGH
        assert "requests" in result[0].line_content

    def test_severity_critical_mapping(self, tmp_path):
        """Maps CRITICAL severity correctly."""
        mock_output = json.dumps({
            "Results": [{
                "Target": "requirements.txt",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "flask",
                    "Severity": "CRITICAL",
                    "Title": "Critical issue",
                    "FixedVersion": "3.0.0",
                }],
                "Misconfigurations": None,
            }]
        })
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trivy(tmp_path)

        assert result[0].severity == Severity.CRITICAL

    def test_parses_misconfigurations(self, tmp_path):
        """Correctly parses trivy misconfiguration findings."""
        mock_output = json.dumps({
            "Results": [{
                "Target": "Dockerfile",
                "Vulnerabilities": None,
                "Misconfigurations": [{
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Severity": "HIGH",
                    "Resolution": "Run as a non-root user",
                }]
            }]
        })
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trivy(tmp_path)

        assert len(result) == 1
        assert result[0].rule_id == "TRIVY-CFG-DS002"
        assert result[0].severity == Severity.HIGH

    def test_graceful_on_timeout(self, tmp_path):
        """Returns empty list on subprocess timeout."""
        import subprocess
        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("trivy", 180)):
                result = run_trivy(tmp_path)
        assert result == []

    def test_graceful_on_json_error(self, tmp_path):
        """Returns empty list on invalid JSON output."""
        mock_proc = MagicMock()
        mock_proc.stdout = "not valid json"

        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trivy(tmp_path)
        assert result == []

    def test_empty_results(self, tmp_path):
        """Handles empty Results list gracefully."""
        mock_proc = MagicMock()
        mock_proc.stdout = json.dumps({"Results": []})

        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trivy(tmp_path)
        assert result == []

    def test_unknown_severity_maps_to_low(self, tmp_path):
        """Maps UNKNOWN severity to Severity.LOW."""
        mock_output = json.dumps({
            "Results": [{
                "Target": "go.sum",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-0001",
                    "PkgName": "gopkg",
                    "Severity": "UNKNOWN",
                    "Title": "Unknown severity issue",
                    "FixedVersion": "",
                }],
                "Misconfigurations": None,
            }]
        })
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.trivy._find_binary", return_value="/usr/bin/trivy"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_trivy(tmp_path)

        assert result[0].severity == Severity.LOW
