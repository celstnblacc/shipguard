"""Rust/Python parity tests for SEC-* rules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from shipguard.rules.secrets import sec_001_aws_key, sec_002_gcp_key, sec_003_github_token
from shipguard.rust_secrets import run_rust_secrets_scan


def _find_testable_rust_bin(repo_root: Path) -> str | None:
    candidates = [
        os.getenv("SHIPGUARD_RUST_SECRETS_BIN"),
        str(repo_root / "rust" / "shipguard-secrets" / "target" / "release" / "shipguard-secrets"),
        str(repo_root / "rust" / "shipguard-secrets" / "target" / "debug" / "shipguard-secrets"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def test_rust_python_secrets_parity_on_fixture(monkeypatch):
    repo_root = Path(__file__).resolve().parents[1]
    rust_bin = _find_testable_rust_bin(repo_root)
    if not rust_bin:
        pytest.skip("Rust binary not available; build rust/shipguard-secrets first.")

    fixture = repo_root / "tests" / "fixtures" / "secrets" / "vulnerable.yml"
    content = fixture.read_text()

    py_findings = []
    py_findings.extend(sec_001_aws_key(fixture, content))
    py_findings.extend(sec_002_gcp_key(fixture, content))
    py_findings.extend(sec_003_github_token(fixture, content))
    py_key = {(f.rule_id, f.line_number, f.message) for f in py_findings}

    monkeypatch.setenv("SHIPGUARD_RUST_SECRETS_BIN", rust_bin)
    rust_findings = run_rust_secrets_scan([fixture], repo_root)
    rust_key = {(f.rule_id, f.line_number, f.message) for f in rust_findings}

    assert rust_key == py_key
