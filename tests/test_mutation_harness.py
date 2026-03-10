"""Mutation testing harness (env-gated)."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest


@pytest.mark.mutation
def test_mutation_tooling_smoke():
    if os.getenv("SHIPGUARD_RUN_MUTATION") != "1":
        pytest.skip("Set SHIPGUARD_RUN_MUTATION=1 to run mutation harness.")

    if shutil.which("mutmut") is None:
        pytest.skip("mutmut is not installed in this environment.")

    proc = subprocess.run(["mutmut", "--help"], capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    assert "mutmut" in (proc.stdout + proc.stderr).lower()
