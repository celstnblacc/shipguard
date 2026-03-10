"""Performance regression tests (env-gated)."""

from __future__ import annotations

import os
import time

import pytest

from shipguard.engine import scan
from shipguard.models import Severity


@pytest.mark.performance
def test_scan_performance_budget(tmp_path):
    if os.getenv("SHIPGUARD_RUN_PERF") != "1":
        pytest.skip("Set SHIPGUARD_RUN_PERF=1 to run performance tests.")

    for i in range(1500):
        (tmp_path / f"safe_{i}.py").write_text("print('ok')\n")

    start = time.monotonic()
    result = scan(tmp_path, severity_threshold=Severity.LOW, max_workers=8)
    elapsed = time.monotonic() - start

    assert result.files_scanned == 1500
    # Budget is intentionally generous to reduce flakiness across environments.
    assert elapsed < 8.0
