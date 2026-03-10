"""Concurrency behavior tests for scanner engine."""

from __future__ import annotations

from pathlib import Path

from shipguard.engine import scan
from shipguard.models import Severity


def test_scan_parallel_and_serial_results_are_equivalent(tmp_path):
    for i in range(80):
        p = tmp_path / f"f{i}.py"
        if i % 10 == 0:
            p.write_text("result = eval(user_input)\n")
        else:
            p.write_text("print('safe')\n")

    serial = scan(tmp_path, severity_threshold=Severity.LOW, max_workers=1)
    parallel = scan(tmp_path, severity_threshold=Severity.LOW, max_workers=8)

    serial_keys = [(f.rule_id, str(f.file_path), f.line_number, f.message) for f in serial.findings]
    parallel_keys = [(f.rule_id, str(f.file_path), f.line_number, f.message) for f in parallel.findings]
    assert parallel_keys == serial_keys


def test_scan_parallel_handles_many_files_without_skips(tmp_path):
    for i in range(200):
        (tmp_path / f"safe_{i}.py").write_text("print('ok')\n")

    result = scan(tmp_path, severity_threshold=Severity.LOW, max_workers=16)
    assert result.files_scanned == 200
    assert result.files_skipped == 0
