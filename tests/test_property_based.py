"""Property-based tests for rule robustness and determinism."""

from __future__ import annotations

from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st  # type: ignore[reportMissingImports]

from reposec.rules.python import py_003_eval_exec
from reposec.rules.shell import shell_002_unquoted_variable


@settings(max_examples=80)
@given(st.text())
def test_shell_rule_is_deterministic_and_no_duplicate_line_rule_pairs(content: str):
    path = Path("test.sh")
    findings1 = shell_002_unquoted_variable(path, content)
    findings2 = shell_002_unquoted_variable(path, content)
    assert [f.to_dict() for f in findings1] == [f.to_dict() for f in findings2]

    seen = set()
    for f in findings1:
        key = (f.rule_id, f.line_number)
        assert key not in seen
        seen.add(key)


@settings(max_examples=80)
@given(st.text())
def test_python_eval_rule_never_crashes_on_arbitrary_text(content: str):
    path = Path("test.py")
    findings = py_003_eval_exec(path, content)
    assert isinstance(findings, list)
