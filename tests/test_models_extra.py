"""Additional model tests for comparison operators."""

from reposec.models import Severity


def test_severity_comparisons_cover_all_operators():
    assert Severity.CRITICAL >= Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM <= Severity.HIGH
    assert Severity.LOW < Severity.MEDIUM
