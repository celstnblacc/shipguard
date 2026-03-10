"""Additional tests for rules registry branch coverage."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules import _registry, get_rules_for_file, load_custom_rules, register


def test_get_rules_for_file_matches_named_pattern_without_dot():
    @register(
        id="CUST-NAMED-1",
        name="named-pattern",
        severity=Severity.LOW,
        description="Matches by exact filename pattern",
        extensions=["dockerfile"],
    )
    def _named_rule(file_path, content, config=None):  # pragma: no cover - registration helper
        return []

    try:
        rules = {r.id for r in get_rules_for_file(Path("Dockerfile"))}
        assert "CUST-NAMED-1" in rules
    finally:
        _registry.pop("CUST-NAMED-1", None)


def test_load_custom_rules_skips_missing_directory(tmp_path):
    loaded = load_custom_rules([tmp_path / "not-a-dir"])
    assert loaded == 0


def test_load_custom_rules_skips_already_loaded_module(tmp_path):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    f = rule_dir / "rule_a.py"
    f.write_text(
        """
from shipguard.models import Severity
from shipguard.rules import register

@register(
    id="CUST-DUP-1",
    name="dup",
    severity=Severity.LOW,
    description="dup",
    extensions=[".txt"],
)
def custom_rule(file_path, content, config=None):
    return []
""".strip()
    )
    first = load_custom_rules([rule_dir])
    second = load_custom_rules([rule_dir])
    assert first == 1
    assert second == 0


def test_load_custom_rules_skips_when_spec_is_none(tmp_path, monkeypatch):
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "x.py").write_text("x=1\n")

    monkeypatch.setattr("importlib.util.spec_from_file_location", lambda *a, **k: None)
    loaded = load_custom_rules([rule_dir])
    assert loaded == 0
