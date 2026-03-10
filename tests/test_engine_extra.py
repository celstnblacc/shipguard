"""Additional engine tests for branch coverage."""

from __future__ import annotations

from pathlib import Path

from shipguard.config import Config
from shipguard.engine import _discover_files, _load_gitignore, _scan_file, scan
from shipguard.models import Finding, Severity
from shipguard.rules import RuleMeta


def test_load_gitignore_and_discover_files_honor_ignore(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.txt\n")
    (tmp_path / "ignored.txt").write_text("x")
    (tmp_path / "keep.py").write_text("print(1)\n")

    spec = _load_gitignore(tmp_path)
    assert spec is not None

    files = _discover_files(tmp_path, Config())
    names = {p.name for p in files}
    assert "keep.py" in names
    assert "ignored.txt" not in names


def test_scan_file_handles_read_error(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("print(1)\n")

    monkeypatch.setattr(Path, "read_text", lambda *a, **k: (_ for _ in ()).throw(OSError("denied")))
    findings = _scan_file(p, Config(), Severity.LOW)
    assert findings == []


def test_scan_file_skips_rule_without_func(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("print(1)\n")
    nofunc = RuleMeta(
        id="NOFUNC-1",
        name="no-func",
        severity=Severity.LOW,
        description="x",
        extensions=[".py"],
        func=None,
    )
    monkeypatch.setattr("shipguard.engine.get_rules_for_file", lambda _: [nofunc])
    findings = _scan_file(p, Config(), Severity.LOW)
    assert findings == []


def test_scan_file_respects_inline_suppression(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("# shipguard:ignore CUST-SUP-1\nprint('x')\n")

    def _func(file_path, content, config):
        return [
            Finding(
                rule_id="CUST-SUP-1",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                line_content="# shipguard:ignore CUST-SUP-1",
                message="x",
            )
        ]

    meta = RuleMeta(
        id="CUST-SUP-1",
        name="suppression-test",
        severity=Severity.HIGH,
        description="x",
        extensions=[".py"],
        func=_func,
    )
    monkeypatch.setattr("shipguard.engine.get_rules_for_file", lambda _: [meta])
    findings = _scan_file(p, Config(), Severity.LOW)
    assert findings == []


def test_scan_rust_branch_filters_disabled_severity_and_suppressed(tmp_path, monkeypatch):
    p = tmp_path / "x.yml"
    p.write_text("# shipguard:ignore SEC-KEEP\nsecret: value\n")
    missing = tmp_path / "missing.yml"  # read_text raises OSError

    rust_findings = [
        Finding(
            rule_id="SEC-DISABLED",
            severity=Severity.CRITICAL,
            file_path=p,
            line_number=1,
            line_content="x",
            message="x",
        ),
        Finding(
            rule_id="SEC-LOW",
            severity=Severity.LOW,
            file_path=p,
            line_number=1,
            line_content="x",
            message="x",
        ),
        Finding(
            rule_id="SEC-KEEP",
            severity=Severity.CRITICAL,
            file_path=p,
            line_number=1,
            line_content="x",
            message="x",
        ),
        Finding(
            rule_id="SEC-OSE",
            severity=Severity.CRITICAL,
            file_path=missing,
            line_number=1,
            line_content="x",
            message="x",
        ),
    ]

    monkeypatch.setattr("shipguard.engine.run_rust_secrets_scan", lambda files, target_dir: rust_findings)
    res = scan(
        tmp_path,
        config=Config(use_rust_secrets=True, disable_rules=["SEC-DISABLED"]),
        severity_threshold=Severity.HIGH,
    )
    ids = [f.rule_id for f in res.findings]
    assert "SEC-DISABLED" not in ids
    assert "SEC-LOW" not in ids
    assert "SEC-KEEP" not in ids
    assert "SEC-OSE" in ids


def test_scan_counts_skipped_files_when_worker_raises(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("print(1)\n")
    monkeypatch.setattr("shipguard.engine._scan_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    res = scan(tmp_path, severity_threshold=Severity.LOW)
    assert res.files_skipped >= 1
