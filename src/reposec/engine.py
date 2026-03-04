"""Scanner engine with parallel file scanning and suppression support."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pathspec

from reposec.config import Config
from reposec.models import Finding, ScanResult, Severity
from reposec.rust_secrets import run_rust_secrets_scan
from reposec.rules import get_rules_for_file, load_builtin_rules, load_custom_rules

SUPPRESSION_RE = re.compile(r"(?:#|//)\s*reposec:ignore\s+([\w\-,\s]+)")
DEFAULT_EXCLUDES = [
    "node_modules/**",
    ".git/**",
    "__pycache__/**",
    "*.pyc",
    ".venv/**",
    "venv/**",
    "dist/**",
    "build/**",
    ".tox/**",
    ".mypy_cache/**",
]


def _load_gitignore(target_dir: Path) -> pathspec.PathSpec | None:
    """Load .gitignore patterns if present."""
    gitignore = target_dir / ".gitignore"
    if gitignore.is_file():
        return pathspec.PathSpec.from_lines("gitignore", gitignore.read_text().splitlines())
    return None


def _discover_files(target_dir: Path, config: Config) -> list[Path]:
    """Discover scannable files, respecting exclusions."""
    exclude_patterns = DEFAULT_EXCLUDES + (config.exclude_paths or [])
    exclude_spec = pathspec.PathSpec.from_lines("gitignore", exclude_patterns)
    gitignore_spec = _load_gitignore(target_dir)

    files: list[Path] = []
    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(target_dir)
        rel_str = str(rel)
        if exclude_spec.match_file(rel_str):
            continue
        if gitignore_spec and gitignore_spec.match_file(rel_str):
            continue
        files.append(path)
    return files


def _get_suppressed_rules(content: str, line_number: int) -> set[str]:
    """Get suppressed rule IDs for a given line (checking current and previous line)."""
    lines = content.splitlines()
    suppressed: set[str] = set()
    for offset in (line_number - 1, line_number - 2):  # current line, line above
        if 0 <= offset < len(lines):
            m = SUPPRESSION_RE.search(lines[offset])
            if m:
                ids = [r.strip() for r in m.group(1).split(",")]
                suppressed.update(ids)
    return suppressed


def _scan_file(
    file_path: Path, config: Config, severity_threshold: Severity
) -> list[Finding]:
    """Scan a single file with all applicable rules."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []

    rules = get_rules_for_file(file_path)
    findings: list[Finding] = []

    seen_line_rules: dict[int, set[str]] = {}
    for rule in rules:
        if rule.id in (config.disable_rules or []):
            continue
        if config.use_rust_secrets and rule.id.startswith("SEC-"):
            continue
        if rule.func is None:
            continue

        rule_findings = rule.func(file_path, content, config)
        for finding in rule_findings:
            # PY-005 already covers subprocess shell=True in Python files.
            if (
                finding.rule_id == "SHELL-009"
                and "PY-005" in seen_line_rules.get(finding.line_number, set())
            ):
                continue
            # Check severity threshold
            if finding.severity < severity_threshold:
                continue
            # Check inline suppression
            suppressed = _get_suppressed_rules(content, finding.line_number)
            if finding.rule_id in suppressed:
                continue
            findings.append(finding)
            seen_line_rules.setdefault(finding.line_number, set()).add(finding.rule_id)

    return findings


def scan(
    target_dir: Path,
    config: Config | None = None,
    severity_threshold: Severity | None = None,
    max_workers: int = 4,
) -> ScanResult:
    """Scan a directory for security vulnerabilities.

    Args:
        target_dir: Directory to scan.
        config: Configuration object. Uses defaults if None.
        severity_threshold: Minimum severity to report. Overrides config.
        max_workers: Number of parallel workers.

    Returns:
        ScanResult with all findings.
    """
    if config is None:
        config = Config()

    load_builtin_rules()
    custom_dirs: list[Path] = []
    for rule_dir in config.custom_rules_dirs:
        p = Path(rule_dir)
        custom_dirs.append(p if p.is_absolute() else (target_dir / p))
    load_custom_rules(custom_dirs)

    threshold = severity_threshold or Severity(config.severity_threshold)
    result = ScanResult()

    files = _discover_files(target_dir, config)
    result.files_scanned = len(files)

    from reposec.rules import get_registry

    result.rules_applied = len(get_registry())

    all_findings: list[Finding] = []
    if config.use_rust_secrets:
        rust_findings = run_rust_secrets_scan(files, target_dir)
        for finding in rust_findings:
            if finding.rule_id in (config.disable_rules or []):
                continue
            if finding.severity < threshold:
                continue
            try:
                content = finding.file_path.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                content = ""
            if content and finding.rule_id in _get_suppressed_rules(content, finding.line_number):
                continue
            all_findings.append(finding)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_scan_file, f, config, threshold): f for f in files
        }
        for future in as_completed(futures):
            try:
                file_findings = future.result()
                all_findings.extend(file_findings)
            except Exception:
                result.files_skipped += 1

    # Sort by severity (descending), then file path, then line number
    all_findings.sort(
        key=lambda f: (-f.severity.rank, str(f.file_path), f.line_number)
    )
    result.findings = all_findings
    result.finish()
    return result
