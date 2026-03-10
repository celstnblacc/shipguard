"""Python security rules (PY-001 through PY-009)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register

PY_EXTS = [".py"]


@register(
    id="PY-001",
    name="zip-path-traversal",
    severity=Severity.CRITICAL,
    description="Detects zipfile.extractall() without member path validation (zip slip)",
    extensions=PY_EXTS,
    cwe_id="CWE-22",
)
def py_001_zip_traversal(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\.extractall\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line) and "zipfile" in content.lower():
            # Check if there's member validation nearby (within 10 lines before)
            lines = content.splitlines()
            start = max(0, i - 11)
            context = "\n".join(lines[start : i - 1])
            if not re.search(r"\.namelist\(\)|\.infolist\(\)|os\.path\..*\.\.", context):
                findings.append(
                    Finding(
                        rule_id="PY-001",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="zipfile.extractall() without path validation enables zip slip attacks",
                        cwe_id="CWE-22",
                        fix_hint="Validate each member name doesn't contain '..' before extraction",
                    )
                )
    return findings


@register(
    id="PY-002",
    name="yaml-unsafe-load",
    severity=Severity.CRITICAL,
    description="Detects yaml.load() without SafeLoader, enabling code execution",
    extensions=PY_EXTS,
    cwe_id="CWE-502",
)
def py_002_yaml_unsafe(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\byaml\.load\s*\(")
    safe_pattern = re.compile(r"Loader\s*=\s*(SafeLoader|yaml\.SafeLoader|CSafeLoader|yaml\.CSafeLoader)")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line) and not safe_pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-002",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="yaml.load() without SafeLoader allows arbitrary code execution",
                    cwe_id="CWE-502",
                    fix_hint="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                )
            )
    return findings


@register(
    id="PY-003",
    name="eval-exec-usage",
    severity=Severity.CRITICAL,
    description="Detects eval() or exec() calls that may execute untrusted code",
    extensions=PY_EXTS,
    cwe_id="CWE-95",
)
def py_003_eval_exec(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\b(eval|exec)\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = pattern.search(line)
        if m:
            func = m.group(1)
            findings.append(
                Finding(
                    rule_id="PY-003",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message=f"{func}() can execute arbitrary code if input is untrusted",
                    cwe_id="CWE-95",
                    fix_hint=f"Replace {func}() with ast.literal_eval() or a safe parser",
                )
            )
    return findings


@register(
    id="PY-004",
    name="startswith-path-check",
    severity=Severity.HIGH,
    description="Detects str.startswith() for path containment checks (CVE-2025-53110)",
    extensions=PY_EXTS,
    cwe_id="CWE-22",
)
def py_004_startswith_path(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Detect patterns like: path.startswith("/some/dir") or str(path).startswith(
    pattern = re.compile(
        r"""(?:str\s*\(\s*\w+\s*\)|\.resolve\(\)|path\w*|dir\w*|file\w*|folder\w*)\.startswith\s*\(""",
        re.IGNORECASE,
    )
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-004",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="str.startswith() for path containment is bypassable with crafted paths",
                    cwe_id="CWE-22",
                    fix_hint="Use pathlib: child.resolve().is_relative_to(parent.resolve())",
                )
            )
    return findings


@register(
    id="PY-005",
    name="subprocess-shell-true",
    severity=Severity.HIGH,
    description="Detects subprocess calls with shell=True",
    extensions=PY_EXTS,
    cwe_id="CWE-78",
)
def py_005_subprocess_shell(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\bsubprocess\.\w+\(")
    shell_pattern = re.compile(r"shell\s*=\s*True")
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            # Check this line and next few lines for shell=True
            window = "\n".join(lines[i - 1 : min(i + 4, len(lines))])
            if shell_pattern.search(window):
                shell_line = i
                for j in range(i - 1, min(i + 4, len(lines))):
                    if shell_pattern.search(lines[j]):
                        shell_line = j + 1
                        break
                findings.append(
                    Finding(
                        rule_id="PY-005",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=shell_line,
                        line_content=lines[shell_line - 1].rstrip(),
                        message="subprocess with shell=True is vulnerable to shell injection",
                        cwe_id="CWE-78",
                        fix_hint="Use shell=False and pass arguments as a list",
                    )
                )
    return findings


@register(
    id="PY-006",
    name="hardcoded-secrets",
    severity=Severity.HIGH,
    description="Detects hardcoded API keys, tokens, and passwords in Python source",
    extensions=PY_EXTS,
    cwe_id="CWE-798",
)
def py_006_hardcoded_secrets(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (re.compile(r"""(?:api_key|apikey|api_secret|secret_key|auth_token|access_token|password)\s*=\s*["'][^"']{8,}["']""", re.IGNORECASE), "hardcoded secret"),
        (re.compile(r"""["'](?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|AKIA[A-Z0-9]{16})["']"""), "API key/token literal"),
    ]
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat, desc in patterns:
            if pat.search(line):
                # Skip obvious test/placeholder values
                lower = line.lower()
                if any(placeholder in lower for placeholder in [
                    "example", "placeholder", "change_me", "your-",
                    "test-fake", "xxx", "replace", "<",
                ]):
                    continue
                findings.append(
                    Finding(
                        rule_id="PY-006",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message=f"Possible {desc} found in source code",
                        cwe_id="CWE-798",
                        fix_hint="Use environment variables or a secrets manager instead",
                    )
                )
                break  # One finding per line
    return findings


@register(
    id="PY-007",
    name="sql-string-format",
    severity=Severity.HIGH,
    description="Detects f-strings or .format() used in SQL queries",
    extensions=PY_EXTS,
    cwe_id="CWE-89",
)
def py_007_sql_injection(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    sql_keywords = r"(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|GRANT)\b"
    # f-string SQL
    fstring_pattern = re.compile(rf'f["\'].*{sql_keywords}', re.IGNORECASE)
    # .format() SQL
    format_pattern = re.compile(rf'["\'].*{sql_keywords}.*["\']\.format\s*\(', re.IGNORECASE)
    # % formatting SQL
    percent_pattern = re.compile(rf'["\'].*{sql_keywords}.*%s.*["\']\s*%', re.IGNORECASE)

    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if fstring_pattern.search(line) or format_pattern.search(line) or percent_pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-007",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="SQL query built with string formatting is vulnerable to SQL injection",
                    cwe_id="CWE-89",
                    fix_hint="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
                )
            )
    return findings


@register(
    id="PY-008",
    name="pickle-load",
    severity=Severity.MEDIUM,
    description="Detects pickle.load/loads() which can execute arbitrary code",
    extensions=PY_EXTS,
    cwe_id="CWE-502",
)
def py_008_pickle_load(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\bpickle\.(?:load|loads)\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-008",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="pickle.load() can execute arbitrary code from untrusted data",
                    cwe_id="CWE-502",
                    fix_hint="Use JSON or a safe serialization format for untrusted data",
                )
            )
    return findings


@register(
    id="PY-009",
    name="tempfile-no-cleanup",
    severity=Severity.LOW,
    description="Detects tempfile.mktemp() usage which has a race condition",
    extensions=PY_EXTS,
    cwe_id="CWE-377",
)
def py_009_tempfile_mktemp(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\btempfile\.mktemp\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-009",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="tempfile.mktemp() has a race condition between name creation and file creation",
                    cwe_id="CWE-377",
                    fix_hint="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead",
                )
            )
    return findings
