"""Shell security rules (SHELL-001 through SHELL-009)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register

SHELL_EXTS = [".sh", ".bash", ".zsh", ".ksh"]


@register(
    id="SHELL-001",
    name="eval-injection",
    severity=Severity.CRITICAL,
    description="Detects eval with command substitution, enabling code injection",
    extensions=SHELL_EXTS,
    cwe_id="CWE-94",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_001_eval_injection(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r'\beval\s+["\']?\$')
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SHELL-001",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="eval with variable/command substitution allows code injection",
                    cwe_id="CWE-94",
                    fix_hint="Avoid eval; use arrays or direct execution instead",
                )
            )
    return findings


@register(
    id="SHELL-002",
    name="unquoted-variable-expansion",
    severity=Severity.HIGH,
    description="Detects unquoted variable expansions in dangerous command arguments",
    extensions=SHELL_EXTS,
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_002_unquoted_variable(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Patterns that indicate safe contexts (no word splitting risk)
    safe_line_patterns = [
        re.compile(r"^\s*#"),                         # comments
        re.compile(r"^\s*(?:export\s+|local\s+|declare\s+|readonly\s+)?\w+="),  # assignments
        re.compile(r"^\s*\[\["),                       # [[ ]] — no word splitting
        re.compile(r"^\s*\(\("),                       # (( )) — arithmetic
        re.compile(r"^\s*(?:return|exit)\s"),           # return/exit — single int
        re.compile(r"^\s*for\s+\w+\s+in\b"),           # for loop iteration
        re.compile(r"^\s*(?:if|elif|while)\s+\[\["),    # conditional with [[
        re.compile(r"^\s*case\s"),                      # case statement
        re.compile(r"^\s*(?:then|else|fi|do|done|esac)\s*$"),  # control keywords
        re.compile(r"^\s*(?:if|elif|while)\s+\["),      # [ ] test command (mostly safe for integers)
        re.compile(r"^\s*if\s+\$\w+\s*;"),              # if $bool_var; then (boolean command)
    ]
    # Safe variable patterns (not dangerous even if unquoted)
    safe_var_patterns = re.compile(
        r"\$\{"                         # ${...} with special syntax:
        r"(?:"
        r"#\w+|"                        # ${#var} — string length
        r"\w+\[@\]|"                    # ${array[@]} — array expansion
        r"\w+\[\*\]|"                   # ${array[*]}
        r"\w+:[-+=?]|"                  # ${var:-default} etc.
        r"\w+//|"                       # ${var//pattern/replace}
        r"\w+%%|"                       # ${var%%pattern}
        r"\w+##"                        # ${var##pattern}
        r")"
    )
    # Dangerous commands where unquoted vars actually matter
    dangerous_cmd_pattern = re.compile(
        r"\b(?:rm|cp|mv|mkdir|chmod|chown|cat|cd|source|\.)"
        r"\s.*\$"
    )

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        # Skip safe contexts
        if any(p.match(stripped) for p in safe_line_patterns):
            continue
        # Skip lines that only have safe variable forms
        if safe_var_patterns.search(stripped) and not re.search(r"(?<!\{)\$\w", stripped):
            continue
        # Only flag lines with dangerous commands or direct command-line usage
        if not _has_unquoted_var(stripped):
            continue
        # Skip [[ ]] anywhere in the line (no word splitting)
        if "[[" in stripped and "]]" in stripped:
            continue
        # Skip [ ] test commands (integer comparisons, string tests)
        if re.search(r"\[\s.*\$\w.*\s\]", stripped):
            continue
        # Skip (( )) arithmetic
        if "((" in stripped and "))" in stripped:
            continue
        # Skip boolean variable as command: $VAR_NAME; or $VAR_NAME &&
        if re.match(r"^\s*\$\w+\s*[;&|]", stripped):
            continue
        # Skip lines where unquoted var is inside $() command substitution as argument
        if re.match(r'^\s*"?\$\(', stripped):
            continue
        # Skip lines that are predominantly quoted (heuristic: more " than unquoted $)
        # This catches cases like: mkdir -p "$(dirname "$plan_file")"
        dq_count = stripped.count('"')
        if dq_count >= 4:  # heavily quoted lines are likely safe
            continue
        # Skip array append: var+=(...)
        if re.match(r"^\s*\w+\+=", stripped):
            continue
        findings.append(
            Finding(
                rule_id="SHELL-002",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=i,
                line_content=line.rstrip(),
                message="Unquoted variable expansion may cause word splitting or globbing",
                cwe_id="CWE-78",
                fix_hint='Quote variables: "$VAR" instead of $VAR',
            )
        )
    return findings


def _has_unquoted_var(line: str) -> bool:
    """Check if a line has $VAR references outside double quotes.

    Skips safe forms: $?, $!, $#, $@, $*, $0-$9, ${#...}, ${...[@]}.
    """
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and not in_single:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "$" and not in_single and not in_double:
            if i + 1 < len(line):
                nxt = line[i + 1]
                # Skip special variables: $?, $!, $#, $@, $*, $0-$9
                if nxt in "?!#@*" or nxt.isdigit():
                    i += 2
                    continue
                # Skip ${#var}, ${var[@]}, ${var[*]}
                if nxt == "{":
                    brace_end = line.find("}", i + 2)
                    if brace_end != -1:
                        inner = line[i + 2 : brace_end]
                        if inner.startswith("#") or "[@]" in inner or "[*]" in inner:
                            i = brace_end + 1
                            continue
                # Regular variable — this is an unquoted var
                if nxt.isalpha() or nxt == "_":
                    return True
        i += 1
    return False


@register(
    id="SHELL-003",
    name="bash-c-string-interpolation",
    severity=Severity.HIGH,
    description="Detects bash -c with interpolated variables enabling injection",
    extensions=SHELL_EXTS,
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_003_bash_c_interpolation(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r'bash\s+-c\s+"[^"]*\$')
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SHELL-003",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="bash -c with string interpolation allows command injection",
                    cwe_id="CWE-78",
                    fix_hint="Pass variables as positional arguments: bash -c '...' _ \"$var\"",
                )
            )
    return findings


@register(
    id="SHELL-004",
    name="sed-replacement-injection",
    severity=Severity.MEDIUM,
    description="Detects user input in sed replacement strings",
    extensions=SHELL_EXTS,
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_004_sed_injection(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # sed with variable in replacement: sed "s/foo/$VAR/" or sed 's/foo/'"$VAR"'/'
    pattern = re.compile(r'\bsed\s+.*s[/|,].*\$\{?\w+')
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SHELL-004",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Variable in sed replacement can inject commands via delimiter characters",
                    cwe_id="CWE-78",
                    fix_hint="Escape delimiter in variable or use awk instead",
                )
            )
    return findings


@register(
    id="SHELL-005",
    name="json-printf-injection",
    severity=Severity.MEDIUM,
    description="Detects variables in printf JSON templates without escaping",
    extensions=SHELL_EXTS,
    cwe_id="CWE-116",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_005_json_printf(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # printf with JSON-like format string and %s
    pattern = re.compile(r"""printf\s+['"].*[{:].*%s""")
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SHELL-005",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="printf with JSON template and %s is vulnerable to JSON injection",
                    cwe_id="CWE-116",
                    fix_hint="Use jq to construct JSON safely",
                )
            )
    return findings


@register(
    id="SHELL-006",
    name="unquoted-github-output",
    severity=Severity.MEDIUM,
    description="Detects unquoted GITHUB_OUTPUT redirection",
    extensions=SHELL_EXTS + [".yml", ".yaml"],
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_006_unquoted_github_output(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r">>\s*\$GITHUB_OUTPUT\b")
    for i, line in enumerate(content.splitlines(), 1):
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SHELL-006",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Unquoted $GITHUB_OUTPUT can cause unexpected behavior",
                    cwe_id="CWE-78",
                    fix_hint='Quote the variable: >> "$GITHUB_OUTPUT"',
                )
            )
    return findings


@register(
    id="SHELL-007",
    name="mktemp-no-cleanup",
    severity=Severity.LOW,
    description="Detects mktemp usage without corresponding trap for cleanup",
    extensions=SHELL_EXTS,
    cwe_id="CWE-459",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_007_mktemp_no_cleanup(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    has_mktemp = False
    mktemp_line = 0
    mktemp_content = ""
    has_trap_exit = bool(re.search(r"\btrap\b.*\bEXIT\b", content))

    for i, line in enumerate(content.splitlines(), 1):
        if "mktemp" in line and not line.strip().startswith("#"):
            if not has_mktemp:
                has_mktemp = True
                mktemp_line = i
                mktemp_content = line.rstrip()

    if has_mktemp and not has_trap_exit:
        findings.append(
            Finding(
                rule_id="SHELL-007",
                severity=Severity.LOW,
                file_path=file_path,
                line_number=mktemp_line,
                line_content=mktemp_content,
                message="mktemp used without trap EXIT cleanup",
                cwe_id="CWE-459",
                fix_hint='Add: trap "rm -f $tmpfile" EXIT',
            )
        )
    return findings


@register(
    id="SHELL-008",
    name="missing-set-euo",
    severity=Severity.LOW,
    description="Detects shell scripts missing set -euo pipefail",
    extensions=SHELL_EXTS,
    cwe_id="CWE-754",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_008_missing_set_euo(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    # Only check files with shebangs (actual scripts)
    lines = content.splitlines()
    if not lines:
        return findings
    if not lines[0].startswith("#!"):
        return findings
    # Check first 10 lines for set -e or set -euo pipefail
    head = "\n".join(lines[:10])
    if not re.search(r"\bset\s+-[a-z]*e", head):
        findings.append(
            Finding(
                rule_id="SHELL-008",
                severity=Severity.LOW,
                file_path=file_path,
                line_number=1,
                line_content=lines[0].rstrip(),
                message="Shell script missing 'set -euo pipefail' for fail-safe execution",
                cwe_id="CWE-754",
                fix_hint="Add 'set -euo pipefail' near the top of the script",
            )
        )
    return findings


@register(
    id="SHELL-009",
    name="shell-true-subprocess",
    severity=Severity.HIGH,
    description="Detects Python subprocess calls with shell=True in shell scripts context",
    extensions=[".py"],
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1"],
)
def shell_009_shell_true_subprocess(
    file_path: Path, content: str, config: object = None
) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"\bsubprocess\.\w+\(.*shell\s*=\s*True", re.DOTALL
    )
    # Line-by-line for better location reporting
    line_pattern = re.compile(r"shell\s*=\s*True")
    in_subprocess = False
    for i, line in enumerate(content.splitlines(), 1):
        if "subprocess." in line:
            in_subprocess = True
        if in_subprocess and line_pattern.search(line):
            findings.append(
                Finding(
                    rule_id="SHELL-009",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="subprocess with shell=True allows shell injection",
                    cwe_id="CWE-78",
                    fix_hint="Use shell=False with a list of arguments instead",
                )
            )
            in_subprocess = False
        if line.strip().endswith(")"):
            in_subprocess = False
    return findings
