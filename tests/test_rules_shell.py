"""Tests for shell security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.shell import (
    _has_unquoted_var,
    shell_001_eval_injection,
    shell_002_unquoted_variable,
    shell_003_bash_c_interpolation,
    shell_004_sed_injection,
    shell_005_json_printf,
    shell_006_unquoted_github_output,
    shell_007_mktemp_no_cleanup,
    shell_008_missing_set_euo,
    shell_009_shell_true_subprocess,
)

FIXTURES = Path(__file__).parent / "fixtures" / "shell"


class TestShell001EvalInjection:
    def test_detects_eval_with_command_sub(self):
        content = 'eval $(get_input)\neval "$(get_data)"'
        findings = shell_001_eval_injection(Path("test.sh"), content)
        assert len(findings) == 2
        assert all(f.rule_id == "SHELL-001" for f in findings)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    def test_ignores_comments(self):
        content = "# eval $(something)"
        findings = shell_001_eval_injection(Path("test.sh"), content)
        assert len(findings) == 0

    def test_ignores_safe_code(self):
        content = "echo hello\nls -la"
        findings = shell_001_eval_injection(Path("test.sh"), content)
        assert len(findings) == 0


class TestShell003BashC:
    def test_detects_bash_c_interpolation(self):
        content = 'bash -c "echo $user_data"'
        findings = shell_003_bash_c_interpolation(Path("test.sh"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_safe_bash_c(self):
        content = "bash -c 'echo hello'"
        findings = shell_003_bash_c_interpolation(Path("test.sh"), content)
        assert len(findings) == 0


class TestShell002UnquotedVariable:
    def test_skips_safe_braced_length_expansion(self):
        content = 'echo ${#name}'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_double_bracket_condition(self):
        content = 'echo [[ $x ]]'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_single_bracket_condition(self):
        content = 'echo [ $x ]'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_arithmetic_condition(self):
        content = 'echo (( $x ))'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_boolean_variable_command(self):
        content = '$flag && echo ok'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_command_substitution_argument(self):
        content = '$(echo ok) $x'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_heavily_quoted_line(self):
        content = 'mkdir -p "$(dirname "$plan_file")" "$target"'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0

    def test_skips_array_append(self):
        content = 'args+=($name)'
        findings = shell_002_unquoted_variable(Path("test.sh"), content)
        assert len(findings) == 0


class TestHasUnquotedVar:
    def test_skips_escaped_dollar(self):
        assert _has_unquoted_var(r'echo \$HOME') is False

    def test_skips_special_var_and_digit(self):
        assert _has_unquoted_var('echo $? $1') is False

    def test_skips_braced_special_forms(self):
        assert _has_unquoted_var('echo ${#x} ${arr[@]} ${arr[*]}') is False


class TestShell004Sed:
    def test_detects_sed_variable(self):
        content = 'sed "s/old/$user_input/g" file.txt'
        findings = shell_004_sed_injection(Path("test.sh"), content)
        assert len(findings) == 1

    def test_ignores_safe_sed(self):
        content = "sed 's/old/new/g' file.txt"
        findings = shell_004_sed_injection(Path("test.sh"), content)
        assert len(findings) == 0


class TestShell005JsonPrintf:
    def test_detects_printf_json(self):
        content = """printf '{"name":"%s"}' "$name" """
        findings = shell_005_json_printf(Path("test.sh"), content)
        assert len(findings) == 1

    def test_ignores_safe_printf(self):
        content = 'printf "Hello %s" "$name"'
        findings = shell_005_json_printf(Path("test.sh"), content)
        assert len(findings) == 0


class TestShell006GithubOutput:
    def test_detects_unquoted(self):
        content = "echo 'val=1' >> $GITHUB_OUTPUT"
        findings = shell_006_unquoted_github_output(Path("test.sh"), content)
        assert len(findings) == 1

    def test_ignores_quoted(self):
        content = 'echo "val=1" >> "$GITHUB_OUTPUT"'
        findings = shell_006_unquoted_github_output(Path("test.sh"), content)
        assert len(findings) == 0


class TestShell007Mktemp:
    def test_detects_mktemp_without_trap(self):
        content = "#!/bin/bash\ntmpfile=$(mktemp)\necho data > $tmpfile"
        findings = shell_007_mktemp_no_cleanup(Path("test.sh"), content)
        assert len(findings) == 1

    def test_ignores_mktemp_with_trap(self):
        content = '#!/bin/bash\ntmpfile=$(mktemp)\ntrap "rm -f $tmpfile" EXIT'
        findings = shell_007_mktemp_no_cleanup(Path("test.sh"), content)
        assert len(findings) == 0


class TestShell008SetEuo:
    def test_detects_missing_set_e(self):
        content = "#!/bin/bash\necho hello"
        findings = shell_008_missing_set_euo(Path("test.sh"), content)
        assert len(findings) == 1

    def test_ignores_script_with_set_e(self):
        content = "#!/bin/bash\nset -euo pipefail\necho hello"
        findings = shell_008_missing_set_euo(Path("test.sh"), content)
        assert len(findings) == 0

    def test_ignores_non_script(self):
        content = "echo hello"
        findings = shell_008_missing_set_euo(Path("test.sh"), content)
        assert len(findings) == 0

    def test_ignores_empty_content(self):
        findings = shell_008_missing_set_euo(Path("test.sh"), "")
        assert len(findings) == 0


class TestShell009SubprocessShell:
    def test_detects_shell_true(self):
        content = 'import subprocess\nsubprocess.run("ls", shell=True)'
        findings = shell_009_shell_true_subprocess(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_shell_false(self):
        content = 'import subprocess\nsubprocess.run(["ls"], shell=False)'
        findings = shell_009_shell_true_subprocess(Path("test.py"), content)
        assert len(findings) == 0


class TestShellFixtureFiles:
    def test_vulnerable_fixture(self, shell_fixtures):
        content = (shell_fixtures / "vulnerable.sh").read_text()
        path = shell_fixtures / "vulnerable.sh"

        all_findings = []
        all_findings.extend(shell_001_eval_injection(path, content))
        all_findings.extend(shell_003_bash_c_interpolation(path, content))
        all_findings.extend(shell_004_sed_injection(path, content))
        all_findings.extend(shell_005_json_printf(path, content))
        all_findings.extend(shell_006_unquoted_github_output(path, content))
        all_findings.extend(shell_007_mktemp_no_cleanup(path, content))
        all_findings.extend(shell_008_missing_set_euo(path, content))

        assert len(all_findings) >= 7

    def test_safe_fixture(self, shell_fixtures):
        content = (shell_fixtures / "safe.sh").read_text()
        path = shell_fixtures / "safe.sh"

        findings = []
        findings.extend(shell_001_eval_injection(path, content))
        findings.extend(shell_003_bash_c_interpolation(path, content))
        findings.extend(shell_006_unquoted_github_output(path, content))
        findings.extend(shell_007_mktemp_no_cleanup(path, content))
        findings.extend(shell_008_missing_set_euo(path, content))

        assert len(findings) == 0
