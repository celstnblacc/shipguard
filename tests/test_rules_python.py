"""Tests for Python security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.python import (
    py_001_zip_traversal,
    py_002_yaml_unsafe,
    py_003_eval_exec,
    py_004_startswith_path,
    py_005_subprocess_shell,
    py_006_hardcoded_secrets,
    py_007_sql_injection,
    py_008_pickle_load,
    py_009_tempfile_mktemp,
)

FIXTURES = Path(__file__).parent / "fixtures" / "python"


class TestPY001ZipTraversal:
    def test_detects_extractall(self):
        content = "import zipfile\nwith zipfile.ZipFile(f) as zf:\n    zf.extractall('/tmp')"
        findings = py_001_zip_traversal(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_safe_code(self):
        content = "import json\ndata = json.load(f)"
        findings = py_001_zip_traversal(Path("test.py"), content)
        assert len(findings) == 0


class TestPY002YamlUnsafe:
    def test_detects_unsafe_load(self):
        content = "import yaml\nyaml.load(data)"
        findings = py_002_yaml_unsafe(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_safe_load(self):
        content = "yaml.safe_load(data)"
        findings = py_002_yaml_unsafe(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_load_with_safe_loader(self):
        content = "yaml.load(data, Loader=yaml.SafeLoader)"
        findings = py_002_yaml_unsafe(Path("test.py"), content)
        assert len(findings) == 0


class TestPY003EvalExec:
    def test_detects_eval(self):
        content = "result = eval(user_input)"
        findings = py_003_eval_exec(Path("test.py"), content)
        assert len(findings) == 1

    def test_detects_exec(self):
        content = "exec(code_string)"
        findings = py_003_eval_exec(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_comments(self):
        content = "# eval(something)"
        findings = py_003_eval_exec(Path("test.py"), content)
        assert len(findings) == 0


class TestPY004StartswithPath:
    def test_detects_startswith_path(self):
        content = 'if str(filepath).startswith("/safe/dir"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_non_path_startswith(self):
        content = 'if name.startswith("prefix"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 0


class TestPY005SubprocessShell:
    def test_detects_shell_true(self):
        content = "import subprocess\nsubprocess.run(cmd, shell=True)"
        findings = py_005_subprocess_shell(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_shell_false(self):
        content = 'subprocess.run(["ls"], shell=False)'
        findings = py_005_subprocess_shell(Path("test.py"), content)
        assert len(findings) == 0


class TestPY006HardcodedSecrets:
    def test_detects_api_key(self):
        content = 'api_key = "sk-live-abcdefghijklmnopqrstuvwx"'
        findings = py_006_hardcoded_secrets(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_placeholder(self):
        content = 'api_key = "your-api-key-here"'
        findings = py_006_hardcoded_secrets(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_env_var(self):
        content = 'api_key = os.environ["API_KEY"]'
        findings = py_006_hardcoded_secrets(Path("test.py"), content)
        assert len(findings) == 0


class TestPY007SqlInjection:
    def test_detects_fstring_sql(self):
        content = 'query = f"SELECT * FROM users WHERE name = \'{name}\'"'
        findings = py_007_sql_injection(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_parameterized(self):
        content = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'
        findings = py_007_sql_injection(Path("test.py"), content)
        assert len(findings) == 0


class TestPY008PickleLoad:
    def test_detects_pickle_load(self):
        content = "data = pickle.load(f)"
        findings = py_008_pickle_load(Path("test.py"), content)
        assert len(findings) == 1

    def test_detects_pickle_loads(self):
        content = "data = pickle.loads(raw)"
        findings = py_008_pickle_load(Path("test.py"), content)
        assert len(findings) == 1


class TestPY009TempfileMktemp:
    def test_detects_mktemp(self):
        content = "path = tempfile.mktemp()"
        findings = py_009_tempfile_mktemp(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_mkstemp(self):
        content = "fd, path = tempfile.mkstemp()"
        findings = py_009_tempfile_mktemp(Path("test.py"), content)
        assert len(findings) == 0


class TestPythonFixtureFiles:
    def test_vulnerable_fixture(self, python_fixtures):
        content = (python_fixtures / "vulnerable.py").read_text()
        path = python_fixtures / "vulnerable.py"

        all_findings = []
        all_findings.extend(py_001_zip_traversal(path, content))
        all_findings.extend(py_002_yaml_unsafe(path, content))
        all_findings.extend(py_003_eval_exec(path, content))
        all_findings.extend(py_004_startswith_path(path, content))
        all_findings.extend(py_005_subprocess_shell(path, content))
        all_findings.extend(py_006_hardcoded_secrets(path, content))
        all_findings.extend(py_007_sql_injection(path, content))
        all_findings.extend(py_008_pickle_load(path, content))
        all_findings.extend(py_009_tempfile_mktemp(path, content))

        assert len(all_findings) >= 9

    def test_safe_fixture(self, python_fixtures):
        content = (python_fixtures / "safe.py").read_text()
        path = python_fixtures / "safe.py"

        findings = []
        findings.extend(py_001_zip_traversal(path, content))
        findings.extend(py_002_yaml_unsafe(path, content))
        findings.extend(py_003_eval_exec(path, content))
        findings.extend(py_005_subprocess_shell(path, content))
        findings.extend(py_007_sql_injection(path, content))
        findings.extend(py_008_pickle_load(path, content))
        findings.extend(py_009_tempfile_mktemp(path, content))

        assert len(findings) == 0
