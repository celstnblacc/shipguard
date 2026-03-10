"""Tests for supply chain rules (SC-001 through SC-004)."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.supply_chain import (
    sc_001_docker_latest,
    sc_002_unpinned_python_dep,
    sc_003_npm_frozen_lockfile,
    sc_004_missing_gitignore_entries,
)

FIXTURES = Path(__file__).parent / "fixtures" / "supply_chain"


class TestSc001DockerLatest:
    def test_sc_001_detects_latest_ubuntu(self):
        """Test that SC-001 detects ubuntu:latest."""
        content = "FROM ubuntu:latest\nRUN apt-get update"
        path = Path("Dockerfile")
        findings = sc_001_docker_latest(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SC-001"
        assert findings[0].severity == Severity.HIGH

    def test_sc_001_detects_latest_python(self):
        """Test that SC-001 detects python:latest."""
        content = "FROM python:latest"
        path = Path("Dockerfile")
        findings = sc_001_docker_latest(path, content)
        assert len(findings) == 1

    def test_sc_001_skips_pinned_versions(self):
        """Test that SC-001 skips pinned versions."""
        content = "FROM ubuntu:22.04\nFROM python:3.12-slim"
        path = Path("Dockerfile")
        findings = sc_001_docker_latest(path, content)
        assert len(findings) == 0

    def test_sc_001_skips_comments(self):
        """Test that SC-001 skips commented FROM lines."""
        content = "# FROM ubuntu:latest"
        path = Path("Dockerfile")
        findings = sc_001_docker_latest(path, content)
        assert len(findings) == 0

    def test_sc_001_works_on_docker_compose(self):
        """Test that SC-001 works on docker-compose files."""
        content = """
services:
  app:
    image: ubuntu:latest
  db:
    image: postgres:15
"""
        path = Path("docker-compose.yml")
        findings = sc_001_docker_latest(path, content)
        # FROM pattern only - image: latest would be different
        assert len(findings) == 0


class TestSc002UnpinnedDep:
    def test_sc_002_detects_unpinned_requests(self):
        """Test that SC-002 detects unpinned requests package."""
        content = "requests\nflask==3.0.0"
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SC-002"
        assert findings[0].severity == Severity.MEDIUM
        assert "requests" in findings[0].line_content

    def test_sc_002_detects_multiple_unpinned(self):
        """Test that SC-002 detects multiple unpinned packages."""
        content = """requests
flask
numpy
pinned==1.0.0
"""
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 3

    def test_sc_002_skips_pinned_versions(self):
        """Test that SC-002 allows pinned versions."""
        content = "requests==2.31.0\nflask==3.0.0\nnumpy==1.26.0"
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 0

    def test_sc_002_skips_version_specifiers(self):
        """Test that SC-002 allows various version specifiers."""
        content = "requests>=2.31.0\nflask~=3.0\nnumpy<=1.26.0"
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 0

    def test_sc_002_skips_comments(self):
        """Test that SC-002 skips comment lines."""
        content = "# requests\nflask==3.0.0"
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 0

    def test_sc_002_skips_empty_lines(self):
        """Test that SC-002 skips blank lines."""
        content = "requests\n\nflask==3.0.0"
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 1

    def test_sc_002_skips_option_lines(self):
        """Test that SC-002 skips option lines."""
        content = "-r other.txt\n-i https://pypi.org/simple\nrequests"
        path = Path("requirements.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 1
        assert "requests" in findings[0].line_content

    def test_sc_002_only_checks_requirements_files(self):
        """Test that SC-002 only runs on requirements*.txt files."""
        content = "requests"
        path = Path("dependencies.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 0

        path = Path("requirements-dev.txt")
        findings = sc_002_unpinned_python_dep(path, content)
        assert len(findings) == 1


class TestSc003NpmFrozenLockfile:
    def test_sc_003_detects_npm_install_without_flags(self):
        """Test that SC-003 detects npm install without frozen-lockfile."""
        content = "npm install"
        path = Path("deploy.sh")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SC-003"
        assert findings[0].severity == Severity.MEDIUM

    def test_sc_003_allows_npm_with_frozen_lockfile(self):
        """Test that SC-003 allows npm install --frozen-lockfile."""
        content = "npm install --frozen-lockfile"
        path = Path("build.sh")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 0

    def test_sc_003_detects_pnpm_install_without_flags(self):
        """Test that SC-003 detects pnpm install without ci flag."""
        content = "pnpm install"
        path = Path("install.sh")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 1

    def test_sc_003_allows_pnpm_with_ci(self):
        """Test that SC-003 allows pnpm install --ci."""
        content = "pnpm install --ci"
        path = Path("ci.sh")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 0

    def test_sc_003_allows_pnpm_with_immutable(self):
        """Test that SC-003 allows pnpm install --immutable."""
        content = "pnpm install --immutable"
        path = Path("ci.yml")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 0

    def test_sc_003_detects_pnpm_i_without_flags(self):
        """Test that SC-003 detects pnpm i without flags."""
        content = "pnpm i"
        path = Path("install.sh")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 1

    def test_sc_003_skips_comments(self):
        """Test that SC-003 skips commented npm install."""
        content = "# npm install"
        path = Path("install.sh")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 0

    def test_sc_003_in_yaml_file(self):
        """Test that SC-003 works in YAML files."""
        content = """
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install
"""
        path = Path(".github/workflows/build.yml")
        findings = sc_003_npm_frozen_lockfile(path, content)
        assert len(findings) == 1


class TestSupplyChainFixtures:
    def test_vulnerable_dockerfile_fixtures(self):
        """Test that vulnerable dockerfile fixtures are detected."""
        vulnerable_file = FIXTURES / "vulnerable.dockerfile"
        if vulnerable_file.exists():
            content = vulnerable_file.read_text()
            findings = sc_001_docker_latest(vulnerable_file, content)
            assert len(findings) > 0

    def test_safe_dockerfile_fixtures(self):
        """Test that safe dockerfile fixtures pass."""
        safe_file = FIXTURES / "safe.dockerfile"
        if safe_file.exists():
            content = safe_file.read_text()
            findings = sc_001_docker_latest(safe_file, content)
            assert len(findings) == 0

    def test_vulnerable_requirements_fixtures(self):
        """Test that vulnerable requirements fixtures are detected."""
        vulnerable_file = FIXTURES / "requirements-vulnerable.txt"
        if vulnerable_file.exists():
            content = vulnerable_file.read_text()
            findings = sc_002_unpinned_python_dep(vulnerable_file, content)
            assert len(findings) > 0

    def test_safe_requirements_fixtures(self):
        """Test that safe requirements fixtures pass."""
        safe_file = FIXTURES / "requirements-safe.txt"
        if safe_file.exists():
            content = safe_file.read_text()
            findings = sc_002_unpinned_python_dep(safe_file, content)
            assert len(findings) == 0


class TestSc004MissingGitignoreEntries:
    def test_sc_004_detects_missing_env_entry(self):
        """Test that SC-004 flags a .gitignore missing .env."""
        content = "node_modules/\ndist/\n*.log"
        path = Path(".gitignore")
        findings = sc_004_missing_gitignore_entries(path, content)
        assert len(findings) == 1
        assert findings[0].rule_id == "SC-004"
        assert findings[0].severity == Severity.HIGH
        assert ".env" in findings[0].message

    def test_sc_004_passes_complete_gitignore(self):
        """Test that SC-004 passes when all required entries are present."""
        content = "node_modules/\n.env\n*.env.*\n*.key\n*.pem\n*.p12\n*.pfx\n"
        path = Path(".gitignore")
        findings = sc_004_missing_gitignore_entries(path, content)
        assert len(findings) == 0

    def test_sc_004_skips_non_gitignore_files(self):
        """Test that SC-004 only runs on .gitignore files."""
        content = "node_modules/"
        path = Path("somefile.txt")
        findings = sc_004_missing_gitignore_entries(path, content)
        assert len(findings) == 0

    def test_sc_004_accepts_wildcard_env(self):
        """Test that .env.* counts as covering .env entries."""
        content = ".env\n.env.*\n*.key\n*.pem\n*.p12\n*.pfx"
        path = Path(".gitignore")
        findings = sc_004_missing_gitignore_entries(path, content)
        assert len(findings) == 0
