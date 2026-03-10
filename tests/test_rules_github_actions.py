"""Tests for GitHub Actions security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.github_actions import (
    gha_001_workflow_injection,
    gha_002_unpinned_action,
    gha_003_excessive_permissions,
    gha_004_secrets_in_log,
    gha_005_pr_target,
)

FIXTURES = Path(__file__).parent / "fixtures" / "github_actions"


class TestGHA001WorkflowInjection:
    def test_detects_injection_in_run(self):
        content = (
            "on:\n  issues:\njobs:\n  test:\n    steps:\n"
            '      - run: echo "${{ github.event.issue.title }}"'
        )
        findings = gha_001_workflow_injection(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_safe_expressions(self):
        content = (
            "on:\n  push:\njobs:\n  test:\n    steps:\n"
            "      - run: echo ${{ github.sha }}"
        )
        findings = gha_001_workflow_injection(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 0


class TestGHA002UnpinnedAction:
    def test_detects_branch_ref(self):
        content = "on: push\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@main"
        findings = gha_002_unpinned_action(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_sha_ref(self):
        content = (
            "on: push\njobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@0ad4b8fadaa221de15dcec353f45205ec38ea70b"
        )
        findings = gha_002_unpinned_action(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 0


class TestGHA003ExcessivePermissions:
    def test_detects_write_all(self):
        content = "on: push\npermissions: write-all\njobs:\n  test:\n    runs-on: ubuntu-latest"
        findings = gha_003_excessive_permissions(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 1

    def test_ignores_minimal_permissions(self):
        content = "on: push\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest"
        findings = gha_003_excessive_permissions(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 0


class TestGHA004SecretsInLog:
    def test_detects_echoed_secret(self):
        content = 'on: push\njobs:\n  test:\n    steps:\n      - run: echo "${{ secrets.TOKEN }}"'
        findings = gha_004_secrets_in_log(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 1


class TestGHA005PrTarget:
    def test_detects_pr_target_with_head_checkout(self):
        content = (
            "on:\n  pull_request_target:\njobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}"
        )
        findings = gha_005_pr_target(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 1

    def test_ignores_regular_pr(self):
        content = "on:\n  pull_request:\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4"
        findings = gha_005_pr_target(
            Path(".github/workflows/test.yml"), content
        )
        assert len(findings) == 0


class TestGHAFixtureFiles:
    def test_vulnerable_fixture(self, gha_fixtures):
        content = (gha_fixtures / "vulnerable.yml").read_text()
        path = Path(".github/workflows/vulnerable.yml")

        all_findings = []
        all_findings.extend(gha_001_workflow_injection(path, content))
        all_findings.extend(gha_002_unpinned_action(path, content))
        all_findings.extend(gha_003_excessive_permissions(path, content))
        all_findings.extend(gha_004_secrets_in_log(path, content))
        all_findings.extend(gha_005_pr_target(path, content))

        assert len(all_findings) >= 5

    def test_safe_fixture(self, gha_fixtures):
        content = (gha_fixtures / "safe.yml").read_text()
        path = Path(".github/workflows/safe.yml")

        findings = []
        findings.extend(gha_001_workflow_injection(path, content))
        findings.extend(gha_002_unpinned_action(path, content))
        findings.extend(gha_003_excessive_permissions(path, content))
        findings.extend(gha_004_secrets_in_log(path, content))
        findings.extend(gha_005_pr_target(path, content))

        assert len(findings) == 0
