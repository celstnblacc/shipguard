# ShipGuard

Reusable security audit tool for any repository. Scans shell scripts, Python, JavaScript/TypeScript, GitHub Actions workflows, and configuration files for **48 vulnerability patterns** across all 7 layers of a unified security pipeline.

## Install

### From PyPI

```bash
python -m pip install shipguard
```

### Recommended: Using pipx (CLI tool)

```bash
pipx install git+https://github.com/celstnblacc/shipguard.git
```

This installs ShipGuard in an isolated environment with global command access.

### From source (development)

```bash
git clone https://github.com/celstnblacc/shipguard.git
cd shipguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### In a project (virtual environment)

```bash
python3.12 -m venv .venv && source .venv/bin/activate && pip install "git+https://github.com/celstnblacc/shipguard.git"
```

### Install from GitHub (correct URL syntax)

```bash
pip install "git+https://github.com/celstnblacc/shipguard.git"
```

You can pin to a branch/tag/commit:

```bash
pip install "git+https://github.com/celstnblacc/shipguard.git@main"
pip install "git+https://github.com/celstnblacc/shipguard.git@efbd130"
```

After install:

```bash
shipguard --version
shipguard scan .
```

Verify you are using the expected binary:

```bash
which shipguard
shipguard scan --help
```

If you open a new shell later:

```bash
source .venv/bin/activate && shipguard --version
```

## Quick Start

```bash
# Scan current directory
shipguard scan .

# Scan another repository by absolute path
shipguard scan /path/to/target-repo

# Scan with JSON output (for CI pipelines)
shipguard scan . --format json

# Scan another repository and save JSON report
shipguard scan /path/to/target-repo --format json --output /tmp/target-repo-shipguard.json

# Optional: enable Rust-accelerated secrets scanning
shipguard scan . --rust-secrets

# Only show critical and high findings
shipguard scan . --severity high

# Only show high+ findings for another repository
shipguard scan /path/to/target-repo --severity high

# Generate markdown report (for PR comments)
shipguard scan . --format markdown --output report.md

# List all 48 rules with descriptions
shipguard list-rules

# Include only selected rules
shipguard scan . --include-rules PY-003,SEC-001

# Exclude noisy rules for a run
shipguard scan . --exclude-rules JS-008,PY-009

# Create a config file
shipguard init

# Create a config file in another repository
shipguard init /path/to/target-repo
```

## Development Staging Bootstrap (Go-Live)

Use the helper script to create a local staging target for `go-live`/`infra-probe` verification:

```bash
# Start local staging and wait for health
./scripts/go_live_staging.sh up

# Show status
./scripts/go_live_staging.sh status

# Tear down cleanly
./scripts/go_live_staging.sh down
```

This workflow uses `docker-compose.staging.yml` and `.env.staging` (auto-copied from `.env.staging.example` if missing).

### Release Rollback Runbook

Rollback trigger criteria:

- New `critical` or `high` finding in post-release scan
- PyPI installation failure for latest tag
- CLI regression in critical path (`shipguard scan`, `shipguard list-rules`)

Rollback steps:

1. Stop promotion and notify the on-call release owner.
2. Repoint users to the previous stable release tag in release notes.
3. Cut a patch release from `main` with the fix and rerun:
   - `pytest tests -q`
   - `shipguard scan . --format terminal`
4. Publish patched tag using `.github/workflows/release.yml`.

Ownership:

- Primary: repository maintainers listed in `SECURITY.md`
- Escalation: GitHub issue with `release-blocker` label and incident summary


## 7-Layer Security Pipeline

ShipGuard implements a **unified security model** across all 7 layers of the software development lifecycle:

| Layer | Focus | ShipGuard Rules | External Tools |
|-------|-------|---------------|---|
| **L1: Dependencies** | Vulnerable packages | — | pip-audit, npm audit, osv-scanner |
| **L2: Secrets** | Credential exposure | SEC-001–010 (10) | gitleaks, detect-secrets |
| **L3: SAST** | Code vulnerabilities | 34 rules | ShellCheck, Bandit, ESLint |
| **L4: AI Reasoning** | Semantic analysis | — | Claude, GPT-4, human architects |
| **L5: DAST** | Runtime vulnerabilities | — | OWASP ZAP, Burp Suite |
| **L6: Supply Chain** | Build integrity | SC-001–004 (4) | Sigstore, Cosign |
| **L7: Observability** | Production monitoring | — | SIEM, Datadog, PagerDuty |

**See [docs/PIPELINE.md](./docs/PIPELINE.md) for complete framework details.**

---

## Rules (48 total)

| Category | Layer | Count | IDs | Examples |
|----------|-------|-------|-----|----------|
| Shell | L3 | 9 | SHELL-001–009 | eval injection, unquoted vars, bash -c interpolation |
| Python | L3 | 9 | PY-001–009 | zip slip, yaml.load, eval/exec, SQL injection |
| JavaScript | L3 | 8 | JS-001–008 | eval, path traversal, prototype pollution, XSS |
| GitHub Actions | L3 | 5 | GHA-001–005 | workflow injection, unpinned actions, secrets in logs |
| Config | L3 | 3 | CFG-001–003 | auto-approve, committed .env, permissive CORS |
| **Secrets** | **L2** | **10** | **SEC-001–010** | **Cloud/API tokens and other hardcoded secret patterns** |
| **Supply Chain** | **L6** | **4** | **SC-001–004** | **Docker :latest, unpinned deps, npm lockfiles, missing .gitignore entries** |

Run `shipguard list-rules` or `shipguard list-rules --format json` for full details.

---

## Quick Start: Complete Security Pipeline

Run the full 7-layer pipeline locally:

```bash
# Install optional dependencies
pip install pip-audit bandit shellcheck-py

# Run all layers (1, 2, 3, 6 local; others require additional setup)
make security

# Run strict blocking gate (fails on high+ findings)
make security-strict

# Or run individual layers
make security-l1   # Dependencies
make security-l2   # Secrets
make security-l3   # SAST
make security-l6   # Supply Chain

# For CI/CD, use GitHub Actions workflow
# See .github/workflows/security.yml
```

---

## Configuration

Create `.shipguard.yml` in your project root (or run `shipguard init`):

```yaml
# Minimum severity to report: critical, high, medium, low
severity_threshold: medium

# Glob patterns for paths to exclude
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/fixtures/**"

# Rule IDs to disable
disable_rules:
  - SHELL-008

# Additional directories containing custom rule modules
custom_rules_dirs: []
```

CLI flags override config file values.

### Optional Rust Acceleration (Secrets)

ShipGuard can offload `SEC-001`, `SEC-002`, and `SEC-003` scanning to a Rust binary while keeping the rest of the scanner in Python.

Build the optional binary:

```bash
cd rust/shipguard-secrets
cargo build --release
```

Then either:

```bash
export SHIPGUARD_RUST_SECRETS_BIN="$PWD/target/release/shipguard-secrets"
shipguard scan . --rust-secrets
```

Or place `shipguard-secrets` in your `PATH`.

## Inline Suppression

Suppress a finding on a specific line:

```python
eval(expr)  # shipguard:ignore PY-003
```

Or on the line above:

```python
# shipguard:ignore PY-003
eval(expr)
```

Multiple rules can be suppressed:

```bash
eval $cmd  # shipguard:ignore SHELL-001, SHELL-002
```

## Output Formats

- **terminal** (default) — Rich color-coded table with severity highlighting and fix hints
- **json** — Machine-readable `{"findings": [...], "summary": {...}}` for CI integration
- **markdown** — Report grouped by severity level, suitable for PR comments

## CI Integration

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/celstnblacc/shipguard
    rev: main
    hooks:
      - id: shipguard
```

### GitHub Action

```yaml
- uses: celstnblacc/shipguard@main
  with:
    severity: medium
    format: terminal
```

### Generic CI

```bash
pip install shipguard
shipguard scan . --severity high --format json
# Exit code 1 if findings exist, 0 if clean
```

## Release Runbook (PyPI Trusted Publishing)

Use this checklist for each release:

1. Prepare version + changelog
- Update package version and append the release notes in `CHANGELOG.md`.

2. Confirm GitHub workflow + environment
- Workflow file: `.github/workflows/publish.yml`
- Required workflow name: `publish.yml`
- Required job environment: `pypi`
- Workflow publishes on tag pushes matching `v*`.

3. Configure PyPI trusted publisher (one-time or when repo changes)
- URL: `https://pypi.org/manage/project/shipguard/settings/publishing/`
- Owner: `newblacc`
- Repository: `shipguard`
- Workflow: `publish.yml`
- Environment: `pypi`

4. Create and push release tag
```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

5. If publish failed before OIDC setup
- Open GitHub Actions and re-run the failed `publish.yml` run for the same tag after trusted publisher configuration is saved.

6. Post-publish smoke test
```bash
python -m pip install -U shipguard
shipguard --version
shipguard scan . --severity high
```

7. Verify release
- Confirm the new version is visible on PyPI and installable in a clean environment.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the severity threshold |
| 1 | One or more findings detected |

## Suppression Comments

Both `#` and `//` comment styles are supported:

```python
# Python / Shell
eval(expr)  # shipguard:ignore PY-003
```

```javascript
// JavaScript
eval(code);  // shipguard:ignore JS-001
```

```bash
# Shell
eval $cmd  # shipguard:ignore SHELL-001
```

Suppress multiple rules:
```bash
eval $cmd  # shipguard:ignore SHELL-001, SHELL-002
```

## About This Project

ShipGuard implements a **7-layer unified security framework** integrated into a single SAST tool. It was developed to package 48 security vulnerability patterns discovered during real-world audits of the [spec-kit](https://github.com/celstnblacc/spec-kit) and [superpowers](https://github.com/celstnblacc/superpowers) projects.

ShipGuard provides:
- **Layer 3 (SAST)**: 34 rules across command injection, path traversal, code injection, and configuration issues
- **Layer 2 (Secrets)**: 10 rules detecting cloud/API credentials and token patterns
- **Layer 6 (Supply Chain)**: 4 rules checking Docker image pinning, dependency pinning, and `.gitignore` secret baselines
- **Integration**: GitHub Actions workflow, pre-commit hooks, local Makefile targets

**See [docs/7_LAYER_SECURITY_MODEL.md](./docs/7_LAYER_SECURITY_MODEL.md) for the complete security framework.**

The rules focus on:
- **Command injection**: eval, exec, bash -c, sed, printf with unquoted variables
- **Path traversal**: Unvalidated path.join(), symlink following
- **Code/data injection**: YAML unsafe load, pickle, SQL string formatting
- **Secrets**: AWS/GCP keys, GitHub tokens, hardcoded credentials
- **Supply chain**: Docker :latest tags, unpinned dependencies, npm lockfile verification
- **Configuration**: Committed .env files, overly permissive CORS, auto-approve settings

## Troubleshooting

### "Module not found" errors

If you get import errors, ensure you're in the correct environment:

```bash
# For pipx installations
pipx list  # Should show shipguard

# For venv installations
source .venv/bin/activate
which shipguard  # Should show venv path
```

### Pre-commit hook not running

Ensure `.pre-commit-hooks.yaml` is in the correct location and hooks are configured:

```bash
pre-commit install
pre-commit run --all-files  # Test manually
```

## Development

To contribute or modify rules:

```bash
git clone https://github.com/celstnblacc/shipguard.git
cd shipguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Test the CLI
shipguard scan tests/fixtures/
```

New rules should be added to `src/shipguard/rules/` with the `@register` decorator:

```python
from shipguard.models import Finding, Severity
from shipguard.rules import register

@register(
    id="RULE-001",
    name="rule-description",
    severity=Severity.HIGH,
    description="What this rule detects",
    extensions=[".py"],
    cwe_id="CWE-123"
)
def rule_001_check(file_path, content, config=None):
    findings = []
    # Detection logic here
    return findings
```

## License

MIT
