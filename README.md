# RepoSec

Reusable security audit tool for any repository. Scans shell scripts, Python, JavaScript/TypeScript, GitHub Actions workflows, and configuration files for **40 vulnerability patterns** across all 7 layers of a unified security pipeline.

## Install

### From PyPI

```bash
python -m pip install reposec
```

### Recommended: Using pipx (CLI tool)

```bash
pipx install git+https://github.com/celstnblacc/reposec.git
```

This installs RepoSec in an isolated environment with global command access.

### From source (development)

```bash
git clone https://github.com/celstnblacc/reposec.git
cd reposec
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### In a project (virtual environment)

```bash
python3.12 -m venv .venv && source .venv/bin/activate && pip install "git+https://github.com/celstnblacc/reposec.git"
```

### Install from GitHub (correct URL syntax)

```bash
pip install "git+https://github.com/celstnblacc/reposec.git"
```

You can pin to a branch/tag/commit:

```bash
pip install "git+https://github.com/celstnblacc/reposec.git@main"
pip install "git+https://github.com/celstnblacc/reposec.git@efbd130"
```

After install:

```bash
reposec --version
reposec scan .
```

If you open a new shell later:

```bash
source .venv/bin/activate && reposec --version
```

## Quick Start

```bash
# Scan current directory
reposec scan .

# Scan with JSON output (for CI pipelines)
reposec scan . --format json

# Optional: enable Rust-accelerated secrets scanning
reposec scan . --rust-secrets

# Only show critical and high findings
reposec scan . --severity high

# Generate markdown report (for PR comments)
reposec scan . --format markdown --output report.md

# List all 40 rules with descriptions
reposec list-rules

# Create a config file
reposec init
```

## 7-Layer Security Pipeline

RepoSec implements a **unified security model** across all 7 layers of the software development lifecycle:

| Layer | Focus | RepoSec Rules | External Tools |
|-------|-------|---------------|---|
| **L1: Dependencies** | Vulnerable packages | — | pip-audit, npm audit, osv-scanner |
| **L2: Secrets** | Credential exposure | SEC-001–003 (3) | gitleaks, detect-secrets |
| **L3: SAST** | Code vulnerabilities | 34 rules | ShellCheck, Bandit, ESLint |
| **L4: AI Reasoning** | Semantic analysis | — | Claude, GPT-4, human architects |
| **L5: DAST** | Runtime vulnerabilities | — | OWASP ZAP, Burp Suite |
| **L6: Supply Chain** | Build integrity | SC-001–003 (3) | Sigstore, Cosign |
| **L7: Observability** | Production monitoring | — | SIEM, Datadog, PagerDuty |

**See [docs/PIPELINE.md](./docs/PIPELINE.md) for complete framework details.**

---

## Rules (40 total)

| Category | Layer | Count | IDs | Examples |
|----------|-------|-------|-----|----------|
| Shell | L3 | 9 | SHELL-001–009 | eval injection, unquoted vars, bash -c interpolation |
| Python | L3 | 9 | PY-001–009 | zip slip, yaml.load, eval/exec, SQL injection |
| JavaScript | L3 | 8 | JS-001–008 | eval, path traversal, prototype pollution, XSS |
| GitHub Actions | L3 | 5 | GHA-001–005 | workflow injection, unpinned actions, secrets in logs |
| Config | L3 | 3 | CFG-001–003 | auto-approve, committed .env, permissive CORS |
| **Secrets** | **L2** | **3** | **SEC-001–003** | **AWS keys, GCP tokens, GitHub PATs** |
| **Supply Chain** | **L6** | **3** | **SC-001–003** | **Docker :latest, unpinned deps, npm lockfiles** |

Run `reposec list-rules` or `reposec list-rules --format json` for full details.

---

## Quick Start: Complete Security Pipeline

Run the full 7-layer pipeline locally:

```bash
# Install optional dependencies
pip install pip-audit bandit shellcheck-py

# Run all layers (1, 2, 3, 6 local; others require additional setup)
make security

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

Create `.reposec.yml` in your project root (or run `reposec init`):

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

RepoSec can offload `SEC-001`, `SEC-002`, and `SEC-003` scanning to a Rust binary while keeping the rest of the scanner in Python.

Build the optional binary:

```bash
cd rust/reposec-secrets
cargo build --release
```

Then either:

```bash
export REPOSEC_RUST_SECRETS_BIN="$PWD/target/release/reposec-secrets"
reposec scan . --rust-secrets
```

Or place `reposec-secrets` in your `PATH`.

## Inline Suppression

Suppress a finding on a specific line:

```python
eval(expr)  # reposec:ignore PY-003
```

Or on the line above:

```python
# reposec:ignore PY-003
eval(expr)
```

Multiple rules can be suppressed:

```bash
eval $cmd  # reposec:ignore SHELL-001, SHELL-002
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
  - repo: https://github.com/celstnblacc/reposec
    rev: main
    hooks:
      - id: reposec
```

### GitHub Action

```yaml
- uses: celstnblacc/reposec@main
  with:
    severity: medium
    format: terminal
```

### Generic CI

```bash
pip install reposec
reposec scan . --severity high --format json
# Exit code 1 if findings exist, 0 if clean
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the severity threshold |
| 1 | One or more findings detected |

## Suppression Comments

Both `#` and `//` comment styles are supported:

```python
# Python / Shell
eval(expr)  # reposec:ignore PY-003
```

```javascript
// JavaScript
eval(code);  // reposec:ignore JS-001
```

```bash
# Shell
eval $cmd  # reposec:ignore SHELL-001
```

Suppress multiple rules:
```bash
eval $cmd  # reposec:ignore SHELL-001, SHELL-002
```

## About This Project

RepoSec implements a **7-layer unified security framework** integrated into a single SAST tool. It was developed to package 40 security vulnerability patterns discovered during real-world audits of the [spec-kit](https://github.com/celstnblacc/spec-kit) and [superpowers](https://github.com/celstnblacc/superpowers) projects.

RepoSec provides:
- **Layer 3 (SAST)**: 34 rules across command injection, path traversal, code injection, and configuration issues
- **Layer 2 (Secrets)**: 3 rules detecting cloud provider credentials (AWS, GCP, GitHub)
- **Layer 6 (Supply Chain)**: 3 rules checking Docker image pinning and dependency versions
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
pipx list  # Should show reposec

# For venv installations
source .venv/bin/activate
which reposec  # Should show venv path
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
git clone https://github.com/celstnblacc/reposec.git
cd reposec
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Test the CLI
reposec scan tests/fixtures/
```

New rules should be added to `src/reposec/rules/` with the `@register` decorator:

```python
from reposec.models import Finding, Severity
from reposec.rules import register

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
