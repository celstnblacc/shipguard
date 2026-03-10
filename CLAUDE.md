# ShipGuard Project Guidelines for Claude Code

## Project Description

**ShipGuard** is a Python-based SAST (Static Application Security Testing) tool that implements a unified 7-layer security framework. It scans repositories for 40 security vulnerability patterns across Shell scripts, Python, JavaScript/TypeScript, GitHub Actions workflows, and configuration files.

**Key Features:**
- 40 built-in security rules across 7 layers
- Layer 3 (SAST): 34 core rules
- Layer 2 (Secrets): 3 credential detection rules
- Layer 6 (Supply Chain): 3 integrity checks
- CLI tool for scanning repositories
- Pre-commit hook integration
- GitHub Action integration
- Multiple output formats (terminal, JSON, markdown)

**Technology Stack:**
- Python 3.10+
- Typer (CLI framework)
- Rich (terminal formatting)
- PyYAML, Pydantic (config/data handling)
- pytest (testing framework)
- Hatchling (build system)

---

## Build Commands

ShipGuard uses Hatchling as the build system. Use these commands:

```bash
# Build the package (wheel)
python -m build
# or
hatch build

# Build in editable/development mode (recommended for development)
pip install -e .

# Build with dev dependencies
pip install -e ".[dev]"

# Clean build artifacts
rm -rf build/ dist/ *.egg-info __pycache__
```

---

## Test Commands

**Run all tests:**
```bash
PYTHONPATH=src pytest tests/ -v
```

**Run specific test file:**
```bash
PYTHONPATH=src pytest tests/test_cli.py -v
PYTHONPATH=src pytest tests/test_rules_secrets.py -v
PYTHONPATH=src pytest tests/test_rules_supply_chain.py -v
```

**Run with coverage:**
```bash
PYTHONPATH=src pytest tests/ --cov=src/shipguard --cov-report=html
```

**Run a specific test:**
```bash
PYTHONPATH=src pytest tests/test_cli.py::TestScanCommand::test_scan_finds_vulnerabilities -v
```

**Run tests matching a pattern:**
```bash
PYTHONPATH=src pytest tests/ -k "secrets" -v
```

> **Note:** `PYTHONPATH=src` ensures pytest loads rules from source rather than any stale installed package in site-packages. Alternatively, run `pip install -e .` once to install in editable mode and skip the prefix.

**Run quick smoke tests:**
```bash
pytest tests/test_cli.py::TestListRulesCommand -v
```

---

## Project Structure

```
shipguard/
├── src/shipguard/                    # Main package
│   ├── __init__.py
│   ├── cli.py                      # CLI entry point (Typer app)
│   ├── engine.py                   # Scan engine logic
│   ├── models.py                   # Data models (Finding, Severity, ScanResult)
│   ├── config.py                   # Configuration handling
│   ├── rules/                      # Security rules
│   │   ├── __init__.py             # Rule registry and loader
│   │   ├── config.py               # CFG rules
│   │   ├── github_actions.py       # GHA rules
│   │   ├── javascript.py           # JS rules
│   │   ├── python.py               # PY rules
│   │   ├── shell.py                # SHELL rules
│   │   ├── secrets.py              # SEC rules (NEW)
│   │   └── supply_chain.py         # SC rules (NEW)
│   └── formatters/                 # Output formatters
│       ├── terminal.py
│       ├── json.py
│       └── markdown.py
├── tests/                          # Test suite
│   ├── conftest.py                 # Pytest configuration
│   ├── test_cli.py                 # CLI tests
│   ├── test_rules_*.py             # Rule-specific tests
│   └── fixtures/                   # Test data
│       ├── shell/
│       ├── python/
│       ├── javascript/
│       ├── github_actions/
│       ├── config/
│       ├── secrets/                # (NEW)
│       └── supply_chain/           # (NEW)
├── docs/                           # Documentation (NEW)
│   ├── 7_LAYER_SECURITY_MODEL.md
│   ├── 7_LAYER_SECURITY_MODEL.html
│   └── PIPELINE.md
├── .github/
│   └── workflows/
│       ├── test.yml
│       └── security.yml            # (NEW)
├── .pre-commit-hooks.yaml          # Pre-commit hook definitions
├── .pre-commit-config.yaml.template # (NEW)
├── pyproject.toml                  # Project metadata and config
├── README.md                        # User documentation
├── CLAUDE.md                        # (THIS FILE)
├── IMPLEMENTATION_SUMMARY.md       # (NEW)
└── Makefile                        # (NEW)
```

---

## Development Conventions

### Code Style
- Follow PEP 8 for Python code
- Use type hints where applicable
- Use dataclasses for data structures
- Use descriptive variable and function names

### Rule Development
All security rules follow this pattern:

```python
from shipguard.models import Finding, Severity
from shipguard.rules import register

@register(
    id="CATEGORY-###",
    name="rule-short-name",
    severity=Severity.HIGH,
    description="What this rule detects",
    extensions=[".py"],
    cwe_id="CWE-XXX"
)
def rule_function(file_path: Path, content: str, config=None) -> list[Finding]:
    findings = []
    # Detection logic here
    return findings
```

**Rules must:**
- Return a list of `Finding` objects
- Handle edge cases (comments, false positives)
- Include fix hints in findings
- Map to relevant CWE IDs
- Support multiple file extensions where applicable

### Testing Conventions
- One test file per rule module (e.g., `test_rules_secrets.py`)
- Organize tests in classes by rule ID
- Include fixtures for vulnerable and safe examples
- Test normal cases, edge cases, and false positives
- Use descriptive test names: `test_{rule_id}_{what_it_tests}`

### Documentation
- Update README.md when adding/modifying rules
- Add docstrings to new functions
- Include examples in comments for complex logic
- Link to CWE definitions where appropriate

---

## Common Development Tasks

### Add a New Security Rule

1. **Choose a category** (shell.py, python.py, javascript.py, github_actions.py, config.py, secrets.py, or supply_chain.py)

2. **Implement the rule** using the @register decorator

3. **Create test fixtures** in `tests/fixtures/{category}/vulnerable.{ext}` and `tests/fixtures/{category}/safe.{ext}`

4. **Write tests** in `tests/test_rules_{category}.py`

5. **Update the rule count** in `tests/test_cli.py` (test_list_rules_json)

6. **Update README.md** with the new rule in the rules table

7. **Run tests** to ensure everything passes:
   ```bash
   pytest tests/test_rules_{category}.py -v
   pytest tests/test_cli.py::TestListRulesCommand -v
   ```

### Run the Full Security Pipeline Locally

```bash
make security         # Runs L1, L2, L3, L6
make security-l3      # Full SAST scan
make help             # See all available targets
```

### Test a Specific Vulnerability

```bash
# Scan just the fixtures
shipguard scan tests/fixtures/

# Scan with JSON output
shipguard scan tests/fixtures/ --format json

# Filter by severity
shipguard scan tests/fixtures/ --severity critical
```

### Update Documentation

- **Framework docs**: Edit `docs/7_LAYER_SECURITY_MODEL.md`
- **Quick reference**: Edit `docs/PIPELINE.md`
- **Interactive dashboard**: Edit `docs/7_LAYER_SECURITY_MODEL.html`
- **User guide**: Edit `README.md`

---

## Important Rules

### Before Committing

1. **Run tests**: `pytest tests/ -v` — All tests must pass
2. **Check syntax**: `python -m py_compile src/shipguard/**/*.py`
3. **Review rule counts**: `shipguard list-rules | wc -l` should match test expectations
4. **Verify no hardcoded secrets**: `grep -r "password\|api_key\|secret" src/ | grep -v "test\|example"`
5. **Update documentation** if adding/changing rules

### Security Exceptions for Test Fixtures

⚠️ **Important:** This is a security scanner tool. Test fixtures intentionally contain vulnerable code to verify ShipGuard detects security issues correctly.

**Test fixtures contain:**
- Unsafe `eval()` statements (PY-001)
- Insecure YAML loading (PY-002)
- Path traversal vulnerabilities (PY-003)
- Unsafe shell `eval` (SHELL-001)
- Unsafe eval in JavaScript (JS-001)
- Untrusted data in GitHub Actions (GHA-001)

**These are EXPECTED and necessary:**
- Located in `tests/fixtures/` — clearly marked as test data
- Used to verify ShipGuard detection works correctly
- Should NOT be fixed or removed
- ShipGuard correctly flags them as critical vulnerabilities

**During /ship pipeline:**
- ShipGuard will report vulnerabilities in `tests/fixtures/`
- This is expected behavior
- Proceed with commit despite critical findings in fixtures
- Production code in `src/shipguard/` should remain clean

### No Destructive Operations

- Never delete rules (only deprecate if necessary)
- Never change existing rule IDs
- Never modify `Severity` enum values
- Never change `Finding` or `ScanResult` field names
- Never use absolute paths (use relative or environment variables)
- Never hardcode usernames or personal paths

### Pre-commit Hook

Before each commit, this project runs:
- All tests (pytest)
- Syntax checks
- Security scans (ShipGuard)

If any fail, the commit is blocked. Fix the issues and try again.

---

## Troubleshooting

### "Module not found" errors
```bash
# Ensure you're in the right environment
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tests fail with import errors
```bash
# Reinstall in development mode
pip install -e . --force-reinstall
```

### Rule changes not reflecting
```bash
# Clear Python cache
find . -type d -name __pycache__ -exec rm -rf {} +
# Reinstall
pip install -e .
```

### Pre-commit hook issues
```bash
# Install hooks
pre-commit install
# Test all files
pre-commit run --all-files
```

---

## References

- **Main Project**: [ShipGuard on GitHub](https://github.com/celstnblacc/shipguard)
- **7-Layer Framework**: See `docs/7_LAYER_SECURITY_MODEL.md`
- **Pipeline Guide**: See `docs/PIPELINE.md`
- **Implementation Details**: See `IMPLEMENTATION_SUMMARY.md`
- **User Guide**: See `README.md`
- **Typer Docs**: https://typer.tiangolo.com/
- **CWE List**: https://cwe.mitre.org/

---

**Last Updated**: 2026-02-27
**Maintained By**: DevOpsCelstn
