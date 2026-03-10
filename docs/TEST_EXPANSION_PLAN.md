# Test Expansion Plan

This document captures the next wave of tests to implement for RepoSec.
We will implement these one by one in the order listed.

## 1. Property-Based Tests (Implemented)
- Use `hypothesis` to fuzz scanner rule inputs (Shell/Python/JavaScript snippets).
- Validate no crashes, deterministic results, and no duplicate findings for identical `(rule_id, file_path, line_number)`.

## 2. Mutation Tests (Implemented, Env-Gated Harness)
- Use `mutmut` or `cosmic-ray` for rule logic and regex conditions.
- Goal: confirm tests fail when security logic is intentionally mutated.

## 3. Golden Snapshot Tests (Implemented)
- Create fixed expected outputs for `terminal`, `json`, and `markdown` formatter paths.
- Detect unintended output regressions through snapshot diffs.

## 4. CLI Contract Tests (Implemented)
- Assert exact exit codes and behavior for:
  - severity thresholds
  - empty scans
  - invalid format/config
  - output file mode

## 5. Performance Regression Tests (Implemented, Env-Gated)
- Scan synthetic large repositories (for example 10k+ files).
- Track and enforce runtime and memory budgets.

## 6. Concurrency and Race Tests (Implemented)
- Stress `ThreadPoolExecutor` scanning path with delays/failures.
- Verify stable behavior under concurrent workload and partial worker failures.

## 7. Config Compatibility Tests (Implemented)
- Validate `.reposec.yml` compatibility matrix:
  - missing keys
  - unknown keys
  - malformed YAML
  - backward-compatible defaults

## 8. End-to-End Mini-Repo Integration Tests (Implemented)
- Build temporary repositories with mixed languages and workflow files.
- Validate discovery, exclusions, and full scan behavior from CLI entrypoint.

## 9. Parser Robustness / Fuzz Tests (Implemented)
- Fuzz edge-case syntax in YAML/Shell/JS/Python inputs.
- Ensure scanner resilience and stable failure behavior (no crashes/panics).

## 10. Rust-Python Parity Tests (SEC-*) (Implemented, Binary-Optional)
- Run both secrets paths over the same corpus.
- Assert equivalent findings or explicitly document intentional differences.

## Run Commands
Run all standard tests:

```bash
PYTHONPATH=backend .venv/bin/pytest tests -q
```

Run with coverage:

```bash
PYTHONPATH=backend .venv/bin/pytest tests --cov=src/reposec --cov-report=term-missing -q
```

Update golden snapshots:

```bash
UPDATE_SNAPSHOTS=1 PYTHONPATH=backend .venv/bin/pytest tests/test_golden_snapshots.py -q
```

Run performance tests:

```bash
REPOSEC_RUN_PERF=1 PYTHONPATH=backend .venv/bin/pytest tests/test_performance_regression.py -q
```

Run mutation harness smoke:

```bash
REPOSEC_RUN_MUTATION=1 PYTHONPATH=backend .venv/bin/pytest tests/test_mutation_harness.py -q
```
