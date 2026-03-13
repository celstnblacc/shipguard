# ShipGuard — Full Project Review

**Date:** 2026-03-10
**Reviewer:** Claude (requested by Rocha)
**Version reviewed:** 0.3.0 (pyproject.toml) / 0.2.0 (CHANGELOG)

---

## Executive Summary

ShipGuard is a well-architected Python SAST tool with **48 security rules** across 7 categories. The codebase is clean, well-tested, and production-ready — but suffers from documentation drift and a handful of broken Makefile targets. Fixing those issues would make this an excellent open-source security tool.

**Verdict:** Solid foundation. Needs a documentation pass and a few CLI/Makefile fixes before the next release.

---

## What Works Well

### Architecture
The codebase follows clean separation of concerns: models, engine, rules, formatters, and CLI are all independent modules. The `@register` decorator pattern for rules is elegant and extensible — adding a new rule is straightforward and self-documenting.

### Rule Quality (48 rules total)
The rules are the heart of the project and they're well-implemented:

| Category | Count | Quality Notes |
|---|---|---|
| SHELL | 9 | Highest quality. SHELL-002 has sophisticated safe-context detection |
| Python | 9 | Strong. PY-001 checks for validation within 10 lines of context |
| JavaScript | 8 | Good coverage of XSS, prototype pollution, ReDoS |
| GitHub Actions | 5 | Handles workflow injection, unpinned actions, secret leaks |
| Config | 3 | Covers CORS, .env commits, auto-approve |
| Secrets | 10 | Excellent false-positive handling (placeholders, env vars, templates) |
| Supply Chain | 4 | Docker :latest, unpinned deps, missing .gitignore entries |

The secrets rules deserve special praise — they detect placeholders like `YOUR_*`, `CHANGE_ME`, environment variable references, and template syntax to reduce noise.

### Testing
27 test files with fixture pairs (vulnerable + safe) for every rule category. Golden snapshot tests, concurrency tests, and property-based tests (Hypothesis) show engineering maturity. The test infrastructure in conftest.py is clean.

### CI/CD & Tooling
Full pipeline: GitHub Actions for testing, security scanning, and PyPI publishing. Pre-commit hooks, a GitHub Action (`action.yml`), and a comprehensive Makefile round out the developer experience.

### Scanning Engine
Parallel scanning via ThreadPoolExecutor, `.gitignore`-aware file discovery, inline suppression (`# shipguard:ignore RULE-ID`), and smart deduplication (e.g., SHELL-009 vs PY-005 overlap) show production-level thinking.

---

## Issues Found

### Critical — Fix Before Next Release

**1. Rule Count Discrepancy**
Documentation (README, CLAUDE.md, IMPLEMENTATION_SUMMARY) claims **40 rules**. Actual count is **48** (10 SEC + 4 SC, not the documented 3+3). The test suite correctly expects 48 — so the code is right, the docs are wrong.

**2. Version Mismatch**
- `pyproject.toml` says `0.3.0`
- `__init__.py` says `0.2.0`
- `CHANGELOG.md` latest entry is `0.2.0`

Either add a 0.3.0 changelog entry or align pyproject.toml back to 0.2.0.

**3. Makefile Broken Targets**
Several Makefile targets use flags that don't exist in the CLI:
- `--rules SEC-001,SEC-002,...` — no `--rules` flag exists
- `--format text` — valid formats are `terminal`, `json`, `markdown`

These targets will fail silently or error out.

**4. Pre-commit Template Uses Old Name**
`.pre-commit-config.yaml.template` still references `shipguard` (the old project name) instead of `shipguard` throughout. Also references a non-existent `shipguard-precommit.yml`.

### Medium — Should Fix

**5. Missing CLI Rule Filtering**
The Makefile assumes a `--rules` flag exists. Adding `--include-rules` / `--exclude-rules` to the CLI would be a natural enhancement and would make the Makefile targets work.

**6. Rust Binary Undocumented**
`rust_secrets.py` integrates with an optional Rust binary for faster secrets scanning. The `rust/` directory has a Cargo.toml. But neither the README nor CLAUDE.md explain how to build it or when to use it.

**7. File Extension Rigidity**
Some rules check exact filenames (`Dockerfile`, `docker-compose.yml`) but miss common variations like `Dockerfile.staging`, `docker-compose.prod.yml`, or lowercase `dockerfile`.

### Low — Nice to Have

**8. No CLI `--version` Flag**
`shipguard --version` isn't implemented — common expectation for CLI tools.

**9. No Coverage Badges**
README could benefit from pytest coverage and PyPI version badges.

**10. Custom Rules Documentation**
The config supports `custom_rules_dirs` but there's no guide on how to write and register custom rules beyond reading the source.

---

## Architecture Diagram

```
CLI (Typer)
  │
  ├── scan ──► Engine ──► Rules Registry ──► [48 rules]
  │              │              │
  │              │              ├── shell.py (9)
  │              │              ├── python.py (9)
  │              │              ├── javascript.py (8)
  │              │              ├── github_actions.py (5)
  │              │              ├── config.py (3)
  │              │              ├── secrets.py (10)
  │              │              └── supply_chain.py (4)
  │              │
  │              ├── File Discovery (.gitignore-aware)
  │              ├── ThreadPoolExecutor (parallel scan)
  │              ├── Inline Suppression (# shipguard:ignore)
  │              └── Deduplication
  │
  ├── Formatters
  │     ├── terminal.py (Rich tables)
  │     ├── json_fmt.py (machine-readable)
  │     └── markdown.py (PR comments)
  │
  ├── list-rules
  └── init ──► .shipguard.yml template
```

---

## File Inventory

### Source (~2,100 LOC)

| File | LOC | Purpose |
|---|---|---|
| `cli.py` | ~150 | Typer CLI: scan, list-rules, init |
| `engine.py` | ~160 | Parallel scanning, file discovery, suppression |
| `models.py` | ~100 | Finding, ScanResult, Severity dataclasses |
| `config.py` | ~90 | Pydantic config from .shipguard.yml |
| `rust_secrets.py` | ~80 | Optional Rust binary integration |
| `rules/__init__.py` | ~120 | @register decorator, rule registry |
| `rules/shell.py` | ~424 | 9 shell rules |
| `rules/python.py` | ~342 | 9 Python rules |
| `rules/javascript.py` | ~321 | 8 JS rules |
| `rules/secrets.py` | ~315 | 10 secrets rules |
| `rules/github_actions.py` | ~206 | 5 GHA rules |
| `rules/supply_chain.py` | ~168 | 4 supply chain rules |
| `rules/config.py` | ~126 | 3 config rules |
| `formatters/` | ~240 | Terminal, JSON, Markdown output |

### Tests (27 files)
Comprehensive coverage across all rule categories, CLI commands, engine behavior, golden snapshots, concurrency, and property-based testing.

### Documentation
README.md, CHANGELOG.md, CLAUDE.md, IMPLEMENTATION_SUMMARY.md, plus `docs/` with the 7-layer model guide, pipeline reference, and an interactive HTML dashboard.

### CI/CD
4 GitHub Actions workflows (test, security, publish, release), pre-commit hooks, Makefile with layer-specific targets.

---

## Recommended Action Plan

### Phase 1 — Documentation Alignment (30 min)
1. Update rule count from 40 → 48 everywhere
2. Align version across pyproject.toml, __init__.py, CHANGELOG
3. Replace "shipguard" → "shipguard" in pre-commit template

### Phase 2 — Fix Broken Tooling (1-2 hrs)
4. Fix Makefile: remove `--rules` flag, change `--format text` → `--format terminal`
5. Add `--include-rules` / `--exclude-rules` CLI flags (then Makefile targets work)
6. Add `--version` flag to CLI

### Phase 3 — Polish (optional, 2-3 hrs)
7. Document the Rust binary build process
8. Expand file extension matching for Docker rules
9. Write a custom rules guide
10. Add coverage badges to README

---

## Final Assessment

ShipGuard is a **well-built security tool** with real production value. The rule implementations are thorough (especially secrets detection with false-positive suppression), the architecture is clean and extensible, and the testing is comprehensive. The main debt is documentation drift — the code has outgrown its docs in several places. A focused documentation pass plus fixing the Makefile would bring everything into alignment for a clean 0.3.0 release.
