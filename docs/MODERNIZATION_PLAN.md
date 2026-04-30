# ShipGuard Modernization: Iterative TDD Plan

This plan follows a **RED → GREEN → REFACTOR** cycle for every iteration to ensure the modernization does not break existing security guarantees.

## Iteration 1: Semantic Core (The Tree-sitter Bridge)
**Goal:** Replace the first 5 Python regex rules with AST-aware rules.
- [x] **RED:** Create a test fixture with "Safe vs. Vulnerable" code that tricks regex but shouldn't trick an AST.
- [x] **ACT:** Integrate `tree-sitter-python` and `tree-sitter-javascript`.
- [x] **GREEN:** Implement `shipguard scan --engine semantic` to correctly identify the fixtures.
- [x] **REFACTOR:** Abstract the `Rule` model to support both `RegexStrategy` and `ASTStrategy`.

## Iteration 2: AI Triage Layer (L4 Integration)
**Goal:** Use LLMs to reduce false positives through "Reachability Analysis."
- [x] **RED:** Define a test case where a vulnerability exists in "Dead Code" (unreferenced function).
- [x] **ACT:** Implement an LLM connector that sends finding context + file outline (via `tilth`) to Claude.
- [x] **GREEN:** ShipGuard auto-dismisses the finding with an "Unreachable" label.
- [x] **REFACTOR:** Cache AI decisions in `.shipguard/ai_cache.db` to save tokens.

## Iteration 3: Auto-Remediation (Self-Healing)
**Goal:** Implement `shipguard fix`.
- [x] **RED:** Create a failing test that checks if a specific `eval()` finding is fixed in the source file.
- [x] **ACT:** Implement `Fixer` class that generates code patches using LLMs.
- [x] **GREEN:** `shipguard fix --id PY-003` successfully replaces vulnerable code and passes tests.
- [x] **REFACTOR:** Add safety checks (Dry-run by default, syntax validation of the patch).

## Iteration 4: Agent Optimization (MCP & RTK)
**Goal:** Make ShipGuard the best security tool for AI Agents.
- [x] **RED:** Test the output token count for a 50-finding scan (target: >60% reduction).
- [x] **ACT:** Implement `shipguard_mcp` server and `--format agent` (RTK-style compression).
- [x] **GREEN:** Successfully run an audit via Claude Code using the MCP tool.
- [x] **REFACTOR:** Standardize JSON/SARIF schemas for cross-agent compatibility.

## Iteration 5: The Rust Unification
**Goal:** Move the core engine to Rust for speed.
- [x] **RED:** Benchmark 10,000 files; target < 500ms.
- [x] **ACT:** Port rule-dispatch and file-walking to Rust (matching `tilth`/`rtk` architecture).
- [x] **GREEN:** `shipguard-rust` passes the full Python parity test suite.
- [x] **REFACTOR:** Package as a single binary with PyO3 bindings for Python backward compatibility.
