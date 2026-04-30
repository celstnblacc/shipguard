# ShipGuard: Path to Production (v1.0)

This document outlines the gaps between ShipGuard's current "Sentinel" state and an enterprise-grade security platform, along with the roadmap to bridge them.

## 📊 Gap Analysis

| Feature | Current (Sentinel) | Production Target | Priority |
| :--- | :--- | :--- | :--- |
| **State** | Stateless (Scans from scratch) | Persistent (Vulnerability lifecycle tracking) | High |
| **Scope** | Single-file AST | Cross-file Call Graph (Inter-procedural) | High |
| **Verification** | Blind Patching (Fix applies, then scan) | Functionality Verification (Run tests before apply) | Med |
| **UX** | CLI / MCP | IDE Integration / Dashboard / Reporting | Med |
| **Policy** | Basic Exclusions | OPA/Rego-based Governance | Low |

---

## 🛠️ The Roadmap

### Phase 1: The Persistence Layer (SQLite)
Implement a project-local database (`.shipguard/state.db`) to track findings. 
- **Goal:** Distinguish between "New," "Acknowledged," and "Fixed" findings. 
- **Benefit:** Prevent "Finding Fatigue" by hiding already triaged issues.

### Phase 2: The Flow (Cross-file Analysis)
Expand the Rust core and `SemanticEngine` to build a project-wide symbol index.
- **Goal:** Determine if an input from one file reaches a dangerous sink in another.
- **Benefit:** Drastic reduction in false positives for complex applications.

### Phase 3: The Verification Loop
Integrate the `fix` command with the project's test suite.
- **Goal:** `Find -> Fix -> Run pytest -> Rollback if Fail`.
- **Benefit:** "Guaranteed" safe remediation that won't break the build.

### Phase 4: The Ecosystem
Harden the MCP server and provide standardized SARIF/JSON outputs for CI/CD dashboards.
- **Goal:** Full integration with Cursor, VS Code, and major CI providers (GHA, GitLab).
- **Benefit:** Seamless developer adoption.
