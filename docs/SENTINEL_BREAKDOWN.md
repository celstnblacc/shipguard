# ShipGuard: The AI-Native Security Sentinel

ShipGuard has evolved from a pattern-matching scanner into an **AI-Native Security Sentinel**. This document breaks down the core architecture of the 2026 Modernization.

## 🧠 The Architecture of a Sentinel

### 1. The Semantic Cortex (Tree-sitter)
Traditional security tools use Regular Expressions (Regex), which are "blind" to code structure. ShipGuard uses **Tree-sitter** to build a full Abstract Syntax Tree (AST) of your code.
- **Why it matters:** It eliminates "noise." It knows the difference between a dangerous `eval()` call and the word "eval" inside a comment or a safe string literal.

### 2. The Reasoning Layer (L4 AI Triage)
Detection is only half the battle. ShipGuard integrates directly with LLMs (Claude/GPT) to perform **Reachability Analysis**.
- **The Process:** When a potential vulnerability is found, the Sentinel examines the surrounding functions. If the code is "dead" (unreachable) or safely sanitized, the AI triage layer auto-dismisses it.
- **Result:** You only see findings that represent real, exploitable risks.

### 3. The Self-Healing Limb (AutoFixer)
ShipGuard doesn't just find holes; it repairs them. The `shipguard fix` command uses AI to generate secure refactors.
- **Example:** It can rewrite a vulnerable `subprocess.run(shell=True)` into a safe, list-based execution, adding the necessary `import` statements and handling edge cases automatically.

### 4. The Nervous System (MCP & Agent-Native)
ShipGuard is built for a world of AI Agents. 
- **MCP Server:** It acts as a "security sense-organ" for other tools (Cursor, Claude Code, Gemini CLI).
- **Token-Diet:** The `--format agent` mode uses "Compressed Context" (inspired by RTK) to provide findings using 60% fewer tokens than standard output.

### 5. The High-Speed Core (Rust/PyO3)
To handle massive monorepos, the file-discovery and core-dispatch logic is written in **Rust**. This ensures that the "Brain" doesn't slow down your development loop.
