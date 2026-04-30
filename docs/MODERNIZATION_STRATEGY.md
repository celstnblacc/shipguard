# ShipGuard Modernization Strategy: 2026 Edition

## Overview
ShipGuard v0.3.3 is a robust pattern-matching tool, but it is architecturally "outdated" for the era of AI-native development. This strategy outlines the pivot from a "Dumb Regex Engine" to a **Semantic, AI-Orchestrated Security Framework**.

## The Core Shifts

### 1. From Regex to Semantic (AST-Aware)
**Current:** Matches strings like `eval(variable)` using regular expressions.  
**Modern:** Uses **Tree-sitter** (leveraging `tilth` logic) to understand the code structure. It distinguishes between a dangerous `eval()` call and a safe `eval` string in a comment or a localized variable name.

### 2. From "Detection" to "Remediation"
**Current:** Reports a vulnerability with a static "Fix Hint."  
**Modern:** Implements **Auto-Fix (L4 AI Layer)**. ShipGuard will generate a specific code patch (Diff/PR) using LLMs, verify it against the project's test suite, and present a "Verified Fix" to the developer.

### 3. From "Human UI" to "Agent/MCP Native"
**Current:** Rich terminal tables for human eyes.  
**Modern:** 
- **MCP Server:** Native integration for AI Agents (Claude Code, Cursor).
- **Token-Diet Output:** Optimized, compressed payloads for LLM context (leveraging `rtk` patterns).

### 4. Performance & Portability (The Rust Pivot)
**Current:** Python core with an optional Rust secret scanner.  
**Modern:** A unified **Rust Core Engine**. This ensures sub-100ms scans and seamless integration with high-performance workspace tools like `rtk` and `tilth`.

## Strategic Technology Stack
- **Engine:** Rust + Tree-sitter
- **AI Layer:** Model Context Protocol (MCP) + Claude 3.5/3.7/4.0
- **Ecosystem:** Unified wrappers for **Semgrep OSS**, **Trivy**, and **Gitleaks**.
- **CLI:** Optimized for both human developers and AI coding agents.

## Desired Outcome
ShipGuard becomes the **Security Brain** of the workspace—not just a scanner that runs in CI, but a real-time advisor that prevents vulnerabilities as they are written by both humans and AI.
