# ShipGuard: Sentinel FAQ

### Q: What is the "AI-Native Security Brain"?
**A:** It refers to ShipGuard's ability to use LLMs for **reasoning** (triage) and **action** (fixing) rather than just simple pattern matching. It behaves like a sentinel that understands the "intent" of your code.

### Q: Should I install this on my MacBook?
**A:** Yes. If you are a developer, having the ShipGuard Sentinel running locally means you catch vulnerabilities *before* they ever reach the CI/CD pipeline. It is already integrated with your `/ship` and `/gauntlet` commands in the Gemini CLI.

### Q: How does the AI Triage work?
**A:** When you run `shipguard scan --ai-triage`, high-severity findings are sent to an LLM with the context of the entire file. The AI determines if the finding is a "False Positive" (e.g., unreachable code). If it is, the finding is hidden from your report.

### Q: Does it use a lot of tokens?
**A:** No. We implemented a **"Token-Diet"** format (`--format agent`). This strips away all UI fluff and terminal tables, providing a highly compressed data stream designed specifically for AI-to-AI communication.

### Q: Can it fix my code automatically?
**A:** Yes. Use `shipguard fix --id RULE-ID --apply`. The Sentinel will generate a patch, verify its syntax, and overwrite the vulnerable code with a secure version. Always review changes before committing.

### Q: How do I add it to my AI Agent (Cursor/Claude Desktop)?
**A:** Add `shipguard-mcp` as an MCP server. Your agent will then be able to call `shipguard_scan` and `shipguard_fix` as native tools during your chat session.
