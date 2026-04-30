"""Model Context Protocol (MCP) server for ShipGuard."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from shipguard.config import load_config
from shipguard.engine import scan
from shipguard.formatters.agent import format_agent
from shipguard.fixer import AutoFixer
from shipguard.rules import load_builtin_rules

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shipguard_mcp")

# Initialize FastMCP server
mcp = FastMCP("shipguard", dependencies=["shipguard"])

@mcp.tool()
def shipguard_scan(path: str, severity: str = "medium", ai_triage: bool = False, rules: Optional[str] = None) -> str:
    """
    Run a ShipGuard security scan on a directory.
    Returns findings in a compressed 'agent' format optimized for tokens.
    
    Args:
        path: The directory path to scan.
        severity: Minimum severity (critical, high, medium, low).
        ai_triage: Enable AI-driven false positive reduction.
        rules: Comma-separated rule IDs to include.
    """
    target_path = Path(path).resolve()
    if not target_path.is_dir():
        return f"Error: Path '{path}' is not a directory."

    load_builtin_rules()
    config = load_config(target_dir=target_path)
    config.ai_triage = ai_triage
    
    include_rules = None
    if rules:
        include_rules = {r.strip().upper() for r in rules.split(",")}

    from shipguard.models import Severity
    try:
        threshold = Severity(severity.lower())
    except ValueError:
        return f"Error: Invalid severity '{severity}'."

    result = scan(
        target_dir=target_path,
        config=config,
        severity_threshold=threshold,
        include_rules=include_rules
    )

    return format_agent(result)


@mcp.tool()
def shipguard_fix(path: str, rule_id: str, apply: bool = True) -> str:
    """
    Automatically generate and apply AI fixes for vulnerabilities.
    
    Args:
        path: The directory path to scan and fix.
        rule_id: The specific Rule ID to target (e.g., 'PY-003').
        apply: If True, writes fixes to disk. If False, does a dry run.
    """
    target_path = Path(path).resolve()
    if not target_path.is_dir():
        return f"Error: Path '{path}' is not a directory."

    load_builtin_rules()
    config = load_config(target_dir=target_path)
    
    result = scan(
        target_dir=target_path,
        config=config,
        include_rules={rule_id.upper()}
    )
    
    if not result.findings:
        return f"No findings found for {rule_id}."
        
    fixer = AutoFixer()
    fixed_count = 0
    for finding in result.findings:
        if fixer.fix(finding, apply=apply):
            fixed_count += 1
            
    if apply:
        return f"Fixed {fixed_count} finding(s) for {rule_id}."
    else:
        return f"Dry run completed. {fixed_count} finding(s) can be fixed."


def main():
    """Entry point for the MCP server."""
    mcp.run()

if __name__ == "__main__":
    main()
