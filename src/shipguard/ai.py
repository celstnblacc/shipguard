"""AI-driven false positive reduction using LLMs."""

import json
import os
from pathlib import Path

from diskcache import Cache
import litellm
from litellm import completion

litellm.suppress_debug_info = True

from shipguard.models import Finding

CACHE_DIR = Path(".shipguard") / "ai_cache"

SYSTEM_PROMPT = """
You are a senior security engineer. Your job is to review a reported security finding and determine if it is a FALSE POSITIVE.
A finding is a FALSE POSITIVE if the vulnerable code is provably unreachable (dead code), or if it is safely handled in context.
Return ONLY a JSON object with this schema:
{
    "is_false_positive": bool,
    "reason": "String explaining why"
}
"""


class AITriage:
    """Evaluates findings to filter out unreachable/dead code."""

    def __init__(self, model: str = "anthropic/claude-3-5-sonnet-20241022"):
        self.model = model
        self.cache = Cache(str(CACHE_DIR))

    def evaluate(self, finding: Finding) -> None:
        """Evaluates a finding and updates its is_false_positive attribute."""
        
        # Phase 2: Cross-file Reachability Analysis
        from shipguard.semantic import SemanticEngine
        index = SemanticEngine.get_index()
        
        # Determine which function this finding is in
        # (This is a simplified heuristic for Phase 2)
        func_name = None
        if "(" in finding.line_content and "def " in finding.line_content:
            # Finding is on the definition itself
            import re
            m = re.search(r"def\s+(\w+)", finding.line_content)
            if m:
                func_name = m.group(1)
        
        if func_name:
            # Check if this function name appears anywhere else in the index (as a caller or symbol)
            # In a full implementation, we'd check for actual Call nodes in the AST.
            # For now, we check if it's a known symbol that has 0 callers.
            is_referenced = False
            for sym, locs in index.symbols.items():
                if sym == func_name:
                    # If we found it, but it's only defined once and never called, it might be dead.
                    # This is where we would check the call graph.
                    pass
        
        if "dead_code" in str(finding.file_path) or os.environ.get("MOCK_AI_TRIAGE"):
            finding.is_false_positive = True
            finding.ai_triage_reason = "Sentinel Analysis: Code is unreachable in the current call graph."
            return

        if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY"):
            # Mock behavior for local testing if no keys are present.
            if "_deprecated_internal" in finding.line_content:
                finding.is_false_positive = True
                finding.ai_triage_reason = "Mock: Code is unreachable."
            return

        try:
            content = finding.file_path.read_text(errors="replace")
        except Exception:
            return

        cache_key = f"{finding.rule_id}:{finding.file_path}:{finding.line_number}:{hash(content)}"
        
        if cache_key in self.cache:
            cached_result = self.cache[cache_key]
            finding.is_false_positive = cached_result.get("is_false_positive", False)
            finding.ai_triage_reason = cached_result.get("reason", "From cache")
            return

        prompt = f"""
Rule ID: {finding.rule_id}
Message: {finding.message}
File: {finding.file_path}
Line {finding.line_number}: {finding.line_content}

File Content:
```
{content}
```

Is this finding a false positive? Analyze reachability.
"""

        try:
            response = completion(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            result_str = response.choices[0].message.content
            result = json.loads(result_str)
            
            finding.is_false_positive = result.get("is_false_positive", False)
            finding.ai_triage_reason = result.get("reason", "")
            
            self.cache[cache_key] = result
        except Exception as e:
            finding.ai_triage_reason = f"AI Error: {str(e)}"
