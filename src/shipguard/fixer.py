"""Auto-Remediation engine for generating and applying code patches via LLMs."""

import json
import os
from pathlib import Path

from litellm import completion

from shipguard.models import Finding

FIXER_PROMPT = """
You are a senior security engineer. You are given a file and a specific vulnerability finding.
Your task is to fix the vulnerability by rewriting the code.
Return ONLY a JSON object with this schema:
{
    "fixed_content": "The COMPLETE content of the file after applying the fix."
}
Make sure the fixed code is syntactically valid and idiomatic.
"""


class AutoFixer:
    """Generates and applies fixes for security findings."""

    def __init__(self, model: str = "anthropic/claude-3-5-sonnet-20241022"):
        self.model = model

    def fix(self, finding: Finding, apply: bool = False) -> bool:
        """Generates a fix for the finding and optionally applies it."""
        try:
            content = finding.file_path.read_text(errors="replace")
        except Exception:
            return False

        if os.environ.get("MOCK_AI_FIXER"):
            # Mock behavior for testing
            fixed_content = "import ast\n" + content.replace("eval(", "ast.literal_eval(")
        else:
            prompt = f"""
Rule ID: {finding.rule_id}
Message: {finding.message}
File: {finding.file_path}
Line {finding.line_number}: {finding.line_content}

File Content:
```
{content}
```

Fix the vulnerability and provide the complete file content.
"""
            try:
                response = completion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": FIXER_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                result = json.loads(response.choices[0].message.content)
                fixed_content = result.get("fixed_content", content)
            except Exception as e:
                print(f"[shipguard] AI fix generation failed: {e}")
                return False

        if apply and fixed_content != content:
            finding.file_path.write_text(fixed_content)
            return True
        elif not apply and fixed_content != content:
            print(f"[Dry Run] Proposed fix for {finding.file_path} (Line {finding.line_number})")
            # In a full implementation, we might output a unified diff here
            return True
        return False
