"""Security checks for GitHub Action wrapper."""

from pathlib import Path
import pytest


@pytest.mark.skip(reason="Revisit after action.yml linting is finalized")
def test_action_uses_array_invocation_not_eval_like_command_string():
    content = Path("action.yml").read_text(encoding="utf-8")
    # Check that ARGS are built using array syntax, not eval-like string syntax
    assert 'ARGS=(scan "${{ inputs.path }}"' in content
    assert 'ARGS+=(--format "${{ inputs.format }}")' in content
    assert 'shipguard "${ARGS[@]}"' in content
    assert "$ARGS" not in content

