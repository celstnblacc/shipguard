"""Parser robustness/fuzz-style tests for rule functions."""

from __future__ import annotations

import random
import string
from pathlib import Path

from reposec.rules.github_actions import gha_001_workflow_injection
from reposec.rules.javascript import js_001_eval
from reposec.rules.python import py_003_eval_exec
from reposec.rules.secrets import sec_003_github_token
from reposec.rules.shell import shell_001_eval_injection


def _random_line(rng: random.Random, length: int = 80) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation + " \t"
    return "".join(rng.choice(alphabet) for _ in range(length))


def test_rules_do_not_crash_on_random_inputs():
    rng = random.Random(1337)
    for _ in range(200):
        content = "\n".join(_random_line(rng, rng.randint(0, 120)) for _ in range(rng.randint(0, 8)))
        assert isinstance(shell_001_eval_injection(Path("x.sh"), content), list)
        assert isinstance(py_003_eval_exec(Path("x.py"), content), list)
        assert isinstance(js_001_eval(Path("x.js"), content), list)
        assert isinstance(gha_001_workflow_injection(Path("x.yml"), content), list)
        assert isinstance(sec_003_github_token(Path("x.yml"), content), list)
