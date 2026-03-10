"""Shared test fixtures for ShipGuard tests."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def shell_fixtures() -> Path:
    return FIXTURES_DIR / "shell"


@pytest.fixture
def python_fixtures() -> Path:
    return FIXTURES_DIR / "python"


@pytest.fixture
def js_fixtures() -> Path:
    return FIXTURES_DIR / "javascript"


@pytest.fixture
def gha_fixtures() -> Path:
    return FIXTURES_DIR / "github_actions"


@pytest.fixture
def config_fixtures() -> Path:
    return FIXTURES_DIR / "config"
