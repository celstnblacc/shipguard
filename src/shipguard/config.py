"""Configuration system for ShipGuard using Pydantic."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

CONFIG_FILENAMES = [".shipguard.yml", ".shipguard.yaml", "shipguard.yml"]

DEFAULT_CONFIG_TEMPLATE = """\
# ShipGuard configuration
# See: https://github.com/DevOpsCelstn/shipguard

# Minimum severity to report: critical, high, medium, low
severity_threshold: medium

# Glob patterns for paths to exclude from scanning
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/fixtures/**"
  - "**/__snapshots__/**"

# Rule IDs to disable
disable_rules: []
  # - SHELL-008
  # - JS-007

# Additional directories containing custom rule modules
custom_rules_dirs: []

# Optional: use Rust-accelerated secrets scanning (SEC-001/002/003)
# Requires a built `shipguard-secrets` binary in PATH or SHIPGUARD_RUST_SECRETS_BIN.
use_rust_secrets: false
"""


class Config(BaseModel):
    """ShipGuard scan configuration."""

    severity_threshold: str = Field(default="medium")
    exclude_paths: list[str] = Field(default_factory=list)
    disable_rules: list[str] = Field(default_factory=list)
    custom_rules_dirs: list[str] = Field(default_factory=list)
    use_rust_secrets: bool = Field(default=False)


def find_config(target_dir: Path) -> Path | None:
    """Find config file in target directory."""
    for name in CONFIG_FILENAMES:
        path = target_dir / name
        if path.is_file():
            return path
    return None


def load_config(config_path: Path | None = None, target_dir: Path | None = None) -> Config:
    """Load configuration from file or return defaults.

    Args:
        config_path: Explicit path to config file.
        target_dir: Directory to search for config file.

    Returns:
        Config object with settings.
    """
    if config_path is None and target_dir is not None:
        config_path = find_config(target_dir)

    if config_path is not None and config_path.is_file():
        raw = yaml.safe_load(config_path.read_text()) or {}
        return Config(**raw)

    return Config()
