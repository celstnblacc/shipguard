"""Config compatibility and error-path tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from reposec.config import load_config


def test_config_missing_keys_uses_defaults(tmp_path):
    cfg = tmp_path / ".reposec.yml"
    cfg.write_text("disable_rules: [PY-003]\n")
    loaded = load_config(config_path=cfg)
    assert loaded.severity_threshold == "medium"
    assert loaded.disable_rules == ["PY-003"]
    assert loaded.use_rust_secrets is False


def test_config_unknown_keys_are_ignored(tmp_path):
    cfg = tmp_path / ".reposec.yml"
    cfg.write_text("severity_threshold: high\nunknown_key: value\n")
    loaded = load_config(config_path=cfg)
    assert loaded.severity_threshold == "high"
    assert not hasattr(loaded, "unknown_key")


def test_config_malformed_yaml_raises(tmp_path):
    cfg = tmp_path / ".reposec.yml"
    cfg.write_text("severity_threshold: [broken\n")
    with pytest.raises(yaml.YAMLError):
        load_config(config_path=cfg)


def test_config_empty_yaml_falls_back_to_defaults(tmp_path):
    cfg = tmp_path / ".reposec.yml"
    cfg.write_text("")
    loaded = load_config(config_path=cfg)
    assert loaded.severity_threshold == "medium"
