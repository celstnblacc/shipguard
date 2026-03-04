"""Additional tests for config branch coverage."""

from pathlib import Path

from reposec.config import find_config, load_config


def test_find_config_returns_first_existing_file(tmp_path):
    cfg = tmp_path / ".reposec.yml"
    cfg.write_text("severity_threshold: high\n")
    found = find_config(tmp_path)
    assert found == cfg


def test_load_config_reads_yaml_values(tmp_path):
    cfg = tmp_path / ".reposec.yml"
    cfg.write_text("severity_threshold: critical\nuse_rust_secrets: true\n")
    loaded = load_config(config_path=cfg)
    assert loaded.severity_threshold == "critical"
    assert loaded.use_rust_secrets is True


def test_load_config_falls_back_to_defaults_for_missing_file(tmp_path):
    loaded = load_config(config_path=tmp_path / "missing.yml")
    assert loaded.severity_threshold == "medium"
