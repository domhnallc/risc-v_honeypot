"""All shipped configs/*.yaml must actually load against the schema.

Nothing else exercises these files, so a typo or schema-field rename here
would otherwise only surface when someone tries to run the honeypot with
that exact config.
"""
from __future__ import annotations

from pathlib import Path

from honeypot.config import load_config

CONFIGS_DIR = Path(__file__).resolve().parent.parent / "configs"


def test_all_shipped_configs_load():
    paths = sorted(CONFIGS_DIR.glob("*.yaml"))
    assert paths, f"expected at least one config under {CONFIGS_DIR}"
    for path in paths:
        config = load_config(path)
        assert config.persona.arch in ("riscv32", "riscv64")


def test_training_config_is_localhost_only_and_inline():
    """The whole point of configs/training.yaml: it must never be reachable
    from anywhere but the machine running it, and never depend on a separate
    fetcher process."""
    config = load_config(CONFIGS_DIR / "training.yaml")
    assert config.listeners.bind_host == "127.0.0.1"
    assert config.fetcher.mode == "inline"
    assert config.credentials.accept_any is True


def test_docker_configs_use_queued_mode():
    """configs/*-docker.yaml back docker-compose.yml's two-container split --
    see test_session.py's queued-mode tests for why mode must be "queued"
    there specifically."""
    for name in ("riscv64-docker.yaml", "riscv32-docker.yaml"):
        config = load_config(CONFIGS_DIR / name)
        assert config.fetcher.mode == "queued"
