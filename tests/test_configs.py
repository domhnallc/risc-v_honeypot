"""All shipped configs/*.yaml must actually load against the schema.

Nothing else exercises these files, so a typo or schema-field rename here
would otherwise only surface when someone tries to run the honeypot with
that exact config.
"""
from __future__ import annotations

from pathlib import Path

import yaml

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


def test_docker_configs_keep_the_ssh_host_key_on_a_mounted_volume():
    """A host key inside the container is regenerated on every rebuild, so an
    attacker sees the "device" change fingerprint. The key path in each docker
    config must sit under a directory docker-compose.yml bind-mounts from the
    host into the honeypot service -- this fails if either side is edited alone."""
    compose = yaml.safe_load((CONFIGS_DIR.parent / "docker-compose.yml").read_text())
    mounted = {v.split(":")[1].rstrip("/") for v in compose["services"]["honeypot"]["volumes"]}
    for path in sorted(CONFIGS_DIR.glob("*-docker.yaml")):
        key_path = load_config(path).listeners.ssh_host_key_path
        container_dir = "/app/" + str(key_path.parent)
        assert container_dir in mounted, f"{path.name}: {key_path} is not under a mounted volume {sorted(mounted)}"


def test_host_key_directory_is_gitignored():
    """Private keys must never be committable."""
    ignore = (CONFIGS_DIR.parent / ".gitignore").read_text().splitlines()
    assert "var/keys/" in ignore
