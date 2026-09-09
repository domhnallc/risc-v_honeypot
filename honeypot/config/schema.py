"""Validated configuration schema for the honeypot (spec sec 4.7).

Config is loaded from YAML and validated through pydantic so that a malformed
or incomplete config fails fast at startup rather than producing an
inconsistent persona at runtime.
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

Arch = Literal["riscv32", "riscv64"]


class Credential(BaseModel):
    username: str
    password: str


class ListenerConfig(BaseModel):
    bind_host: str = "0.0.0.0"
    ssh_enabled: bool = True
    ssh_port: int = 2222
    telnet_enabled: bool = True
    telnet_port: int = 2223
    # Generated on first run if missing (honeypot/listeners/ssh.py). Kept
    # config-driven so separate configs (e.g. configs/training.yaml) don't
    # silently share a host key with each other or with a real deployment.
    ssh_host_key_path: Path = Path("var/ssh_host_key")


class PersonaConfig(BaseModel):
    """Everything needed to render a self-consistent fake RISC-V device."""

    arch: Arch
    hostname: str = "buildroot"
    kernel_version: str = "5.10.0"
    isa: str = "rv64imafdc"
    uarch: str = "sifive,u74-mc"
    mmu: str = "sv39"
    hart_count: int = 4
    os_release_name: str = "Buildroot"
    os_release_version: str = "2023.02"
    ssh_banner: str = "SiFive RISC-V Linux (buildroot)"
    telnet_banner: str = "SiFive RISC-V Linux (buildroot)\nlogin: "

    @field_validator("hart_count")
    @classmethod
    def _positive_hart_count(cls, v: int) -> int:
        if v < 1:
            raise ValueError("hart_count must be >= 1")
        return v


class CredentialPolicy(BaseModel):
    """Which username/password pairs the fake login accepts.

    accept_any=True maximizes capture of credential-stuffing attempts (spec
    4.1); accept_any=False restricts acceptance to `allow_list`.
    """

    accept_any: bool = True
    allow_list: list[Credential] = Field(default_factory=list)

    def accepts(self, username: str, password: str) -> bool:
        if self.accept_any:
            return True
        return any(
            c.username == username and c.password == password
            for c in self.allow_list
        )


class FetcherConfig(BaseModel):
    quarantine_dir: Path = Path("var/quarantine")
    jobs_dir: Path = Path("var/jobs")
    max_file_size_bytes: int = 50 * 1024 * 1024
    timeout_seconds: float = 15.0
    allowed_protocols: list[str] = Field(default_factory=lambda: ["http", "https"])
    verify_tls: bool = False
    # "inline": SessionManager awaits fetch_and_quarantine() directly -- fine
    # for a single-process/single-container deployment (default).
    # "queued": SessionManager only enqueues a job and polls for the result a
    # separate `honeypot.fetcher.worker` process writes -- required whenever
    # the fetcher actually runs as a different process/container, since that
    # is the only mode that never performs the outbound fetch from the
    # session-handling side (see docker-compose.yml).
    mode: Literal["inline", "queued"] = "inline"


class LoggingConfig(BaseModel):
    log_dir: Path = Path("var/logs")
    transcript_dir: Path = Path("var/transcripts")
    json_log_filename: str = "events.jsonl"
    level: str = "INFO"
    forward_url: str | None = None


class HoneypotConfig(BaseModel):
    persona: PersonaConfig
    listeners: ListenerConfig = Field(default_factory=ListenerConfig)
    credentials: CredentialPolicy = Field(default_factory=CredentialPolicy)
    fetcher: FetcherConfig = Field(default_factory=FetcherConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)


def load_config(path: str | Path) -> HoneypotConfig:
    """Load and validate a YAML config file into a HoneypotConfig.

    Uses yaml.safe_load: config files are operator-controlled, not attacker
    input, but safe_load is used throughout regardless (no reason to allow
    arbitrary YAML tags anywhere in this codebase).
    """
    raw = yaml.safe_load(Path(path).read_text())
    return HoneypotConfig.model_validate(raw or {})
