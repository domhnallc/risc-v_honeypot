"""Validated configuration schema for the honeypot (spec sec 4.7).

Config is loaded from YAML and validated through pydantic so that a malformed
or incomplete config fails fast at startup rather than producing an
inconsistent persona at runtime.
"""
from __future__ import annotations

import functools
import sys
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

Arch = Literal["riscv32", "riscv64"]


@functools.lru_cache(maxsize=8)
def _load_wordlist(path: Path) -> frozenset[str]:
    """One-time-per-process load of a plain-text, one-entry-per-line
    wordlist (operator-controlled config path, not attacker input). Missing
    files degrade to "nothing matches" with a warning rather than crashing
    the honeypot at login time."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"warning: could not read wordlist {path}: {exc}", file=sys.stderr)
        return frozenset()
    return frozenset(line.strip() for line in lines if line.strip())


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
    # First line of defense against a cheap connection-flood DoS (neither
    # asyncssh nor asyncio's stream server cap concurrent connections on
    # their own, and each one holds a transcript file handle open for its
    # lifetime). 0 disables the cap. Real throttling against a distributed
    # flood belongs at the OS/network layer (fail2ban, iptables connlimit),
    # not here -- this only bounds what one source IP can do.
    max_connections_per_ip: int = 8
    # Absolute cap on how long any single session may stay connected,
    # regardless of activity -- neither listener enforced any limit before
    # this (asyncssh's login_timeout only covers the pre-auth handshake;
    # our own Telnet loop had no timeout anywhere, not even at the login
    # prompt), so a held-open connection was previously unbounded. 0
    # disables the cap.
    max_session_seconds: float = 180.0


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
    # The SSH protocol version-exchange string (RFC 4253 sec 4.2) identifies
    # the *SSH daemon implementation*, e.g. "SSH-2.0-dropbear_2020.81" --
    # never a human-readable device description like ssh_banner above. Real
    # embedded/IoT devices overwhelmingly run Dropbear (tiny footprint), so
    # that's the realistic default; this is visible pre-auth from a bare
    # TCP connect, so getting its format right matters more than most
    # other fields here.
    ssh_server_id: str = "dropbear_2020.81"

    @field_validator("hart_count")
    @classmethod
    def _positive_hart_count(cls, v: int) -> int:
        if v < 1:
            raise ValueError("hart_count must be >= 1")
        return v


class CredentialPolicy(BaseModel):
    """Which username/password pairs the fake login accepts.

    accept_any=True maximizes capture of credential-stuffing attempts (spec
    4.1) but is itself a honeypot tell -- no real device accepts a
    literally-arbitrary, never-seen credential pair. The realistic
    alternative: set accept_any=False, point password_wordlist_path at a
    real-world-observed password list, and rely on `valid_usernames` (not
    username_wordlist_path) to gate which usernames can ever succeed --
    a login is accepted when the username is one of `valid_usernames` and
    the password independently appears in the password wordlist.
    `allow_list` remains a small always-accepted fast path on top of
    either mode, for exact pairs worth guaranteeing (e.g. Mirai's
    root/xc3511, which a general password list doesn't contain).

    Why `valid_usernames` (a small fixed set) rather than also matching
    the username against a broad wordlist: confirmed against real traffic
    that doing so lets one source IP succeed with many wildly different
    usernames against the same simulated device (one IP got 9 different
    accepted usernames -- "arthur", "botuser", "mailuser", "teste"... all
    "working" on one box). No real embedded device has 9 valid accounts;
    it has one, occasionally two. That pattern looks selective on any
    single login attempt and only falls apart across repeated attempts
    from the same source -- exactly the kind of check a deliberate
    honeypot-hunter (not just a generic credential-stuffing bot) would
    run. `username_wordlist_path` is kept only for `is_known_username()`,
    used purely to judge "does this look like a plausible attempted
    username" for the dashboard's off-wordlist flag -- not to gate
    acceptance.
    """

    accept_any: bool = True
    allow_list: list[Credential] = Field(default_factory=list)
    username_wordlist_path: Path | None = None
    password_wordlist_path: Path | None = None
    # The actual gate on which usernames can ever succeed a login (see the
    # class docstring for why this isn't username_wordlist_path). Real
    # embedded/IoT SSH-Telnet backdoors overwhelmingly run everything as a
    # single root account; some (routers, NAS boxes) also expose a
    # separate admin account.
    valid_usernames: list[str] = Field(default_factory=lambda: ["root", "admin"])

    def is_known_username(self, username: str) -> bool | None:
        """None means "no wordlist configured, this can't be judged" --
        distinct from False ("wordlist configured, not found in it") so
        callers (the dashboard) can skip the check entirely rather than
        flagging every login as suspicious when no wordlist is set up.
        Judges plausibility for the dashboard's off-wordlist flag only --
        see accepts() and the class docstring for why login acceptance
        itself gates on valid_usernames instead."""
        if self.username_wordlist_path is None:
            return None
        return username in _load_wordlist(self.username_wordlist_path)

    def is_known_password(self, password: str) -> bool | None:
        if self.password_wordlist_path is None:
            return None
        return password in _load_wordlist(self.password_wordlist_path)

    def accepts(self, username: str, password: str) -> bool:
        if self.accept_any:
            return True
        if any(c.username == username and c.password == password for c in self.allow_list):
            return True
        if username in self.valid_usernames and self.password_wordlist_path:
            return bool(self.is_known_password(password))
        return False


class FetcherConfig(BaseModel):
    quarantine_dir: Path = Path("var/quarantine")
    jobs_dir: Path = Path("var/jobs")
    max_file_size_bytes: int = 50 * 1024 * 1024
    timeout_seconds: float = 15.0
    allowed_protocols: list[str] = Field(default_factory=lambda: ["http", "https"])
    verify_tls: bool = False
    # Refuse to connect (initial request *or* mid-fetch redirect) to any
    # address that resolves to loopback/RFC1918/link-local/reserved/
    # multicast -- this is what stops an attacker from using wget/curl to
    # turn the fetcher into a scanner against your own internal network or
    # cloud metadata endpoint (169.254.169.254). Leave True everywhere
    # except a config that deliberately targets local addresses on purpose
    # (see configs/training.yaml).
    block_private_networks: bool = True
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
