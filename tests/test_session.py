"""Tests for SessionManager (honeypot/session/manager.py).

Uses a local http.server to stand in for dropper infrastructure so a full
command -> download -> quarantine -> logged-event round trip can be tested
without touching the real network. Verifies login-attempt logging, command
logging, and that a wget command produces both a file.download "requested"
event and a follow-up outcome event with hashes.
"""
from __future__ import annotations

import asyncio
import http.server
import json
import tempfile
import threading
from pathlib import Path

import pytest

from honeypot.config.schema import (
    CredentialPolicy,
    FetcherConfig,
    HoneypotConfig,
    ListenerConfig,
    LoggingConfig,
    PersonaConfig,
)
from honeypot.logging.events import EventLogger
from honeypot.session.manager import SessionManager


class _Server:
    def __init__(self, directory: Path) -> None:
        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(*a, directory=str(directory), **kw)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}/{path}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def config(tmp_path) -> HoneypotConfig:
    return HoneypotConfig(
        persona=PersonaConfig(arch="riscv64"),
        listeners=ListenerConfig(),
        credentials=CredentialPolicy(accept_any=True),
        fetcher=FetcherConfig(
            quarantine_dir=tmp_path / "quarantine",
            jobs_dir=tmp_path / "jobs",
        ),
        logging=LoggingConfig(
            log_dir=tmp_path / "logs",
            transcript_dir=tmp_path / "transcripts",
        ),
    )


def _read_events(config: HoneypotConfig) -> list[dict]:
    path = Path(config.logging.log_dir) / config.logging.json_log_filename
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_login_accept_any_logs_success(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "ssh", config, logger)
    session.on_connect()
    assert session.try_login("root", "anything") is True
    events = _read_events(config)
    assert events[0]["event"] == "session.connect"
    assert events[1]["event"] == "login.success"
    assert events[1]["username"] == "root"


def test_login_rejects_when_not_in_allow_list(tmp_path, config):
    config.credentials = CredentialPolicy(accept_any=False, allow_list=[])
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "ssh", config, logger)
    assert session.try_login("root", "root") is False
    events = _read_events(config)
    assert events[0]["event"] == "login.failed"


def test_command_input_is_logged():
    with tempfile.TemporaryDirectory() as d:
        tmp_path = Path(d)
        cfg = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"),
            fetcher=FetcherConfig(quarantine_dir=tmp_path / "q", jobs_dir=tmp_path / "j"),
            logging=LoggingConfig(log_dir=tmp_path / "logs", transcript_dir=tmp_path / "t"),
        )
        logger = EventLogger(cfg.logging.log_dir, cfg.logging.json_log_filename)
        session = SessionManager("1.2.3.4", 5555, 2222, "telnet", cfg, logger)
        output = asyncio.run(session.handle_command("uname -a"))
        assert "riscv64" in output
        events = _read_events(cfg)
        command_events = [e for e in events if e["event"] == "command.input"]
        assert command_events[0]["command"] == "uname"


def test_wget_download_round_trip(config):
    with tempfile.TemporaryDirectory() as d:
        serve_dir = Path(d)
        content = b"payload-bytes"
        (serve_dir / "mal.bin").write_bytes(content)
        server = _Server(serve_dir)
        try:
            logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
            session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
            output = asyncio.run(session.handle_command(f"wget {server.url('mal.bin')} -O mal.bin"))
        finally:
            server.stop()

    assert "saved" in output
    events = _read_events(config)
    download_events = [e for e in events if e["event"] == "file.download"]
    assert download_events[0]["outcome"] == "requested"
    assert download_events[1]["outcome"] == "success"
    assert download_events[1]["sha256"] is not None
    quarantined = list(Path(config.fetcher.quarantine_dir).glob("*.bin"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == content


def test_execution_attempt_is_logged_and_never_runs_anything(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    output = asyncio.run(session.handle_command("chmod +x mal.bin"))
    assert output == ""
    output = asyncio.run(session.handle_command("./mal.bin"))
    assert output == ""
    events = _read_events(config)
    exec_events = [e for e in events if e["event"] == "file.execution_attempt"]
    assert len(exec_events) == 2


def test_exit_command_sets_should_exit(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    asyncio.run(session.handle_command("exit"))
    assert session.should_exit is True
