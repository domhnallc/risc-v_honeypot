"""Tests for the liveness heartbeat (honeypot/main.py).

A public honeypot is knocked on every few minutes around the clock, so a long
gap in events.jsonl means the process stopped -- but only if the log can say
"still here" when nobody connects.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path

import pytest

from honeypot.config.schema import LoggingConfig
from honeypot.logging.events import EventLogger
from honeypot.main import _heartbeat, run


def _events(log_dir: Path) -> list[dict]:
    path = log_dir / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def _run_for(coro, seconds: float) -> None:
    task = asyncio.ensure_future(coro)
    await asyncio.sleep(seconds)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def test_heartbeat_is_on_by_default_every_five_minutes():
    assert LoggingConfig().heartbeat_seconds == 300


def test_heartbeat_logs_immediately_then_periodically(tmp_path):
    logger = EventLogger(tmp_path, "events.jsonl")
    asyncio.run(_run_for(_heartbeat(logger, 0.05), 0.33))

    beats = [e for e in _events(tmp_path) if e["event"] == "honeypot.heartbeat"]
    assert len(beats) >= 4
    assert beats[0]["uptime_seconds"] < 0.05        # written at startup: marks every restart
    uptimes = [b["uptime_seconds"] for b in beats]
    assert uptimes == sorted(uptimes) and uptimes[-1] > 0.1


def test_heartbeat_survives_a_failing_write(tmp_path):
    """The heartbeat shares a TaskGroup with the listeners: if a full disk made it
    raise, the honeypot itself would go down."""
    class Flaky(EventLogger):
        calls = 0

        def heartbeat(self, uptime_seconds: float) -> None:
            Flaky.calls += 1
            if Flaky.calls <= 2:
                raise OSError("No space left on device")
            super().heartbeat(uptime_seconds)

    asyncio.run(_run_for(_heartbeat(Flaky(tmp_path, "events.jsonl"), 0.03), 0.3))
    assert Flaky.calls > 3
    assert any(e["event"] == "honeypot.heartbeat" for e in _events(tmp_path))


def _config_file(tmp_path: Path, heartbeat_seconds: float) -> Path:
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"""
persona:
  arch: riscv64
listeners:
  bind_host: "127.0.0.1"
  ssh_enabled: true
  ssh_port: 0
  telnet_enabled: false
  ssh_host_key_path: {tmp_path}/keys/ssh_host_key
logging:
  log_dir: {tmp_path}/logs
  transcript_dir: {tmp_path}/transcripts
  heartbeat_seconds: {heartbeat_seconds}
""")
    return cfg


def _run_honeypot_briefly(config_path: Path) -> None:
    with pytest.raises(TimeoutError):
        asyncio.run(asyncio.wait_for(run(str(config_path)), timeout=1.5))


def test_run_writes_a_startup_heartbeat(tmp_path):
    _run_honeypot_briefly(_config_file(tmp_path, heartbeat_seconds=300))
    beats = [e for e in _events(tmp_path / "logs") if e["event"] == "honeypot.heartbeat"]
    assert len(beats) == 1 and beats[0]["uptime_seconds"] < 1.0


def test_run_writes_no_heartbeat_when_disabled(tmp_path):
    _run_honeypot_briefly(_config_file(tmp_path, heartbeat_seconds=0))
    assert not [e for e in _events(tmp_path / "logs") if e["event"] == "honeypot.heartbeat"]
