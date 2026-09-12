"""Tests for the Telnet listener (honeypot/listeners/telnet.py).

Covers the unbounded-line-buffer DoS finding from the pre-deployment
security review: a connection that never sends '\\n' or closes must still
be dropped once its pending line exceeds _MAX_LINE_BYTES, rather than
growing an in-memory buffer forever.
"""
from __future__ import annotations

import asyncio

from honeypot.config.schema import HoneypotConfig, PersonaConfig
from honeypot.listeners.limiter import ConnectionLimiter
from honeypot.listeners.telnet import _MAX_LINE_BYTES, handle_telnet_connection
from honeypot.logging.events import EventLogger


class _FakeWriter:
    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False

    def get_extra_info(self, name):
        return ("9.9.9.9", 1234) if name == "peername" else None

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_oversized_line_drops_the_connection(tmp_path):
    config = HoneypotConfig(
        persona=PersonaConfig(arch="riscv64"),
        listeners={"bind_host": "127.0.0.1"},
        logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
    )
    logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
    limiter = ConnectionLimiter(max_per_ip=8)
    writer = _FakeWriter()

    async def run() -> None:
        reader = asyncio.StreamReader()
        reader.feed_data(b"a" * (_MAX_LINE_BYTES + 100))  # no '\n', connection stays open
        await handle_telnet_connection(reader, writer, config, logger, limiter)

    asyncio.run(run())

    # The connection must have been dropped rather than hanging or growing
    # its buffer forever -- try_login/handle_command never get called since
    # the username line itself never completes.
    assert writer.closed
