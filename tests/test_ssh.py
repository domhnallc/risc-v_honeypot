"""Tests for the SSH listener (honeypot/listeners/ssh.py).

Covers the SSH-version-banner finding from the pentest review: the wire
banner must be a plausible single SSH-2.0-<implementation> string, not the
double-prefixed "SSH-2.0-SSH-2.0-..." that resulted from passing an
already-prefixed string to asyncssh's server_version (which prepends
"SSH-2.0-" itself). Also covers the unbounded-session-duration finding:
asyncssh's own login_timeout only covers the pre-auth handshake, so an
authenticated session had no maximum duration at all before
listeners.max_session_seconds was added.
"""
from __future__ import annotations

import asyncio
import json

import asyncssh

from honeypot.config.schema import CredentialPolicy, HoneypotConfig, PersonaConfig
from honeypot.listeners.ssh import start_ssh_listener
from honeypot.logging.events import EventLogger


def test_wire_banner_is_not_double_prefixed(tmp_path):
    async def run() -> bytes:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64", ssh_server_id="dropbear_2020.81"),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        try:
            port = server.get_addresses()[0][1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                return await reader.readline()
            finally:
                writer.close()
        finally:
            server.close()

    line = asyncio.run(run())
    assert line == b"SSH-2.0-dropbear_2020.81\r\n"
    assert line.count(b"SSH-2.0-") == 1


def test_ssh_server_id_defaults_to_a_dropbear_style_string():
    persona = PersonaConfig(arch="riscv64")
    assert persona.ssh_server_id.startswith("dropbear_")


def test_authenticated_session_is_dropped_after_max_session_seconds(tmp_path):
    async def run() -> list[dict]:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"),
            credentials=CredentialPolicy(accept_any=True),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False,
                       "max_session_seconds": 0.3},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        try:
            port = server.get_addresses()[0][1]
            async with asyncssh.connect("127.0.0.1", port=port, username="root", password="root",
                                         known_hosts=None) as conn:
                async with conn.create_process() as process:
                    # Login succeeded (asyncssh wouldn't have gotten here
                    # otherwise); now stay connected without sending
                    # anything, well past max_session_seconds, and confirm
                    # the server actually drops it rather than holding the
                    # process open indefinitely.
                    await asyncio.wait_for(process.stdout.read(), timeout=5.0)
        finally:
            server.close()
        return [json.loads(line) for line in (tmp_path / "logs" / "events.jsonl").read_text().splitlines()]

    events = asyncio.run(run())
    closed = next(e for e in events if e["event"] == "session.closed")
    assert closed["reason"] == "max_duration_exceeded"
