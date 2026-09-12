"""Tests for the SSH listener (honeypot/listeners/ssh.py).

Covers the SSH-version-banner finding from the pentest review: the wire
banner must be a plausible single SSH-2.0-<implementation> string, not the
double-prefixed "SSH-2.0-SSH-2.0-..." that resulted from passing an
already-prefixed string to asyncssh's server_version (which prepends
"SSH-2.0-" itself).
"""
from __future__ import annotations

import asyncio

from honeypot.config.schema import HoneypotConfig, PersonaConfig
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
