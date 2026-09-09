"""SSH listener (spec sec 4.1), built on asyncssh.

Feeds into the same SessionManager as the Telnet listener (honeypot.session)
so command parsing/logging isn't duplicated per protocol.
"""
from __future__ import annotations

from pathlib import Path

import asyncssh

from honeypot.config.schema import HoneypotConfig
from honeypot.logging.events import EventLogger
from honeypot.session.manager import SessionManager


class _HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, config: HoneypotConfig, event_logger: EventLogger) -> None:
        self.config = config
        self.event_logger = event_logger
        self.session: SessionManager | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        client_version = conn.get_extra_info("client_version")
        self.session = SessionManager(
            peer[0], peer[1], self.config.listeners.ssh_port, "ssh",
            self.config, self.event_logger, client_id=client_version,
        )
        self.session.on_connect()
        setattr(conn, "_honeypot_server", self)

    def begin_auth(self, username: str) -> bool:
        return True  # always require a password step -- never allow no-auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        assert self.session is not None
        return self.session.try_login(username, password)


async def _handle_process(process: asyncssh.SSHServerProcess) -> None:
    conn = process.channel.get_connection()
    server: _HoneypotSSHServer = getattr(conn, "_honeypot_server")
    session = server.session
    assert session is not None
    try:
        process.stdout.write(session.prompt())
        async for line in process.stdin:
            session.record_recv(line.encode())
            output = await session.handle_command(line)
            reply = (output + "\n" if output else "")
            if not session.should_exit:
                reply += session.prompt()
            process.stdout.write(reply)
            session.record_send(reply.encode())
            if session.should_exit:
                break
    except asyncssh.BreakReceived:
        pass
    finally:
        session.on_disconnect("closed")
        process.exit(0)


def _process_factory(config: HoneypotConfig):
    async def factory(process: asyncssh.SSHServerProcess) -> None:
        await _handle_process(process)
    return factory


async def _ensure_host_key(host_key_path: Path) -> None:
    if host_key_path.exists():
        return
    host_key_path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-rsa")
    host_key_path.write_bytes(key.export_private_key())
    host_key_path.chmod(0o600)


async def start_ssh_listener(config: HoneypotConfig, event_logger: EventLogger,
                              host_key_path: str | Path = "var/ssh_host_key") -> asyncssh.SSHAcceptor:
    host_key_path = Path(host_key_path)
    await _ensure_host_key(host_key_path)

    def server_factory() -> _HoneypotSSHServer:
        return _HoneypotSSHServer(config, event_logger)

    banner_version = "SSH-2.0-" + config.persona.ssh_banner.replace(" ", "_")[:40]

    return await asyncssh.create_server(
        server_factory,
        host=config.listeners.bind_host,
        port=config.listeners.ssh_port,
        server_host_keys=[str(host_key_path)],
        process_factory=_process_factory(config),
        server_version=banner_version,
    )
