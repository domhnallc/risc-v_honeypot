"""SSH listener (spec sec 4.1), built on asyncssh.

Feeds into the same SessionManager as the Telnet listener (honeypot.session)
so command parsing/logging isn't duplicated per protocol.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import asyncssh

from honeypot.config.schema import HoneypotConfig
from honeypot.listeners.limiter import ConnectionLimiter
from honeypot.logging.events import EventLogger
from honeypot.session.manager import MAX_INPUT_CHARS, SessionManager


class _HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, config: HoneypotConfig, event_logger: EventLogger,
                 limiter: ConnectionLimiter) -> None:
        self.config = config
        self.event_logger = event_logger
        self.limiter = limiter
        self.session: SessionManager | None = None
        self._limited_ip: str | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        if not self.limiter.try_acquire(peer[0]):
            conn.abort()  # too many concurrent connections from this source IP
            return
        self._limited_ip = peer[0]
        client_version = conn.get_extra_info("client_version")
        self.session = SessionManager(
            peer[0], peer[1], self.config.listeners.ssh_port, "ssh",
            self.config, self.event_logger, client_id=client_version,
        )
        self.session.on_connect()
        setattr(conn, "_honeypot_server", self)

    def connection_lost(self, exc: Exception | None) -> None:
        if self.session is not None:
            self.session.on_disconnect("closed")
        if self._limited_ip is not None:
            self.limiter.release(self._limited_ip)
            self._limited_ip = None

    def begin_auth(self, username: str) -> bool:
        return True  # always require a password step -- never allow no-auth

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        assert self.session is not None
        return self.session.try_login(username, password)


async def _run_exec_command(process: asyncssh.SSHServerProcess, session: SessionManager) -> None:
    """`ssh user@host "<command>"` (an SSH exec request, no interactive shell).

    This is how most SSH-side botnets deliver their dropper one-liner
    (paramiko/libssh `exec_command`). Previously only the interactive-shell
    path existed, so the command was silently discarded and the client saw a
    connection that just hung until the session cap -- no command logged, no
    download ever attempted.
    """
    command = (process.command or "")[:MAX_INPUT_CHARS]
    session.record_recv((command + "\n").encode())
    output = await session.handle_command(command)
    reply = output + "\n" if output else ""
    process.stdout.write(reply)
    session.record_send(reply.encode())


async def _run_process_session(process: asyncssh.SSHServerProcess, session: SessionManager) -> None:
    if process.command is not None:
        await _run_exec_command(process, session)
        return
    process.stdout.write(session.prompt())
    async for line in process.stdin:
        line = line[:MAX_INPUT_CHARS]
        session.record_recv(line.encode())
        output = await session.handle_command(line)
        reply = (output + "\n" if output else "")
        if not session.should_exit:
            reply += session.prompt()
        process.stdout.write(reply)
        session.record_send(reply.encode())
        if session.should_exit:
            break


async def _handle_process(process: asyncssh.SSHServerProcess, config: HoneypotConfig) -> None:
    conn = process.channel.get_connection()
    server: _HoneypotSSHServer | None = getattr(conn, "_honeypot_server", None)
    if server is None or server.session is None:
        # connection_made rejected this connection (e.g. per-IP connection
        # cap) before a session was ever created.
        process.exit(1)
        return
    session = server.session
    max_seconds = config.listeners.max_session_seconds
    disconnect_reason = "closed"
    # An exec request is one of possibly several channels on this connection
    # (paramiko-style bots run one exec_command after another); the session
    # is closed by connection_lost instead of at the end of each channel.
    is_exec = process.command is not None
    try:
        if max_seconds > 0:
            await asyncio.wait_for(_run_process_session(process, session), timeout=max_seconds)
        else:
            await _run_process_session(process, session)
    except asyncssh.BreakReceived:
        pass
    except asyncio.TimeoutError:
        disconnect_reason = "max_duration_exceeded"
    finally:
        if not is_exec or disconnect_reason != "closed":
            session.on_disconnect(disconnect_reason)
        process.exit(0)


def _process_factory(config: HoneypotConfig):
    async def factory(process: asyncssh.SSHServerProcess) -> None:
        await _handle_process(process, config)
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
    limiter = ConnectionLimiter(config.listeners.max_connections_per_ip)

    def server_factory() -> _HoneypotSSHServer:
        return _HoneypotSSHServer(config, event_logger, limiter)

    return await asyncssh.create_server(
        server_factory,
        host=config.listeners.bind_host,
        port=config.listeners.ssh_port,
        server_host_keys=[str(host_key_path)],
        process_factory=_process_factory(config),
        # asyncssh prepends "SSH-2.0-" itself (see _send_version in
        # asyncssh/connection.py) -- this must be *just* the software
        # identifier (e.g. "dropbear_2020.81"), not a full "SSH-2.0-..."
        # string, or the wire banner ends up double-prefixed
        # ("SSH-2.0-SSH-2.0-..."), which was the previous bug here.
        server_version=config.persona.ssh_server_id,
    )
