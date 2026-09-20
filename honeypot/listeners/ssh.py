"""SSH listener (spec sec 4.1), built on asyncssh.

Feeds into the same SessionManager as the Telnet listener (honeypot.session)
so command parsing/logging isn't duplicated per protocol.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path

import asyncssh

from honeypot.config.schema import HoneypotConfig
from honeypot.listeners.limiter import ConnectionLimiter
from honeypot.logging.events import EventLogger
from honeypot.session.manager import MAX_INPUT_CHARS, SessionManager

log = logging.getLogger(__name__)


# asyncssh puts no limit on how many public keys a client may offer, and each
# one we log is a line on disk: bound it per connection.
_MAX_LOGGED_KEYS = 20


class _HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, config: HoneypotConfig, event_logger: EventLogger,
                 limiter: ConnectionLimiter) -> None:
        self.config = config
        self.event_logger = event_logger
        self.limiter = limiter
        self.session: SessionManager | None = None
        self._limited_ip: str | None = None
        self._conn: asyncssh.SSHServerConnection | None = None
        self._client_version_reported = False
        self._auth_username: str | None = None   # last user a client asked to authenticate as
        self._credential_tried = False           # a password or public key was actually offered
        self._logged_keys = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._conn = conn
        peer = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        if not self.limiter.try_acquire(peer[0]):
            conn.abort()  # too many concurrent connections from this source IP
            return
        self._limited_ip = peer[0]
        # No client_id yet: the version exchange happens after this callback.
        # See _report_client_version.
        self.session = SessionManager(
            peer[0], peer[1], self.config.listeners.ssh_port, "ssh",
            self.config, self.event_logger,
        )
        self.session.on_connect()
        setattr(conn, "_honeypot_server", self)

    def connection_lost(self, exc: Exception | None) -> None:
        if self.session is not None:
            # A client that sent its banner and left without ever reaching
            # authentication still gets its version recorded here.
            self._report_client_version()
            if self._auth_username is not None and not self._credential_tried:
                # Asked to authenticate as a user, then went away without
                # offering a password or key: a scanner probing which methods
                # exist ("none" is the SSH auth method that requests exactly that).
                self.session.on_auth_attempt("none", self._auth_username)
            self.session.on_disconnect("closed")
        if self._limited_ip is not None:
            self.limiter.release(self._limited_ip)
            self._limited_ip = None

    def _report_client_version(self) -> None:
        # Not available in connection_made (the version exchange has not
        # happened yet), which is why session.connect always carried null.
        if self._client_version_reported or self.session is None or self._conn is None:
            return
        version = self._conn.get_extra_info("client_version")
        if version:
            self._client_version_reported = True
            self.session.on_client_version(str(version))

    def begin_auth(self, username: str) -> bool:
        self._report_client_version()
        self._auth_username = username
        return True  # always require a credential step -- never allow no-auth

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        # Dropbear offers publickey and password, so a device advertising only
        # "password" was itself slightly off. Every key is refused; the point
        # is to record which keys scanners and botnets try.
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        self._credential_tried = True
        if self.session is not None and self._logged_keys < _MAX_LOGGED_KEYS:
            self._logged_keys += 1
            self.session.on_auth_attempt(
                "publickey", username,
                key_type=key.get_algorithm(), key_fingerprint=key.get_fingerprint())
        return False

    def validate_password(self, username: str, password: str) -> bool:
        assert self.session is not None
        self._credential_tried = True
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


def _load_or_create_host_key(host_key_path: Path) -> asyncssh.SSHKey:
    """The persistent SSH host key, created on first use.

    A device whose host key changes between visits is a tell, and the key used
    to be regenerated on every container rebuild because it lived inside the
    container. Deployments now mount its directory from the host (see
    docker-compose.yml), and this keeps it there.

    The honeypot being reachable matters more than the key persisting, so an
    unusable path -- a mount that doesn't exist or isn't writable by the
    container's UID, a key file that can't be read or parsed -- falls back to a
    temporary in-memory key with a loud error, rather than raising out of
    start_ssh_listener and crash-looping the container. An unreadable or corrupt
    existing file is never overwritten.
    """
    try:
        try:
            return asyncssh.read_private_key(host_key_path)
        except FileNotFoundError:
            pass
        key = asyncssh.generate_private_key("ssh-rsa")
        host_key_path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a private temp name in the same directory and rename into
        # place: the key is 0600 from its first byte (write_bytes + chmod left
        # a window where it was world-readable) and a crash mid-write cannot
        # leave a truncated key behind for the next start to trip over.
        tmp = host_key_path.with_name(f".{host_key_path.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(key.export_private_key())
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, host_key_path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return key
    except (OSError, asyncssh.KeyImportError, asyncssh.KeyEncryptionError) as exc:
        log.error(
            "SSH host key %s is unusable (%s: %s); using a TEMPORARY in-memory key, so the "
            "host fingerprint will change on every restart. Fix the directory's ownership/"
            "permissions (the container runs as UID 10001) or the key file.",
            host_key_path, type(exc).__name__, exc)
        return asyncssh.generate_private_key("ssh-rsa")


async def start_ssh_listener(config: HoneypotConfig, event_logger: EventLogger,
                              host_key_path: str | Path = "var/ssh_host_key") -> asyncssh.SSHAcceptor:
    host_key = _load_or_create_host_key(Path(host_key_path))
    limiter = ConnectionLimiter(config.listeners.max_connections_per_ip)

    def server_factory() -> _HoneypotSSHServer:
        return _HoneypotSSHServer(config, event_logger, limiter)

    return await asyncssh.create_server(
        server_factory,
        host=config.listeners.bind_host,
        port=config.listeners.ssh_port,
        server_host_keys=[host_key],
        process_factory=_process_factory(config),
        # asyncssh prepends "SSH-2.0-" itself (see _send_version in
        # asyncssh/connection.py) -- this must be *just* the software
        # identifier (e.g. "dropbear_2020.81"), not a full "SSH-2.0-..."
        # string, or the wire banner ends up double-prefixed
        # ("SSH-2.0-SSH-2.0-..."), which was the previous bug here.
        server_version=config.persona.ssh_server_id,
    )
