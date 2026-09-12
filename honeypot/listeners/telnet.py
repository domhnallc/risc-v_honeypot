"""Telnet listener (spec sec 4.1).

Implemented as a lightweight custom asyncio protocol rather than a mature
async Telnet library (none exists) -- most IoT malware Telnet clients don't
negotiate options beyond the bare minimum, so this only strips/discards IAC
option negotiation rather than fully implementing RFC 854.
"""
from __future__ import annotations

import asyncio
import logging

from honeypot.config.schema import HoneypotConfig
from honeypot.listeners.limiter import ConnectionLimiter
from honeypot.logging.events import EventLogger
from honeypot.session.manager import SessionManager

IAC = 0xFF
WILL, WONT, DO, DONT = 0xFB, 0xFC, 0xFD, 0xFE
SB, SE = 0xFA, 0xF0

log = logging.getLogger(__name__)

_NORMAL, _GOT_IAC, _GOT_CMD, _IN_SUBNEG, _SUBNEG_IAC = range(5)

# No real embedded telnetd accepts an unbounded line before a newline either
# -- without a cap here, one connection sending data with no '\n' grows
# `linebuf` forever, and a handful of such connections is a memory-exhaustion
# DoS against the whole process. 8KiB is generously above any real command
# line this fake shell ever needs to parse.
_MAX_LINE_BYTES = 8192


class _IacFilter:
    """Stateful Telnet IAC filter -- safe across arbitrary read boundaries.

    feed() takes one raw byte and returns a cleaned data byte, or None if
    that byte was consumed as part of option negotiation. No negotiated
    option is ever honored; everything IAC-prefixed is simply discarded.
    """

    def __init__(self) -> None:
        self._state = _NORMAL

    def feed(self, byte: int) -> int | None:
        state = self._state
        if state == _NORMAL:
            if byte == IAC:
                self._state = _GOT_IAC
                return None
            return byte
        if state == _GOT_IAC:
            if byte == IAC:
                self._state = _NORMAL
                return IAC
            if byte in (WILL, WONT, DO, DONT):
                self._state = _GOT_CMD
                return None
            if byte == SB:
                self._state = _IN_SUBNEG
                return None
            self._state = _NORMAL
            return None
        if state == _GOT_CMD:
            self._state = _NORMAL
            return None
        if state == _IN_SUBNEG:
            if byte == IAC:
                self._state = _SUBNEG_IAC
            return None
        if state == _SUBNEG_IAC:
            self._state = _NORMAL if byte == SE else _IN_SUBNEG
            return None
        return None


async def handle_telnet_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                    config: HoneypotConfig, event_logger: EventLogger,
                                    limiter: ConnectionLimiter) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    if not limiter.try_acquire(peer[0]):
        writer.close()  # too many concurrent connections from this source IP
        return
    iac = _IacFilter()
    linebuf = bytearray()

    async def read_line() -> str | None:
        nonlocal linebuf
        while True:
            data = await reader.read(4096)
            if not data:
                return None
            session.record_recv(data)
            for raw_byte in data:
                cleaned = iac.feed(raw_byte)
                if cleaned is None:
                    continue
                if cleaned == 0x0A:
                    line = bytes(linebuf).decode("utf-8", errors="replace")
                    linebuf = bytearray()
                    return line
                if cleaned != 0x0D:
                    if len(linebuf) >= _MAX_LINE_BYTES:
                        return None  # oversized line: drop the connection
                    linebuf.append(cleaned)

    async def write(text: str) -> None:
        data = text.encode()
        writer.write(data)
        session.record_send(data)
        await writer.drain()

    session = SessionManager(peer[0], peer[1], config.listeners.telnet_port, "telnet",
                              config, event_logger)
    session.on_connect()
    try:
        await write(session.banner())
        for _ in range(3):
            await write("login: ")
            username = await read_line()
            if username is None:
                return
            await write("Password: ")
            password = await read_line()
            if password is None:
                return
            if session.try_login(username.strip(), password.strip()):
                break
            await write("\nLogin incorrect\n")
        else:
            return

        await write("\n" + session.prompt())
        while True:
            line = await read_line()
            if line is None:
                break
            output = await session.handle_command(line)
            reply = (output + "\n" if output else "")
            if not session.should_exit:
                reply += session.prompt()
            await write(reply)
            if session.should_exit:
                break
    finally:
        session.on_disconnect("closed")
        writer.close()
        limiter.release(peer[0])


async def start_telnet_listener(config: HoneypotConfig, event_logger: EventLogger) -> asyncio.AbstractServer:
    limiter = ConnectionLimiter(config.listeners.max_connections_per_ip)

    async def _client_connected(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await handle_telnet_connection(reader, writer, config, event_logger, limiter)
        except (ConnectionResetError, BrokenPipeError):
            pass

    return await asyncio.start_server(
        _client_connected, host=config.listeners.bind_host, port=config.listeners.telnet_port,
    )
