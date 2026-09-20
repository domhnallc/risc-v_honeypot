"""Entry point: loads config and runs the SSH + Telnet listeners.

For v1, the fetcher runs in-process (a fetch is awaited directly inside
SessionManager.handle_command) rather than as a separate process -- spec sec
3 explicitly allows this during initial development, on the condition that
the fetcher's own code stays structurally isolated from session/shell state,
which honeypot.fetcher.fetcher does. For a production deployment, run
`python -m honeypot.fetcher.worker <config>` as a separate, network-isolated
process/container instead and point this process's config fetcher.jobs_dir
at the same directory (mounted read/write for the session host, read-only-
except-write for the fetcher host, per SAFETY.md).
"""
from __future__ import annotations

import asyncio
import logging
import sys
import time

from honeypot.config import load_config
from honeypot.listeners.ssh import start_ssh_listener
from honeypot.listeners.telnet import start_telnet_listener
from honeypot.logging.events import EventLogger
from honeypot.logging.sanitize import setup_logging

log = logging.getLogger(__name__)


async def _heartbeat(event_logger: EventLogger, interval: float) -> None:
    """Log a liveness event now and then every `interval` seconds, forever.

    The first one is written immediately, so every (re)start leaves a marker
    with uptime ~0. A failed write (full disk, bad permissions) is logged and
    retried next tick: this runs inside the TaskGroup that also serves the
    listeners, so letting it raise would take the honeypot down with it.
    """
    started = time.monotonic()
    while True:
        try:
            event_logger.heartbeat(time.monotonic() - started)
        except OSError:
            log.exception("could not write heartbeat event")
        await asyncio.sleep(interval)


async def run(config_path: str) -> None:
    config = load_config(config_path)
    setup_logging(config.logging.level)
    event_logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)

    servers = []
    if config.listeners.ssh_enabled:
        ssh_server = await start_ssh_listener(config, event_logger, config.listeners.ssh_host_key_path)
        servers.append(ssh_server)
        log.info("SSH listener on %s:%s", config.listeners.bind_host, config.listeners.ssh_port)
    if config.listeners.telnet_enabled:
        telnet_server = await start_telnet_listener(config, event_logger)
        servers.append(telnet_server)
        log.info("Telnet listener on %s:%s", config.listeners.bind_host, config.listeners.telnet_port)

    if not servers:
        log.error("No listeners enabled in config; exiting")
        return

    async with asyncio.TaskGroup() as tg:
        if config.logging.heartbeat_seconds > 0:
            tg.create_task(_heartbeat(event_logger, config.logging.heartbeat_seconds))
        for server in servers:
            tg.create_task(server.serve_forever() if hasattr(server, "serve_forever") else server.wait_closed())


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m honeypot.main <config.yaml>", file=sys.stderr)
        raise SystemExit(2)
    try:
        asyncio.run(run(sys.argv[1]))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
