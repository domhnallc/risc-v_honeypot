"""Tests for the fetcher's outbound-destination guard (honeypot/fetcher/ssrf_guard.py).

Covers the SSRF finding from the pre-deployment security review: nothing
should let an attacker-supplied wget/curl URL (or a redirect it returns)
reach loopback/RFC1918/link-local/cloud-metadata addresses.

test_literal_ip_target_is_actually_blocked_end_to_end below is the
important one: an earlier version of this guard wrapped only aiohttp's
resolver, which aiohttp never even calls when the URL's host is already a
literal IP address (TCPConnector._resolve_host fast-paths is_ip_address()
before touching the configured resolver) -- confirmed live against this
exact test's server, which was fetched successfully, unblocked, before
that was fixed to override _resolve_host itself. A unit test of
is_blocked_address() alone would never have caught that regression class,
since the bug was entirely about which code path aiohttp takes to reach
it, not about the address-classification logic.
"""
from __future__ import annotations

import asyncio
import http.server
import threading
from pathlib import Path

import aiohttp
import pytest

from honeypot.fetcher.ssrf_guard import BlockedDestinationError, SafeTCPConnector, is_blocked_address


class _Server:
    def __init__(self, directory: Path) -> None:
        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(*a, directory=str(directory), **kw)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.mark.parametrize("address", [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.5",
    "192.168.1.1",
    "169.254.169.254",  # cloud metadata endpoint
    "0.0.0.0",
    "::1",
])
def test_non_public_addresses_are_blocked(address):
    assert is_blocked_address(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_addresses_are_not_blocked(address):
    assert not is_blocked_address(address)


def test_unparseable_address_is_blocked():
    assert is_blocked_address("not-an-ip")


def test_hostname_target_is_blocked():
    async def run():
        connector = SafeTCPConnector()
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get("http://localhost/", timeout=aiohttp.ClientTimeout(total=5)):
                    pass
        finally:
            await connector.close()

    with pytest.raises(Exception) as exc_info:
        asyncio.run(run())
    exc = exc_info.value
    blocked = exc if isinstance(exc, BlockedDestinationError) else exc.__cause__
    assert isinstance(blocked, BlockedDestinationError)


def test_literal_ip_target_is_actually_blocked_end_to_end(tmp_path):
    """Regression test for the real gap found in production: a literal-IP
    URL, with a real server actually listening and answering, must still
    be refused -- not just fail to resolve for some unrelated reason."""
    (tmp_path / "index.html").write_text("internal-secret-content")
    server = _Server(tmp_path)
    try:
        async def run():
            connector = SafeTCPConnector()
            try:
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(f"http://127.0.0.1:{server.port}/",
                                            timeout=aiohttp.ClientTimeout(total=5)):
                        pass
            finally:
                await connector.close()

        with pytest.raises(Exception) as exc_info:
            asyncio.run(run())
        exc = exc_info.value
        blocked = exc if isinstance(exc, BlockedDestinationError) else exc.__cause__
        assert isinstance(blocked, BlockedDestinationError), (
            f"expected the literal-IP target to be blocked, got {type(exc)}: {exc}"
        )
    finally:
        server.stop()
