"""Outbound-fetch destination guard (code-side half of SAFETY.md guarantee #5).

fetch_and_quarantine() fetches attacker-controlled URLs by design -- that's
the whole point of a payload-capture honeypot. But nothing about "fetch
whatever URL the attacker typed" should extend to loopback, RFC1918,
link-local (which covers the 169.254.169.254 cloud-metadata endpoint), or
other non-public destinations reachable from the fetcher process, whether
that address comes from the original URL, a redirect it returns mid-fetch,
or DNS resolution of a hostname.

An earlier version of this module wrapped only aiohttp's *resolver*
(passed as TCPConnector(resolver=...)). That misses a huge case:
aiohttp.TCPConnector._resolve_host() fast-paths any host that is already a
literal IP address and returns it directly, *without ever calling the
configured resolver* -- confirmed by reading aiohttp's source and by a
live test (a fetch to a literal loopback IP with a real server listening
went straight through, unblocked, while the exact same fetch to a
hostname needing resolution was correctly blocked). Since "wget
http://<ip>/..." with no hostname at all is the simpler and more common
form of this attack, not an edge case, that gap is the whole ballgame.

The fix: override TCPConnector._resolve_host() itself rather than just the
resolver it delegates to. Every connection this connector makes -- literal
IP, hostname, or a redirect to either -- funnels through that one method,
so it's the one choke point that actually covers all three cases with a
single check. _resolve_host is a private aiohttp API (no public hook
exists for this), so test_ssrf_guard.py includes a live end-to-end test
against a literal-IP target specifically to catch a future aiohttp upgrade
silently reopening this gap, not just a unit test of is_blocked_address().
"""
from __future__ import annotations

import ipaddress

from aiohttp import TCPConnector


class BlockedDestinationError(OSError):
    """Raised when a resolved address is not a permitted public address."""


def is_blocked_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True  # unparseable -- refuse rather than guess
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


class SafeTCPConnector(TCPConnector):
    """A TCPConnector that refuses to connect to any non-public address,
    whether the attacker's URL names it directly as a literal IP or it's
    reached via DNS (including mid-fetch, via a redirect to a different
    host) -- see this module's docstring for why overriding
    _resolve_host, not the resolver, is what actually covers both."""

    async def _resolve_host(self, host, port, traces=None):
        results = await super()._resolve_host(host, port, traces=traces)
        for result in results:
            if is_blocked_address(result["host"]):
                raise BlockedDestinationError(
                    f"destination for '{host}' is not a permitted public address"
                )
        return results
