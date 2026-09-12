"""Outbound-fetch destination guard (code-side half of SAFETY.md guarantee #5).

fetch_and_quarantine() fetches attacker-controlled URLs by design -- that's
the whole point of a payload-capture honeypot. But nothing about "fetch
whatever URL the attacker typed" should extend to loopback, RFC1918,
link-local (which covers the 169.254.169.254 cloud-metadata endpoint), or
other non-public destinations reachable from the fetcher process, whether
that address comes from the original URL or from a redirect it returns
mid-fetch. aiohttp re-resolves the host for every connection it makes
(including each hop of a redirect chain), so wrapping the *resolver* --
rather than checking the URL string once up front -- is what closes off
both the direct case and the redirect-based bypass with one check.
"""
from __future__ import annotations

import ipaddress
import socket

from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import DefaultResolver


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


class SafeResolver(AbstractResolver):
    """Wraps aiohttp's default resolver and rejects any result that isn't a
    public address, so every DNS lookup this connector performs -- initial
    connect or redirect -- is checked, not just the attacker-supplied URL's
    literal host string (which DNS rebinding or a redirect can trivially
    route around a check made only once up front)."""

    def __init__(self) -> None:
        self._inner = DefaultResolver()

    async def resolve(self, host: str, port: int = 0,
                       family: socket.AddressFamily = socket.AF_INET) -> list[ResolveResult]:
        results = await self._inner.resolve(host, port, family)
        for result in results:
            if is_blocked_address(result["host"]):
                raise BlockedDestinationError(
                    f"destination for '{host}' is not a permitted public address"
                )
        return results

    async def close(self) -> None:
        await self._inner.close()
