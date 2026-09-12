"""Tests for the fetcher's outbound-destination guard (honeypot/fetcher/ssrf_guard.py).

Covers the SSRF finding from the pre-deployment security review: nothing
should let an attacker-supplied wget/curl URL (or a redirect it returns)
reach loopback/RFC1918/link-local/cloud-metadata addresses.
"""
from __future__ import annotations

import asyncio

import pytest

from honeypot.fetcher.ssrf_guard import BlockedDestinationError, SafeResolver, is_blocked_address


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


def test_resolver_raises_for_loopback_hostname():
    async def run():
        resolver = SafeResolver()
        try:
            with pytest.raises(BlockedDestinationError):
                await resolver.resolve("localhost", 80)
        finally:
            await resolver.close()

    asyncio.run(run())
