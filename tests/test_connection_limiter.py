"""Tests for the per-source-IP connection cap (honeypot/listeners/limiter.py).

Covers the connection-flood DoS finding from the pre-deployment security
review: neither listener imposes any concurrent-connection limit on its own.
"""
from __future__ import annotations

from honeypot.listeners.limiter import ConnectionLimiter


def test_blocks_once_limit_reached():
    limiter = ConnectionLimiter(max_per_ip=2)
    assert limiter.try_acquire("1.2.3.4")
    assert limiter.try_acquire("1.2.3.4")
    assert not limiter.try_acquire("1.2.3.4")


def test_release_frees_a_slot():
    limiter = ConnectionLimiter(max_per_ip=1)
    assert limiter.try_acquire("1.2.3.4")
    assert not limiter.try_acquire("1.2.3.4")
    limiter.release("1.2.3.4")
    assert limiter.try_acquire("1.2.3.4")


def test_different_ips_are_independent():
    limiter = ConnectionLimiter(max_per_ip=1)
    assert limiter.try_acquire("1.2.3.4")
    assert limiter.try_acquire("5.6.7.8")


def test_zero_disables_the_cap():
    limiter = ConnectionLimiter(max_per_ip=0)
    for _ in range(100):
        assert limiter.try_acquire("1.2.3.4")
