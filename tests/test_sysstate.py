"""Tests for honeypot/shell/sysstate.py -- the fake load/memory/network/
uptime state behind `top`/`free`/`ifconfig`/`/proc/uptime`/`/proc/loadavg`.

Covers the "static system-status output" pentest finding: two calls close
together must be stable (real load/memory figures don't visibly jump
between commands typed a second apart), but calls far enough apart must
differ (a real device's numbers always drift, and /proc/uptime always
climbs) -- the previous, fully-static output failed both properties.
"""
from __future__ import annotations

from honeypot.shell import sysstate


def test_load_average_stable_within_the_same_time_bucket(monkeypatch):
    monkeypatch.setattr(sysstate.time, "time", lambda: 1_000_000.0)
    assert sysstate.load_average() == sysstate.load_average()


def test_load_average_differs_across_time_buckets(monkeypatch):
    monkeypatch.setattr(sysstate.time, "time", lambda: 1_000_000.0)
    first = sysstate.load_average()
    monkeypatch.setattr(sysstate.time, "time", lambda: 1_000_100.0)
    second = sysstate.load_average()
    assert first != second


def test_memory_kb_stable_within_bucket_and_totals_add_up(monkeypatch):
    monkeypatch.setattr(sysstate.time, "time", lambda: 1_000_000.0)
    total, used, free_kb = sysstate.memory_kb()
    assert (total, used, free_kb) == sysstate.memory_kb()
    assert used + free_kb == total
    assert 0 < used < total


def test_cpu_percentages_sum_to_100(monkeypatch):
    monkeypatch.setattr(sysstate.time, "time", lambda: 1_000_000.0)
    usr, sysp, idle = sysstate.cpu_percentages()
    assert round(usr + sysp + idle, 1) == 100.0


def test_uptime_seconds_only_ever_increases():
    a = sysstate.uptime_seconds()
    b = sysstate.uptime_seconds()
    assert b >= a


def test_network_counters_are_monotonic_with_uptime(monkeypatch):
    monkeypatch.setattr(sysstate, "uptime_seconds", lambda: 3600.0)
    early = sysstate.network_counters()
    monkeypatch.setattr(sysstate, "uptime_seconds", lambda: 7200.0)
    later = sysstate.network_counters()
    assert later["rx_packets"] > early["rx_packets"]
    assert later["tx_bytes"] > early["tx_bytes"]


def test_uptime_line_format():
    line = sysstate.uptime_line()
    assert line.endswith("\n")
    up, idle = line.strip().split()
    assert float(up) > 0
    assert float(idle) > 0


def test_loadavg_line_format():
    line = sysstate.loadavg_line(hart_count=4)
    parts = line.strip().split()
    assert len(parts) == 5
    float(parts[0]), float(parts[1]), float(parts[2])  # 1/5/15-min averages parse as numbers
    assert "/" in parts[3]
