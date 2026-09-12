"""Deterministic-but-time-varying fake system state.

Shared by every place the fake shell exposes "live" system status --
`top`, `free`, `ifconfig`, `/proc/uptime`, `/proc/loadavg` -- all of which
were previously hardcoded strings that returned byte-identical output on
every call, and `/proc/uptime` didn't exist at all. Both are cheap,
common ways a dropper checks whether it's talking to a real device rather
than a honeypot (a real device's load/memory/packet counters always drift
between two calls, even a few seconds apart).

Not truly random per call: real load/memory figures don't visibly jump
between two commands typed a second apart, so most of this reseeds a PRNG
from the current time bucket (a few/tens of seconds wide) rather than from
wall-clock on every call -- short-term stability, real drift over time.
State is shared per-process (not per-session), like a real device's actual
resource usage is shared across whoever happens to be logged into it.
Every input here is our own clock -- nothing attacker-influenced.
"""
from __future__ import annotations

import random
import time

_PROCESS_START = time.monotonic()
# Real embedded devices are rarely caught freshly booted -- start the fake
# uptime clock already a few days in, then let it climb for real from there
# for the life of this process.
_FAKE_BOOT_OFFSET_SECONDS = random.uniform(3 * 86400, 21 * 86400)


def uptime_seconds() -> float:
    return _FAKE_BOOT_OFFSET_SECONDS + (time.monotonic() - _PROCESS_START)


def _bucket(width_seconds: float) -> int:
    """Same value for calls within `width_seconds` of each other."""
    return int(time.time() // width_seconds)


def load_average() -> tuple[float, float, float]:
    rng = random.Random(f"load:{_bucket(5.0)}")
    base = 0.03 + rng.uniform(0.0, 0.12)
    return (
        round(base + rng.uniform(0.0, 0.04), 2),
        round(base * 0.75 + rng.uniform(0.0, 0.03), 2),
        round(base * 0.5 + rng.uniform(0.0, 0.02), 2),
    )


def memory_kb(total_kb: int = 256000) -> tuple[int, int, int]:
    """Returns (total, used, free), all in KB."""
    rng = random.Random(f"mem:{_bucket(30.0)}")
    used = int(total_kb * rng.uniform(0.16, 0.24))
    return total_kb, used, total_kb - used


def cpu_percentages() -> tuple[float, float, float]:
    """Returns (usr, sys, idle) percentages summing to 100."""
    rng = random.Random(f"cpu:{_bucket(5.0)}")
    usr = round(rng.uniform(0.5, 4.0), 1)
    sysp = round(rng.uniform(0.3, 2.5), 1)
    return usr, sysp, round(100.0 - usr - sysp, 1)


def network_counters() -> dict[str, int]:
    """Monotonically increasing since (fake) boot, like a real interface's
    packet/byte counters -- never resets or moves backward within a
    process's lifetime."""
    uptime = uptime_seconds()
    rng = random.Random(f"net:{int(uptime // 3600)}")  # drifts hourly
    rx_packets = int(uptime * rng.uniform(0.9, 1.3))
    tx_packets = int(uptime * rng.uniform(0.6, 0.9))
    rx_bytes = rx_packets * rng.randint(350, 850)
    tx_bytes = tx_packets * rng.randint(250, 650)
    return {"rx_packets": rx_packets, "tx_packets": tx_packets,
            "rx_bytes": rx_bytes, "tx_bytes": tx_bytes}


def format_bytes_human(n: int) -> str:
    mib = n / (1024 * 1024)
    return f"{mib:.1f} MiB" if mib >= 1 else f"{n / 1024:.1f} KiB"


def uptime_line() -> str:
    """Content of /proc/uptime: "<uptime> <idle>\\n" -- idle is cumulative
    CPU idle time summed across cores, roughly uptime * idle_fraction on a
    lightly loaded box."""
    up = uptime_seconds()
    return f"{up:.2f} {up * 0.93:.2f}\n"


def loadavg_line(hart_count: int, last_pid: int = 1234) -> str:
    """Content of /proc/loadavg: "1m 5m 15m running/total last_pid\\n"."""
    one, five, fifteen = load_average()
    return f"{one:.2f} {five:.2f} {fifteen:.2f} 1/{85 + hart_count} {last_pid}\n"
