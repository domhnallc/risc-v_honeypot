"""Per-source-IP concurrent-connection cap, shared by both listeners.

Neither asyncssh.create_server nor asyncio.start_server impose any limit on
concurrent connections by default, and each connection holds open resources
(a TranscriptWriter file handle, a FakeFilesystem) for its lifetime -- so a
simple connection flood from one or a few source IPs is a cheap
memory/file-descriptor exhaustion DoS before any application-layer logic
(login, command dispatch) ever runs. This is a first line of defense, not a
substitute for OS/network-layer throttling (fail2ban, iptables connlimit)
against a distributed flood from many source IPs.
"""
from __future__ import annotations

from collections import defaultdict


class ConnectionLimiter:
    def __init__(self, max_per_ip: int) -> None:
        self.max_per_ip = max_per_ip
        self._counts: dict[str, int] = defaultdict(int)

    def try_acquire(self, ip: str) -> bool:
        if self.max_per_ip <= 0:
            return True  # 0/negative disables the cap
        if self._counts[ip] >= self.max_per_ip:
            return False
        self._counts[ip] += 1
        return True

    def release(self, ip: str) -> None:
        if self._counts.get(ip):
            self._counts[ip] -= 1
            if self._counts[ip] <= 0:
                del self._counts[ip]
