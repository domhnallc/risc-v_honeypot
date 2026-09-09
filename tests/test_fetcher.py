"""Tests for the isolated fetcher (honeypot/fetcher/fetcher.py).

Serves fixed byte content from a local, throwaway http.server instance (no
real internet access, no attacker-controlled infrastructure involved) and
exercises: hashing, quarantine permissions, the size cap, disallowed
protocols, connection failures, and the ELF arch-mismatch flag end to end.

Async fetcher calls are driven with asyncio.run() directly rather than
pytest-asyncio, to avoid adding another test-only dependency.
"""
from __future__ import annotations

import asyncio
import hashlib
import http.server
import os
import struct
import threading
from pathlib import Path

import pytest

from honeypot.config.schema import FetcherConfig
from honeypot.fetcher.fetcher import fetch_and_quarantine
from honeypot.fetcher.queue import make_job


class _Server:
    def __init__(self, directory: Path) -> None:
        handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(*a, directory=str(directory), **kw)
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}/{path}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def http_server(tmp_path):
    server = _Server(tmp_path)
    yield server, tmp_path
    server.stop()


def _config(tmp_path: Path, **overrides) -> FetcherConfig:
    base = dict(
        quarantine_dir=tmp_path / "quarantine",
        jobs_dir=tmp_path / "jobs",
        max_file_size_bytes=50 * 1024 * 1024,
        timeout_seconds=5.0,
        allowed_protocols=["http", "https"],
        verify_tls=False,
    )
    base.update(overrides)
    return FetcherConfig(**base)


def test_fetch_success_hashes_and_quarantines(http_server):
    server, tmp_path = http_server
    content = b"not a real payload, just test bytes" * 10
    (tmp_path / "payload.bin").write_bytes(content)
    config = _config(tmp_path)
    job = make_job("sess1", "10.0.0.1", server.url("payload.bin"), "http", "payload.bin", "wget ...")

    result = asyncio.run(fetch_and_quarantine(job, config))

    assert result.success
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.md5 == hashlib.md5(content).hexdigest()
    assert result.size_bytes == len(content)
    quarantined = Path(result.quarantine_path)
    assert quarantined.exists()
    assert quarantined.read_bytes() == content
    assert oct(os.stat(quarantined).st_mode & 0o777) == oct(0o440)
    sidecar = quarantined.with_suffix(".json")
    assert sidecar.exists()
    assert oct(os.stat(sidecar).st_mode & 0o777) == oct(0o440)


def test_fetch_enforces_size_cap(http_server):
    server, tmp_path = http_server
    (tmp_path / "big.bin").write_bytes(b"x" * 10_000)
    config = _config(tmp_path, max_file_size_bytes=100)
    job = make_job("sess2", "10.0.0.1", server.url("big.bin"), "http", "big.bin", "wget ...")

    result = asyncio.run(fetch_and_quarantine(job, config))

    assert not result.success
    assert "max_file_size_bytes" in result.error
    assert list((tmp_path / "quarantine").glob("*.bin")) == []


def test_fetch_rejects_disallowed_protocol(tmp_path):
    config = _config(tmp_path, allowed_protocols=["http"])
    job = make_job("sess3", "10.0.0.1", "ftp://example/x", "ftp", "x", "curl ...")

    result = asyncio.run(fetch_and_quarantine(job, config))

    assert not result.success
    assert "not permitted" in result.error


def test_fetch_handles_connection_refused(tmp_path):
    config = _config(tmp_path)
    job = make_job("sess4", "10.0.0.1", "http://127.0.0.1:1/x", "http", "x", "wget ...")

    result = asyncio.run(fetch_and_quarantine(job, config))

    assert not result.success
    assert result.error


def test_fetch_flags_arch_mismatch(http_server):
    server, tmp_path = http_server
    ident = bytearray(20)
    ident[0:4] = b"\x7fELF"
    ident[4] = 2  # ELFCLASS64
    ident[5] = 1  # little-endian
    struct.pack_into("<H", ident, 18, 62)  # EM_X86_64, not RISC-V
    (tmp_path / "wrongarch.bin").write_bytes(bytes(ident))
    config = _config(tmp_path)
    job = make_job("sess5", "10.0.0.1", server.url("wrongarch.bin"), "http", "wrongarch.bin", "wget ...")

    result = asyncio.run(fetch_and_quarantine(job, config, persona_arch="riscv64"))

    assert result.success
    assert result.detected_machine == "EM_X86_64"
    assert result.arch_mismatch is None


def test_fetch_flags_riscv32_on_riscv64_persona_as_mismatch(http_server):
    server, tmp_path = http_server
    ident = bytearray(20)
    ident[0:4] = b"\x7fELF"
    ident[4] = 1  # ELFCLASS32
    ident[5] = 1  # little-endian
    struct.pack_into("<H", ident, 18, 243)  # EM_RISCV
    (tmp_path / "riscv32.bin").write_bytes(bytes(ident))
    config = _config(tmp_path)
    job = make_job("sess6", "10.0.0.1", server.url("riscv32.bin"), "http", "riscv32.bin", "wget ...")

    result = asyncio.run(fetch_and_quarantine(job, config, persona_arch="riscv64"))

    assert result.success
    assert result.detected_bitness == 32
    assert result.arch_mismatch is True
