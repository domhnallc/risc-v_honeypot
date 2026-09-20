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
import json
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
        # These tests fetch from a local _Server standing in for dropper
        # infrastructure (127.0.0.1) -- the SSRF guard would otherwise
        # (correctly) block every one of them. See test_ssrf_guard.py for
        # dedicated tests of the guard itself.
        block_private_networks=False,
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


# -- HTTP status and request fingerprint ----------------------------------------

async def _serve_once(response: bytes, seen: list[bytes]):
    """A throwaway raw HTTP server: records the request head, replies with `response`."""
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        seen.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(response)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def _fetch_from_raw(tmp_path, response: bytes, **cfg):
    seen: list[bytes] = []

    async def scenario():
        server, port = await _serve_once(response, seen)
        try:
            job = make_job("s", "10.0.0.1", f"http://127.0.0.1:{port}/telnetd", "http", "telnetd", "wget")
            return await fetch_and_quarantine(job, _config(tmp_path, **cfg))
        finally:
            server.close()
    return asyncio.run(scenario()), seen[0].decode("latin-1")


@pytest.mark.parametrize("status_line", ["404 Not Found", "403 Forbidden", "500 Internal Server Error"])
def test_http_error_responses_are_failures_not_samples(tmp_path, status_line):
    body = b"<html>not the payload you are looking for</html>"
    response = (f"HTTP/1.1 {status_line}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    result, _ = _fetch_from_raw(tmp_path, response)

    code = int(status_line.split()[0])
    assert not result.success
    assert result.http_status == code and result.error == f"HTTP {code}"
    assert result.sha256 is None and result.quarantine_path is None
    leftovers = [p for p in (tmp_path / "quarantine").glob("*")
                 if p.suffix in (".bin", ".json") or p.name.startswith(".tmp-")]
    assert leftovers == []


def test_success_records_status_in_result_and_sidecar(tmp_path):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    result, _ = _fetch_from_raw(tmp_path, response)
    assert result.success and result.http_status == 200
    sidecar = json.loads(Path(result.quarantine_path).with_suffix(".json").read_text())
    assert sidecar["http_status"] == 200


def test_request_looks_like_busybox_wget_not_python(tmp_path):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    _, request = _fetch_from_raw(tmp_path, response)
    headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip()
               for l in request.split("\r\n")[1:] if ":" in l}
    assert headers["user-agent"] == "Wget"
    assert "accept-encoding" not in headers      # no gzip: store the bytes a real wget would get
    assert "accept" not in headers
    assert "python" not in request.lower() and "aiohttp" not in request.lower()


def test_user_agent_is_configurable(tmp_path):
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    _, request = _fetch_from_raw(tmp_path, response, user_agent="Wget/1.21.4")
    assert "user-agent: wget/1.21.4" in request.lower()


def test_result_and_sidecar_record_endianness(tmp_path):
    # Big-endian 32-bit MIPS: the same e_machine as MIPSEL, told apart only by EI_DATA.
    ident = bytearray(64)
    ident[0:4] = b"\x7fELF"
    ident[4], ident[5], ident[6] = 1, 2, 1
    struct.pack_into(">H", ident, 18, 8)
    (tmp_path / "www").mkdir()
    (tmp_path / "www" / "gnome").write_bytes(bytes(ident))
    server = _Server(tmp_path / "www")
    try:
        job = make_job("s", "10.0.0.1", server.url("gnome"), "http", "gnome", "wget")
        result = asyncio.run(fetch_and_quarantine(job, _config(tmp_path)))
    finally:
        server.stop()
    assert result.detected_machine == "EM_MIPS" and result.detected_endianness == "big"
    sidecar = json.loads(Path(result.quarantine_path).with_suffix(".json").read_text())
    assert sidecar["detected_endianness"] == "big"


def test_result_and_sidecar_record_flags_and_abi(tmp_path):
    from tests.test_elf import _full_header
    (tmp_path / "www").mkdir()
    (tmp_path / "www" / "telnetd").write_bytes(_full_header(ei_class=1, ei_data=1, e_machine=40, e_flags=0x05000400))
    server = _Server(tmp_path / "www")
    try:
        job = make_job("s", "10.0.0.1", server.url("telnetd"), "http", "telnetd", "wget")
        result = asyncio.run(fetch_and_quarantine(job, _config(tmp_path)))
    finally:
        server.stop()
    assert (result.detected_flags, result.detected_abi) == (0x05000400, "EABI5 hard-float")
    sidecar = json.loads(Path(result.quarantine_path).with_suffix(".json").read_text())
    assert (sidecar["detected_flags"], sidecar["detected_abi"]) == (0x05000400, "EABI5 hard-float")
