"""Isolated fetcher: retrieves a URL and quarantines the result (spec sec 4.4).

This module is the only place in the codebase that performs an outbound
network fetch of attacker-supplied URLs, and it never executes, loads, or
interprets what it downloads -- it only streams bytes to disk, hashes them,
and runs the static detector in honeypot.fetcher.elf.

Every function here takes only a DownloadJob + FetcherConfig, with no
reference to session/shell state, so it can be lifted into a separate
process/container (see honeypot/fetcher/worker.py) without changing this
file -- v1 runs it in-process, which spec sec 3 explicitly allows during
initial development.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from honeypot.config.schema import FetcherConfig
from honeypot.fetcher import elf
from honeypot.fetcher.queue import DownloadJob
from honeypot.fetcher.ssrf_guard import BlockedDestinationError, SafeResolver


@dataclass
class FetchResult:
    success: bool
    sha256: str | None = None
    md5: str | None = None
    size_bytes: int = 0
    detected_type: str | None = None
    detected_bitness: int | None = None
    detected_machine: str | None = None
    arch_mismatch: bool | None = None
    quarantine_path: str | None = None
    error: str | None = None


async def fetch_and_quarantine(job: DownloadJob, config: FetcherConfig,
                                persona_arch: str | None = None) -> FetchResult:
    protocol = job.protocol.lower()
    if protocol not in config.allowed_protocols:
        return FetchResult(success=False, error=f"protocol '{protocol}' not permitted by fetcher config")
    if protocol not in ("http", "https"):
        # TFTP/FTP clients are common in IoT droppers but not implemented in
        # v1 (spec sec 4.4 only requires that the *request* be logged, which
        # the caller already does before this function is ever invoked).
        return FetchResult(success=False, error=f"protocol '{protocol}' not yet implemented")

    quarantine_dir = Path(config.quarantine_dir)
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = quarantine_dir / f".tmp-{job.job_id}"

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)

    try:
        # verify_tls=False is intentional and logged: malware C2 infra
        # commonly serves self-signed certs (spec sec 4.4 step 4).
        #
        # resolver=SafeResolver() re-validates the destination on every DNS
        # lookup this connector makes -- not just the attacker's original
        # URL -- so a redirect to an internal address is blocked exactly
        # like a direct one would be (see honeypot/fetcher/ssrf_guard.py).
        connector = aiohttp.TCPConnector(
            ssl=None if config.verify_tls else False,
            resolver=SafeResolver() if config.block_private_networks else None,
        )
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as http:
            async with http.get(job.url) as resp:
                with tmp_path.open("wb") as fh:
                    async for chunk in resp.content.iter_chunked(65536):
                        size += len(chunk)
                        if size > config.max_file_size_bytes:
                            raise ValueError(
                                "payload exceeded max_file_size_bytes "
                                f"({config.max_file_size_bytes})"
                            )
                        sha256.update(chunk)
                        md5.update(chunk)
                        fh.write(chunk)
    except BlockedDestinationError as exc:
        # Tagged distinctly from other failures so operators reading
        # events.jsonl can tell "attacker pointed this at our own network"
        # apart from an ordinary dead/unreachable URL.
        tmp_path.unlink(missing_ok=True)
        return FetchResult(success=False, error=f"blocked non-public destination: {exc}")
    except Exception as exc:  # fetch failures are data, not exceptions to propagate
        tmp_path.unlink(missing_ok=True)
        return FetchResult(success=False, error=str(exc))

    digest = sha256.hexdigest()
    final_path = quarantine_dir / f"{digest}.bin"
    sidecar = final_path.with_suffix(".json")

    # An identical payload (same sha256) may already be quarantined from an
    # earlier fetch, with its .bin/.json chmod 0o440 per guarantee #3
    # ("quarantine, don't touch"). Re-fetching it must not try to overwrite
    # that read-only sidecar below -- that raises PermissionError, which
    # previously went uncaught and killed the whole session. Treat a hash
    # already on file as a successful capture without re-touching it.
    already_quarantined = final_path.exists()
    if already_quarantined:
        tmp_path.unlink(missing_ok=True)
    else:
        os.replace(tmp_path, final_path)
        os.chmod(final_path, 0o440)  # read-only, non-executable from this point on

    detected = elf.detect(final_path.read_bytes()[:64])
    arch_mismatch = None
    if persona_arch is not None:
        matched = elf.arch_matches_persona(detected, persona_arch)
        if matched is not None:
            arch_mismatch = not matched

    result = FetchResult(
        success=True,
        sha256=digest,
        md5=md5.hexdigest(),
        size_bytes=size,
        detected_type=detected.file_type,
        detected_bitness=detected.bitness,
        detected_machine=detected.machine,
        arch_mismatch=arch_mismatch,
        quarantine_path=str(final_path),
    )

    if not already_quarantined:
        sidecar.write_text(json.dumps({
            "session_id": job.session_id,
            "src_ip": job.src_ip,
            "url": job.url,
            "protocol": job.protocol,
            "requested_filename": job.requested_filename,
            "timestamp": time.time(),
            "size_bytes": size,
            "sha256": digest,
            "md5": result.md5,
            "detected_type": result.detected_type,
            "detected_bitness": result.detected_bitness,
            "detected_machine": result.detected_machine,
            "arch_mismatch": arch_mismatch,
        }, indent=2))
        os.chmod(sidecar, 0o440)

    return result
