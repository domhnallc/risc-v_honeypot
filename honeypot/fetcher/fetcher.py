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
from honeypot.fetcher.ssrf_guard import BlockedDestinationError, SafeTCPConnector


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
    # Final HTTP status (after redirects) when a response was received at all.
    # 4xx/5xx is a failure -- an error page is not a sample -- but the status
    # is kept because "the C2 answered 403" is itself worth knowing.
    http_status: int | None = None
    # Stage two (see honeypot/fetcher/stage2.py). In queued mode the session
    # process cannot read the quarantine, so the worker reports what it found
    # and queued here; each dict is {job_id, url, protocol, requested_filename, depth}.
    stage2_jobs: list[dict] | None = None
    stage2_found: int = 0
    stage2_skipped: int = 0


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
    http_status: int | None = None
    timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)

    try:
        # verify_tls=False is intentional and logged: malware C2 infra
        # commonly serves self-signed certs (spec sec 4.4 step 4).
        #
        # SafeTCPConnector re-validates the destination on every connection
        # this makes -- literal IP, hostname, or a redirect to either --
        # not just the attacker's original URL (see
        # honeypot/fetcher/ssrf_guard.py for why a literal IP address needs
        # more than wrapping the resolver).
        connector_cls = SafeTCPConnector if config.block_private_networks else aiohttp.TCPConnector
        connector = connector_cls(ssl=None if config.verify_tls else False)
        # Look like the BusyBox wget the attacker's own script would have
        # used: its User-Agent, and none of aiohttp's automatic Accept /
        # Accept-Encoding headers -- the latter would also make a server
        # gzip the payload, so we would store something other than the bytes
        # a real wget receives.
        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector,
            headers={"User-Agent": config.user_agent},
            skip_auto_headers=("Accept", "Accept-Encoding"),
        ) as http:
            async with http.get(job.url) as resp:
                http_status = resp.status
                if http_status >= 400:
                    return FetchResult(success=False, http_status=http_status,
                                       error=f"HTTP {http_status}")
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
    except Exception as exc:  # fetch failures are data, not exceptions to propagate
        tmp_path.unlink(missing_ok=True)
        # aiohttp wraps whatever SafeTCPConnector._resolve_host() raises in
        # its own connector exception rather than letting it propagate
        # directly (confirmed: BlockedDestinationError survives only as
        # __cause__) -- walk the chain so operators reading events.jsonl
        # can still tell "attacker pointed this at our own network" apart
        # from an ordinary dead/unreachable URL, distinctly from every
        # other failure reason.
        blocked = exc if isinstance(exc, BlockedDestinationError) else exc.__cause__
        if isinstance(blocked, BlockedDestinationError):
            return FetchResult(success=False, error=f"blocked non-public destination: {blocked}")
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
        http_status=http_status,
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
            "http_status": http_status,
            "depth": job.depth,
            "parent_sha256": job.parent_sha256,
        }, indent=2))
        os.chmod(sidecar, 0o440)

    return result
