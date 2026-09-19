"""Stage two planning: turn a quarantined script into follow-on fetch jobs.

Runs on the fetcher side only. In the docker deployment the session container
has no access to var/quarantine on purpose, so it is the fetcher that reads the
sample (bytes, read-only), scans it as text (honeypot.fetcher.script_scan) and
decides which URLs to fetch next. Like fetcher.py, everything here takes only a
DownloadJob / FetchResult / FetcherConfig -- no session or shell state.

The script is attacker-authored, so every URL it lists is untrusted input to
an outbound request. Follow-ups still pass through fetch_and_quarantine (and so
the SSRF guard, size cap and timeout); on top of that the Stage2Limiter bounds
how many can be triggered per script, per session, and how often the same URL
is re-fetched.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from honeypot.config.schema import FetcherConfig
from honeypot.fetcher.fetcher import FetchResult
from honeypot.fetcher.queue import DownloadJob, make_job
from honeypot.fetcher.script_scan import MAX_SCRIPT_BYTES, looks_like_script, scan_script

log = logging.getLogger(__name__)

_MAX_TRACKED = 4096


class Stage2Limiter:
    """Process-wide budgets: per-session URL count, a per-URL cooldown, and a
    per-host cap. The host cap is what stops a script (or many sessions)
    listing endless *distinct* URLs -- `http://victim/?1`, `?2`, ... -- at one
    third party; a genuine dropper serves all its binaries from one host, so
    it only ever needs a few dozen per window."""

    def __init__(self) -> None:
        self._seen_urls: dict[str, float] = {}
        self._per_session: dict[str, int] = {}
        self._per_host: dict[str, list[float]] = {}

    def admit(self, session_id: str, urls: list[str], config: FetcherConfig,
              now: float | None = None) -> list[str]:
        now = time.monotonic() if now is None else now
        self._prune(now, config.stage2_dedupe_seconds)
        used = self._per_session.get(session_id, 0)
        admitted: list[str] = []
        for url in urls:
            if used + len(admitted) >= config.stage2_max_per_session:
                break
            seen_at = self._seen_urls.get(url)
            if seen_at is not None and now - seen_at < config.stage2_dedupe_seconds:
                continue
            host = (urlsplit(url).hostname or "").lower()
            recent = [t for t in self._per_host.get(host, []) if now - t < config.stage2_dedupe_seconds]
            if len(recent) >= config.stage2_max_per_host:
                self._per_host[host] = recent
                continue
            recent.append(now)
            self._per_host[host] = recent
            admitted.append(url)
            self._seen_urls[url] = now
        self._per_session[session_id] = used + len(admitted)
        return admitted

    def _prune(self, now: float, ttl: float) -> None:
        if len(self._seen_urls) > _MAX_TRACKED:
            self._seen_urls = {u: t for u, t in self._seen_urls.items() if now - t < ttl}
            while len(self._seen_urls) > _MAX_TRACKED:
                self._seen_urls.pop(next(iter(self._seen_urls)))
        while len(self._per_session) > _MAX_TRACKED:
            self._per_session.pop(next(iter(self._per_session)))
        while len(self._per_host) > _MAX_TRACKED:
            self._per_host.pop(next(iter(self._per_host)))


DEFAULT_LIMITER = Stage2Limiter()


@dataclass
class Stage2Plan:
    jobs: list[DownloadJob] = field(default_factory=list)
    found: int = 0      # http(s) URLs the scan extracted
    skipped: int = 0    # download commands it could not turn into one

    def summaries(self) -> list[dict]:
        return [{"job_id": j.job_id, "url": j.url, "protocol": j.protocol,
                 "requested_filename": j.requested_filename, "depth": j.depth}
                for j in self.jobs]


def plan_followups(job: DownloadJob, result: FetchResult, config: FetcherConfig,
                   limiter: Stage2Limiter | None = None) -> Stage2Plan:
    """Read a just-quarantined file and plan fetches for the URLs it lists.

    Returns an empty plan for anything that is not a small text script, and
    never raises: a scanning problem must not take the fetcher down.
    """
    plan = Stage2Plan()
    if (not config.stage2_enabled or not result.success or not result.quarantine_path
            or job.depth >= config.stage2_max_depth or result.size_bytes > MAX_SCRIPT_BYTES):
        return plan
    limiter = DEFAULT_LIMITER if limiter is None else limiter
    try:
        with open(result.quarantine_path, "rb") as fh:   # read-only; never opened for anything else
            data = fh.read(MAX_SCRIPT_BYTES + 1)
        if len(data) > MAX_SCRIPT_BYTES or not looks_like_script(data):
            return plan
        scan = scan_script(data.decode("utf-8", errors="replace"), config.stage2_max_urls_per_script)
        plan.found, plan.skipped = len(scan.urls), scan.skipped
        for url in limiter.admit(job.session_id, scan.urls, config):
            parts = urlsplit(url)
            filename = PurePosixPath(parts.path).name or "index.html"
            plan.jobs.append(make_job(
                job.session_id, job.src_ip, url, parts.scheme, filename,
                f"(stage {job.depth + 2}: listed in {job.url})",
                depth=job.depth + 1, parent_sha256=result.sha256,
            ))
    except Exception:  # noqa: BLE001 - see docstring
        log.exception("stage-two scan failed for %s", result.quarantine_path)
        return Stage2Plan()
    return plan
