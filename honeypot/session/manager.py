"""Per-connection session state machine, shared by the SSH and Telnet listeners.

Spec sec 4.1 requires both listeners to feed into one Session Manager so
command parsing/logging is shared code rather than duplicated per protocol --
this is that shared code. It owns login handling, dispatches command lines to
honeypot.shell.commands, hands download requests off to the isolated fetcher,
and writes both the structured JSON events and the raw transcript.
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import time
import uuid
from http import HTTPStatus
from pathlib import Path
from urllib.parse import urlsplit

from honeypot.config.schema import HoneypotConfig
from honeypot.fetcher.fetcher import FetchResult, fetch_and_quarantine
from honeypot.fetcher.queue import DownloadJob, enqueue_job, make_job
from honeypot.logging.events import EventLogger, TranscriptWriter
from honeypot.fetcher.stage2 import Stage2Plan, plan_followups
from honeypot.shell.commands import dispatch, split_command_line
from honeypot.shell.filesystem import FakeFilesystem
from honeypot.shell import persona as persona_render

_QUEUE_POLL_INTERVAL_SECONDS = 0.3
_log = logging.getLogger(__name__)
_STAGE2_POLL_INTERVAL_SECONDS = 1.0
_QUEUE_RESULT_GRACE_SECONDS = 5.0  # slack on top of fetcher.timeout_seconds for queue latency


def _wget_error_text(error: str | None) -> str:
    """Map an internal fetch-failure reason to one of a small set of
    plausible busybox wget error lines -- never the raw exception text.

    The raw aiohttp/asyncio exception string can include internal network
    detail (which port refused vs timed out vs failed DNS) that lets an
    attacker use wget as a blind scanner against whatever network the
    fetcher can reach. Collapsing every real network failure to the same
    generic line closes that off; only our own explicit, non-sensitive
    failure reasons (bad protocol, oversized transfer) get a distinct,
    still-generic message.
    """
    error = error or ""
    m = re.fullmatch(r"HTTP (\d{3})", error)
    if m:
        # Unlike a connect/DNS error, an HTTP status only exists after a real
        # connection to a public host (the SSRF guard refuses internal
        # destinations before any request is made), so echoing it -- as real
        # BusyBox wget does -- tells the attacker nothing about our network.
        status = int(m.group(1))
        try:
            reason = HTTPStatus(status).phrase
        except ValueError:
            reason = "Error"
        return f"server returned error: HTTP/1.1 {status} {reason}"
    if "not permitted" in error or "not yet implemented" in error:
        return "not an http or ftp url"
    if "exceeded max_file_size_bytes" in error:
        return "transfer closed with file not completely written"
    if "waiting for isolated fetcher" in error:
        # Queued-mode-only: the worker process never responded in time.
        # Safe to show verbatim-ish -- it doesn't vary with the attacker's
        # chosen URL/destination, so it can't be used to fingerprint what's
        # reachable, unlike a real per-target network error would.
        return "timed out waiting for a response"
    return "can't connect to remote host"


def new_session_id() -> str:
    return uuid.uuid4().hex[:16]


# Longest input line/exec command we will process or record. Matches the
# Telnet listener's per-line cap; a real dropper one-liner is well under 2 KB.
MAX_INPUT_CHARS = 8192


# Strong references to in-flight stage-two tasks: they outlive the command that
# started them (and often the session), and asyncio only weakly references tasks.
_BACKGROUND_TASKS: set[asyncio.Task] = set()


class SessionManager:
    def __init__(self, src_ip: str, src_port: int, dst_port: int, protocol: str,
                 config: HoneypotConfig, event_logger: EventLogger,
                 client_id: str | None = None, session_id: str | None = None) -> None:
        self.session_id = session_id or new_session_id()
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.client_id = client_id
        self.config = config
        self.events = event_logger
        self.transcript = TranscriptWriter(config.logging.transcript_dir, self.session_id)

        self.fs = FakeFilesystem(config.persona)
        self.authenticated = False
        self.username: str | None = None
        self.should_exit = False
        self._connect_time = time.monotonic()
        self._command_count = 0
        self._closed = False
        self._download_count = 0
        self._stage2_tasks: list[asyncio.Task] = []

    # -- lifecycle -----------------------------------------------------

    def on_connect(self) -> None:
        self.events.session_connect(
            self.session_id, self.src_ip, self.src_port, self.dst_port,
            self.protocol, self.client_id,
        )

    def on_disconnect(self, reason: str) -> None:
        # Idempotent: an SSH connection can outlive several exec channels, so
        # both the channel handler and connection_lost may call this.
        if self._closed:
            return
        self._closed = True
        duration = time.monotonic() - self._connect_time
        self.events.session_closed(self.session_id, duration, reason)
        self.transcript.close()

    def on_client_version(self, client_id: str) -> None:
        self.client_id = client_id
        self.events.client_version(self.session_id, client_id)

    def on_auth_attempt(self, method: str, username: str, **details) -> None:
        self.events.auth_attempt(self.session_id, method=method, username=username,
                                 src_ip=self.src_ip, **details)

    def record_recv(self, data: bytes) -> None:
        self.transcript.record("recv", data)

    def record_send(self, data: bytes) -> None:
        self.transcript.record("send", data)

    # -- auth ------------------------------------------------------------

    def try_login(self, username: str, password: str) -> bool:
        credentials = self.config.credentials
        accepted = credentials.accepts(username, password)
        self.events.login_attempt(
            self.session_id, username, password, accepted, self.src_ip,
            username_known=credentials.is_known_username(username),
            password_known=credentials.is_known_password(password),
        )
        if accepted:
            self.authenticated = True
            self.username = username
        return accepted

    def banner(self) -> str:
        if self.protocol == "ssh":
            return persona_render.ssh_banner(self.config.persona)
        return persona_render.login_banner(self.config.persona)

    def prompt(self) -> str:
        user = self.username or "root"
        return f"{user}@{self.config.persona.hostname}:{self.fs.cwd_display()}# "

    # -- commands ----------------------------------------------------------

    async def handle_command(self, raw: str) -> str:
        """Log the input line once, then run each `;` / `&&` / `||` segment.

        Real droppers send one-liners like `cd /tmp || cd /var/run; wget A;
        chmod +x A; ./A` -- dispatching the line as a single command meant
        the wget was never seen. Exit status is tracked only well enough to
        pick the right arm of `&&` / `||` (skipped segments leave it alone,
        as in a real shell).
        """
        self._command_count += 1
        tokens = raw.strip().split()
        command_name = tokens[0] if tokens else ""
        self.events.command_input(self.session_id, raw, command_name, tokens[1:])

        segments = split_command_line(raw.rstrip("\n").rstrip("\r")) or [(";", "")]
        outputs: list[str] = []
        status = 0
        for op, segment in segments:
            if (op == "&&" and status != 0) or (op == "||" and status == 0):
                continue
            output, status = await self._run_segment(segment)
            if output:
                outputs.append(output)
            if self.should_exit:
                break
        return "\n".join(outputs)

    async def _run_segment(self, raw: str) -> tuple[str, int]:
        result = dispatch(raw, self.fs, self.config.persona, self.username)
        if result.exit_session:
            self.should_exit = True

        if result.execution_attempt is not None:
            self.events.execution_attempt(self.session_id, raw, result.execution_attempt)

        if result.download_request is not None:
            req = result.download_request
            self._download_count += 1
            if self._download_count > self.config.fetcher.max_downloads_per_session:
                self.events.file_download(
                    self.session_id, url=req.url, protocol=req.protocol,
                    requested_filename=req.requested_filename, raw_command=raw,
                    outcome="failed", error="per-session download limit reached",
                )
                # Same generic failure line as any unreachable host, so the
                # cap itself isn't an obvious tell.
                return f"Connecting to {urlsplit(req.url).netloc or req.url}\nwget: can't connect to remote host", 1
            self.events.file_download(
                self.session_id, url=req.url, protocol=req.protocol,
                requested_filename=req.requested_filename, raw_command=raw,
                outcome="requested",
            )
            job = make_job(self.session_id, self.src_ip, req.url, req.protocol,
                            req.requested_filename, raw)
            if self.config.fetcher.mode == "queued":
                fetch_result = await self._fetch_via_queue(job)
            else:
                fetch_result = await fetch_and_quarantine(job, self.config.fetcher,
                                                            self.config.persona.arch)
            self.events.file_download(
                self.session_id, url=req.url, protocol=req.protocol,
                requested_filename=req.requested_filename, raw_command=raw,
                outcome="success" if fetch_result.success else "failed",
                **self._result_fields(fetch_result),
            )
            self._start_stage2(job, fetch_result)
            return self._render_download_response(req, fetch_result), 0 if fetch_result.success else 1

        return result.output, result.status

    @staticmethod
    def _result_fields(fetch_result: FetchResult) -> dict:
        return dict(
            sha256=fetch_result.sha256, md5=fetch_result.md5,
            size_bytes=fetch_result.size_bytes,
            detected_type=fetch_result.detected_type,
            detected_bitness=fetch_result.detected_bitness,
            detected_machine=fetch_result.detected_machine,
            detected_endianness=fetch_result.detected_endianness,
            arch_mismatch=fetch_result.arch_mismatch,
            error=fetch_result.error,
            http_status=fetch_result.http_status,
        )

    # -- stage two: follow-on downloads listed inside a fetched script ------
    #
    # Runs in the background so the attacker's own `wget` is answered at once.
    # Inline mode plans and fetches here (this process *is* the fetcher);
    # queued mode never reads the quarantine -- the worker plans, queues the
    # follow-ups and reports them in the parent's result, and this side only
    # polls for their outcomes to log.

    def _start_stage2(self, job: DownloadJob, fetch_result: FetchResult) -> None:
        fetcher = self.config.fetcher
        if not fetcher.stage2_enabled or not fetch_result.success:
            return
        if fetcher.mode == "queued":
            if not (fetch_result.stage2_jobs or fetch_result.stage2_found or fetch_result.stage2_skipped):
                return
            coro = self._collect_stage2_queued(job, fetch_result)
        else:
            coro = self._run_stage2_inline(job, fetch_result)
        task = asyncio.ensure_future(coro)
        _BACKGROUND_TASKS.add(task)
        task.add_done_callback(_BACKGROUND_TASKS.discard)
        self._stage2_tasks.append(task)

    async def wait_stage2(self) -> None:
        """Wait for this session's stage-two work (used by tests and shutdown)."""
        await asyncio.gather(*self._stage2_tasks, return_exceptions=True)

    def _log_stage2_scan(self, parent_url: str, parent_sha256: str | None, depth: int,
                         found: int, queued: int, skipped: int) -> None:
        if found or skipped:
            self.events.stage2_scan(
                self.session_id, parent_url=parent_url, parent_sha256=parent_sha256,
                stage=depth + 1, urls_found=found, urls_queued=queued, skipped=skipped,
            )

    def _log_stage2_outcome(self, url: str, protocol: str, filename: str, depth: int,
                            parent_url: str, parent_sha256: str | None,
                            fetch_result: FetchResult) -> None:
        self.events.file_download(
            self.session_id, url=url, protocol=protocol, requested_filename=filename,
            raw_command=f"(stage {depth + 1}: listed in {parent_url})",
            outcome="success" if fetch_result.success else "failed",
            stage=depth + 1, parent_url=parent_url, parent_sha256=parent_sha256,
            **self._result_fields(fetch_result),
        )

    async def _run_stage2_inline(self, job: DownloadJob, fetch_result: FetchResult) -> None:
        try:
            pending: list[tuple[DownloadJob, FetchResult]] = [(job, fetch_result)]
            while pending:
                parent_job, parent_result = pending.pop(0)
                plan: Stage2Plan = plan_followups(parent_job, parent_result, self.config.fetcher)
                self._log_stage2_scan(parent_job.url, parent_result.sha256, parent_job.depth,
                                      plan.found, len(plan.jobs), plan.skipped)
                for child in plan.jobs:
                    child_result = await fetch_and_quarantine(child, self.config.fetcher,
                                                               self.config.persona.arch)
                    self._log_stage2_outcome(child.url, child.protocol, child.requested_filename,
                                             child.depth, parent_job.url, parent_result.sha256,
                                             child_result)
                    pending.append((child, child_result))
        except Exception:  # noqa: BLE001 - a background task has nobody to raise to
            _log.exception("stage-two fetch failed for session %s", self.session_id)

    async def _collect_stage2_queued(self, job: DownloadJob, fetch_result: FetchResult) -> None:
        try:
            self._log_stage2_scan(job.url, fetch_result.sha256, job.depth, fetch_result.stage2_found,
                                  len(fetch_result.stage2_jobs or []), fetch_result.stage2_skipped)
            # (parent url, parent sha256, follow-up job summary)
            pending = [(job.url, fetch_result.sha256, info) for info in fetch_result.stage2_jobs or []]
            deadline = time.monotonic() + self.config.fetcher.stage2_wait_seconds
            processing = Path(self.config.fetcher.jobs_dir) / ".processing"
            while pending and time.monotonic() < deadline:
                waiting = []
                for parent_url, parent_sha, info in pending:
                    # The result file comes from the fetcher container, the
                    # more exposed of the two: treat its job_id as untrusted
                    # and never let it steer a path outside .processing/.
                    job_id = str(info.get("job_id", ""))
                    child = (self._load_fetch_result(processing / f"{job_id}.result.json")
                             if job_id and Path(job_id).name == job_id and job_id not in (".", "..")
                             else FetchResult(success=False, error="invalid follow-up job id"))
                    if child is None:
                        waiting.append((parent_url, parent_sha, info))
                        continue
                    self._log_stage2_outcome(info["url"], info["protocol"], info["requested_filename"],
                                             info["depth"], parent_url, parent_sha, child)
                    self._log_stage2_scan(info["url"], child.sha256, info["depth"], child.stage2_found,
                                          len(child.stage2_jobs or []), child.stage2_skipped)
                    waiting.extend((info["url"], child.sha256, grandchild)
                                   for grandchild in child.stage2_jobs or [])
                pending = waiting
                if pending:
                    await asyncio.sleep(_STAGE2_POLL_INTERVAL_SECONDS)
            for parent_url, parent_sha, info in pending:
                self._log_stage2_outcome(
                    info["url"], info["protocol"], info["requested_filename"], info["depth"],
                    parent_url, parent_sha,
                    FetchResult(success=False, error="timed out waiting for isolated fetcher"))
        except Exception:  # noqa: BLE001
            _log.exception("stage-two collection failed for session %s", self.session_id)

    @staticmethod
    def _load_fetch_result(result_path: Path) -> FetchResult | None:
        """The worker's result file as a FetchResult, or None if not there (yet)."""
        try:
            data = json.loads(result_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None
        result_fields = {f.name for f in dataclasses.fields(FetchResult)}
        return FetchResult(**{k: v for k, v in data.items() if k in result_fields})

    async def _fetch_via_queue(self, job: DownloadJob) -> FetchResult:
        """"queued" mode: enqueue the job and poll for the result a separate
        `honeypot.fetcher.worker` process writes, rather than fetching here.

        This is what actually makes the network-isolation split in
        docker-compose.yml true rather than aspirational: this process never
        calls fetch_and_quarantine() itself in this mode, so it never
        performs the outbound request to attacker-controlled infrastructure.
        """
        enqueue_job(self.config.fetcher.jobs_dir, job)
        result_path = Path(self.config.fetcher.jobs_dir) / ".processing" / f"{job.job_id}.result.json"
        deadline = time.monotonic() + self.config.fetcher.timeout_seconds + _QUEUE_RESULT_GRACE_SECONDS
        result_fields = {f.name for f in dataclasses.fields(FetchResult)}
        while time.monotonic() < deadline:
            if result_path.exists():
                try:
                    data = json.loads(result_path.read_text())
                except (json.JSONDecodeError, OSError):
                    await asyncio.sleep(_QUEUE_POLL_INTERVAL_SECONDS)
                    continue
                return FetchResult(**{k: v for k, v in data.items() if k in result_fields})
            await asyncio.sleep(_QUEUE_POLL_INTERVAL_SECONDS)
        return FetchResult(success=False, error="timed out waiting for isolated fetcher")

    def _render_download_response(self, req, fetch_result) -> str:
        host = urlsplit(req.url).netloc or req.url
        if fetch_result.success:
            return (
                f"Connecting to {host}\n"
                f"saving to '{req.requested_filename}'\n"
                f"{req.requested_filename}          100% |***************************|"
                f"  {fetch_result.size_bytes // 1024 or 1}k  0:00:00 ETA\n"
                f"'{req.requested_filename}' saved"
            )
        return f"Connecting to {host}\nwget: {_wget_error_text(fetch_result.error)}"
