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
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from honeypot.config.schema import HoneypotConfig
from honeypot.fetcher.fetcher import FetchResult, fetch_and_quarantine
from honeypot.fetcher.queue import DownloadJob, enqueue_job, make_job
from honeypot.logging.events import EventLogger, TranscriptWriter
from honeypot.shell.commands import dispatch, split_command_line
from honeypot.shell.filesystem import FakeFilesystem
from honeypot.shell import persona as persona_render

_QUEUE_POLL_INTERVAL_SECONDS = 0.3
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
                sha256=fetch_result.sha256, md5=fetch_result.md5,
                size_bytes=fetch_result.size_bytes,
                detected_type=fetch_result.detected_type,
                detected_bitness=fetch_result.detected_bitness,
                detected_machine=fetch_result.detected_machine,
                arch_mismatch=fetch_result.arch_mismatch,
                error=fetch_result.error,
            )
            return self._render_download_response(req, fetch_result), 0 if fetch_result.success else 1

        return result.output, result.status

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
