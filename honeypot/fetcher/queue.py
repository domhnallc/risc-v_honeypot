"""File-based job queue between the session handler and the isolated fetcher.

Spec sec 3/4.4 requires the component that talks to attackers to never itself
perform the outbound fetch. The handoff here is deliberately dumb: a JSON job
file written to a watched directory, atomically renamed into place so a job
is either fully there or not there at all -- no shared memory or RPC between
the session process and the fetcher.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class DownloadJob:
    job_id: str
    session_id: str
    src_ip: str
    url: str
    protocol: str
    requested_filename: str
    raw_command: str
    timestamp: float


def make_job(session_id: str, src_ip: str, url: str, protocol: str,
             requested_filename: str, raw_command: str) -> DownloadJob:
    ts = time.time()
    return DownloadJob(
        job_id=f"{ts:.6f}-{uuid.uuid4().hex[:8]}",
        session_id=session_id, src_ip=src_ip, url=url, protocol=protocol,
        requested_filename=requested_filename, raw_command=raw_command,
        timestamp=ts,
    )


def enqueue_job(jobs_dir: str | Path, job: DownloadJob) -> Path:
    """Atomically write a job file: write to a temp name, then rename.

    The rename is atomic on POSIX filesystems, so the fetcher never observes
    a partially-written job file.
    """
    jobs_dir = Path(jobs_dir)
    jobs_dir.mkdir(parents=True, exist_ok=True)
    final_path = jobs_dir / f"{job.job_id}.json"
    tmp_path = jobs_dir / f".{job.job_id}.json.tmp"
    tmp_path.write_text(json.dumps(asdict(job)))
    tmp_path.rename(final_path)
    return final_path


def claim_pending_jobs(jobs_dir: str | Path) -> list[tuple[Path, DownloadJob]]:
    """Claim all pending job files by moving them into a `.processing` subdir.

    Claiming (rather than reading in place) means two fetcher instances can
    never double-process the same job, and a crash mid-fetch leaves the job
    file sitting in `.processing` for inspection rather than silently lost.
    Used by the standalone out-of-process worker (honeypot/fetcher/worker.py);
    the default in-process v1 path does not need this.
    """
    jobs_dir = Path(jobs_dir)
    processing_dir = jobs_dir / ".processing"
    processing_dir.mkdir(parents=True, exist_ok=True)
    claimed = []
    for path in sorted(jobs_dir.glob("*.json")):
        dest = processing_dir / path.name
        try:
            path.rename(dest)
        except OSError:
            continue
        job = DownloadJob(**json.loads(dest.read_text()))
        claimed.append((dest, job))
    return claimed
