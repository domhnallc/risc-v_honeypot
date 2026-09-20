"""Standalone fetcher worker process (production deployment mode).

Run this as a separate OS process -- ideally in its own network namespace or
container with no route back to the honeypot's internal management network
(spec sec 2.4) -- to get the full physical isolation the spec recommends for
production, instead of the in-process fetcher task main.py runs for v1/dev.

Usage: python -m honeypot.fetcher.worker path/to/config.yaml
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import sys
import time

from honeypot.config import load_config
from honeypot.fetcher.fetcher import fetch_and_quarantine
from honeypot.fetcher.queue import claim_pending_jobs, enqueue_job
from honeypot.fetcher.stage2 import Stage2Limiter, plan_followups
from honeypot.logging.sanitize import setup_logging

POLL_INTERVAL_SECONDS = 2.0


async def process_pending(config, limiter: Stage2Limiter | None = None) -> int:
    """One pass over the job queue; returns how many jobs were processed.

    Stage-two follow-ups are queued as ordinary jobs *after* the parent's
    result is written, so the attacker-facing session is never held up by
    them and a long chain cannot monopolise the worker -- they interleave with
    other sessions' jobs in FIFO order.
    """
    processed = 0
    for job_path, job in claim_pending_jobs(config.fetcher.jobs_dir):
        result = await fetch_and_quarantine(job, config.fetcher, config.persona.arch)
        plan = plan_followups(job, result, config.fetcher, limiter)
        result.stage2_jobs = plan.summaries() or None
        result.stage2_found, result.stage2_skipped = plan.found, plan.skipped
        # Full FetchResult, not just a subset -- SessionManager (running
        # in a different process in "queued" mode) reconstructs a
        # FetchResult from exactly these fields to log/render the
        # outcome, so this must stay a superset of FetchResult's fields.
        payload = {"job_id": job.job_id, "processed_at": time.time(), **dataclasses.asdict(result)}
        result_path = job_path.with_suffix(".result.json")
        tmp_path = result_path.with_suffix(".result.json.tmp")
        tmp_path.write_text(json.dumps(payload))
        tmp_path.rename(result_path)  # atomic: the poller never sees a partial write
        for followup in plan.jobs:
            enqueue_job(config.fetcher.jobs_dir, followup)
        processed += 1
        print(f"[fetcher-worker] processed {job.job_id} (depth {job.depth}): "
              f"success={result.success} followups={len(plan.jobs)}", file=sys.stderr)
    return processed


async def run(config_path: str) -> None:
    config = load_config(config_path)
    setup_logging(config.logging.level)   # the worker's own log lines get the same control-character escaping
    print(f"[fetcher-worker] watching {config.fetcher.jobs_dir}", file=sys.stderr)
    while True:
        await process_pending(config)
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: python -m honeypot.fetcher.worker <config.yaml>", file=sys.stderr)
        raise SystemExit(2)
    asyncio.run(run(sys.argv[1]))


if __name__ == "__main__":
    main()
