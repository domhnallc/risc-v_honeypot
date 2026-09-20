#!/usr/bin/env python3
"""Quick command-line status check: the same at-a-glance numbers as
tools/dashboard.py's report, as plain text for a fast glance without a
browser. Reuses dashboard.py's Report for all aggregation, so this and the
HTML dashboard can never disagree about what counts as a "repeat visitor"
or a "real download" -- and adds one thing the dashboard doesn't show:
command patterns grouped across successful logins, which is what actually
distinguishes a credential harvester (sends nothing) from real recon
(uname/id/busybox) from weaponization attempts (apt-get install masscan)
in the raw log.

Usage:
    python3 tools/status_check.py configs/riscv64.yaml
    python3 tools/status_check.py --events var/logs/events.jsonl
    python3 tools/status_check.py --events var/logs/events.jsonl --exclude-ip 1.2.3.4

--exclude-ip drops a source IP's sessions entirely (e.g. your own manual
testing) -- by session, not by event, since most event types
(command.input, file.download, session.closed) don't carry src_ip
directly; filtering on literal event fields alone silently keeps them.

Rotated logs (events.jsonl.1, events.jsonl.2.gz, ...) next to the one you name
are read too (--no-rotated to skip them): logrotate splits the log at midnight
UTC, and reading only events.jsonl would show just "today so far" -- a fresh
rotation looks exactly like the honeypot going quiet.

The "Newest event" line is measured against the unfiltered log, so --exclude-ip
can't hide that nothing has been logged recently; it warns after --stale-minutes
of silence (the honeypot logs a honeypot.heartbeat every few minutes, so
silence means it stopped, not that nobody knocked).
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from dashboard import Report, _load_events, rotated_siblings  # noqa: E402


def _filter_excluded_ips(events: list[dict[str, Any]], exclude_ips: set[str]) -> list[dict[str, Any]]:
    if not exclude_ips:
        return events
    session_ip = {
        e["session_id"]: e["src_ip"] for e in events
        if e.get("event") == "session.connect" and "session_id" in e
    }
    excluded_sessions = {sid for sid, ip in session_ip.items() if ip in exclude_ips}
    return [e for e in events if e.get("session_id") not in excluded_sessions]


def _command_patterns(report: Report) -> Counter[tuple[str, ...]]:
    by_session: dict[str, list[str]] = {}
    for ev in report.events:
        if ev.get("event") == "command.input":
            by_session.setdefault(ev.get("session_id", ""), []).append(ev.get("raw", "").strip())

    success_sessions = {ev["session_id"] for ev in report.events if ev.get("event") == "login.success"}
    patterns: Counter[tuple[str, ...]] = Counter()
    for sid in success_sessions:
        patterns[tuple(by_session.get(sid, []))] += 1
    return patterns


def _download_line(d: dict) -> str:
    """One row of the download list. Stage-two fetches (URLs found by
    scanning a captured script) are tagged so they are not mistaken for
    something the attacker typed, and ELF samples show their architecture --
    the RISC-V ones are what this whole project is looking for."""
    tag = f"[stage {d['stage']}] " if d.get("stage") else ""
    arch = ""
    if d.get("detected_machine"):
        flags = d.get("detected_flags")
        details = [f"{d['detected_bitness']}-bit" if d.get("detected_bitness") else None,
                   d.get("detected_endianness"),
                   # the decoded ABI when there is one; otherwise the raw word, unless it is zero
                   d.get("detected_abi") or (f"flags={flags:#x}" if flags else None)]
        arch = "  " + " ".join([d["detected_machine"], *[x for x in details if x]])
    return f"  {d.get('timestamp')}  {d.get('outcome', '-'):8s}  {tag}{d.get('url')}{arch}"


def _parse_timestamp(value: Any) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _format_age(age: timedelta) -> str:
    minutes = max(0, int(age.total_seconds() // 60))
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m" if hours else f"{minutes}m"


def _liveness_lines(events: list[dict[str, Any]], now: datetime | None = None,
                    stale_minutes: float = 30) -> list[str]:
    """How long since the honeypot last logged anything, and a warning if that is too long."""
    now = now or datetime.now(timezone.utc)
    stamped = [(t, e) for e in events if (t := _parse_timestamp(e.get("timestamp"))) is not None]
    if not stamped:
        return ["Newest event: (none in this log)"]
    newest, _ = max(stamped, key=lambda pair: pair[0])
    age = now - newest
    lines = [f"Newest event: {newest:%Y-%m-%dT%H:%M:%SZ}  ({_format_age(age)} ago)"]
    heartbeats = [t for t, e in stamped if e.get("event") == "honeypot.heartbeat"]
    if heartbeats:
        lines.append(f"Heartbeat:    last {max(heartbeats):%Y-%m-%dT%H:%M:%SZ}, {len(heartbeats)} in this log")
    if age > timedelta(minutes=stale_minutes):
        lines.append(f"WARNING:      nothing logged for {_format_age(age)}. If this is the live log, the honeypot "
                     "may be down: check `docker compose ps` and `docker compose logs honeypot`.")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", nargs="?", help="honeypot config YAML, used to find the events log by default")
    parser.add_argument("--events", help="explicit path to events.jsonl (overrides --config-derived path)")
    parser.add_argument("--exclude-ip", action="append", default=[], metavar="IP",
                         help="source IP to exclude entirely (e.g. your own testing IP); repeatable")
    parser.add_argument("--top", type=int, default=10, help="rows per top-N list (default 10)")
    parser.add_argument("--no-rotated", action="store_true",
                         help="read only the named log, not its rotated events.jsonl.N[.gz] siblings")
    parser.add_argument("--stale-minutes", type=float, default=30,
                         help="warn if nothing has been logged for this long (default 30)")
    args = parser.parse_args()

    if args.events:
        events_path = Path(args.events)
    elif args.config:
        from honeypot.config import load_config
        config = load_config(args.config)
        events_path = Path(config.logging.log_dir) / config.logging.json_log_filename
    else:
        parser.error("pass either a config YAML or --events path/to/events.jsonl")
        return

    include_rotated = not args.no_rotated
    all_events = _load_events(events_path, include_rotated=include_rotated)
    if include_rotated and (rotated := rotated_siblings(events_path)):
        print(f"(also read {len(rotated)} rotated log file(s): {rotated[0].name} .. {rotated[-1].name})",
              file=sys.stderr)
    events = _filter_excluded_ips(all_events, set(args.exclude_ip))
    report = Report(events)

    total_logins = report.login_success + report.login_failed
    pct = (100 * report.login_success / total_logins) if total_logins else 0.0
    protocols = Counter(s["protocol"] for s in report.sessions.values())
    successful_downloads = sum(1 for d in report.downloads if d.get("outcome") == "success")

    print(f"Window:       {report.first_seen or '-'}  to  {report.last_seen or '-'}")
    for line in _liveness_lines(all_events, stale_minutes=args.stale_minutes):
        print(line)
    print(f"Volume:       {len(report.sessions)} sessions")
    print(f"Unique IPs:   {len(report.unique_ips)}")
    print(f"Protocols:    {dict(protocols)}")
    print(f"Logins:       {report.login_success} succeeded / {total_logins} total ({pct:.1f}%)")
    print(f"Off-wordlist: {len(report.off_list_logins)} credential attempts")
    print(f"Downloads:    {len(report.downloads)} attempts, {successful_downloads} succeeded")
    print(f"Repeat IPs:   {len(report.repeat_visitor_ips)} logged in successfully more than once")

    print(f"\nTop {args.top} source IPs:")
    for ip in report.unique_ips[: args.top]:
        print(f"  {report.ip_session_counts[ip]:5d}  {ip}")

    patterns = _command_patterns(report)
    blank_count = patterns[()] + patterns[("",)]
    notable = [(p, c) for p, c in patterns.most_common() if p not in ((), ("",))]
    print(f"\nCommand patterns across successful logins ({blank_count} sent nothing -- harvester-style):")
    if notable:
        for pattern, count in notable[: args.top]:
            print(f"  {count:5d}  {pattern}")
    else:
        print("  (none -- every successful login sent nothing)")

    if report.downloads:
        print("\nDownload attempts:")
        for d in report.downloads:
            print(_download_line(d))

    if report.repeat_visitor_ips:
        print(f"\nTop {args.top} repeat visitors:")
        for ip, logins in report.repeat_visitor_ips[: args.top]:
            usernames = sorted({e.get("username", "") for e in logins})
            print(f"  {len(logins):3d} logins  {ip:16s} usernames: {', '.join(usernames)}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # `status_check.py | head`: the reader closed the pipe on purpose, which
        # is not an error. Left alone, Python prints a traceback and then a
        # second "Exception ignored" when it flushes stdout at shutdown; point
        # stdout at /dev/null so that final flush is silent too.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
