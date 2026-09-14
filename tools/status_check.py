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
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from dashboard import Report, _load_events  # noqa: E402


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", nargs="?", help="honeypot config YAML, used to find the events log by default")
    parser.add_argument("--events", help="explicit path to events.jsonl (overrides --config-derived path)")
    parser.add_argument("--exclude-ip", action="append", default=[], metavar="IP",
                         help="source IP to exclude entirely (e.g. your own testing IP); repeatable")
    parser.add_argument("--top", type=int, default=10, help="rows per top-N list (default 10)")
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

    events = _filter_excluded_ips(_load_events(events_path), set(args.exclude_ip))
    report = Report(events)

    total_logins = report.login_success + report.login_failed
    pct = (100 * report.login_success / total_logins) if total_logins else 0.0
    protocols = Counter(s["protocol"] for s in report.sessions.values())
    successful_downloads = sum(1 for d in report.downloads if d.get("outcome") == "success")

    print(f"Window:       {report.first_seen or '-'}  to  {report.last_seen or '-'}")
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
            print(f"  {d.get('timestamp')}  {d.get('outcome', '-'):8s}  {d.get('url')}")

    if report.repeat_visitor_ips:
        print(f"\nTop {args.top} repeat visitors:")
        for ip, logins in report.repeat_visitor_ips[: args.top]:
            usernames = sorted({e.get("username", "") for e in logins})
            print(f"  {len(logins):3d} logins  {ip:16s} usernames: {', '.join(usernames)}")


if __name__ == "__main__":
    main()
