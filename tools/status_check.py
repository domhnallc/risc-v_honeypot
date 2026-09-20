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


# Everything below that comes from the event log -- usernames, URLs, SSH client
# banners, key fingerprints -- is attacker-controlled text, and this tool prints it
# to an operator's terminal. A crafted username can carry escape sequences (retitle
# the window, move the cursor to overwrite earlier lines, and in some terminals do
# worse), a newline that fakes an extra row, or a bidi override that reverses what
# you read. The HTML dashboard escapes all of this; the CLI now shows such
# characters as a visible \xNN / \uNNNN instead of acting on them.
_UNSAFE_CHARS = {c: f"\\x{c:02x}" for c in (*range(0x20), 0x7F, *range(0x80, 0xA0))}
_UNSAFE_CHARS.update({
    c: f"\\u{c:04x}"
    for c in (*range(0x200B, 0x2010), 0x2028, 0x2029, *range(0x202A, 0x202F),
              *range(0x2060, 0x2065), *range(0x2066, 0x206A), 0xFEFF)
})


def _printable(value: Any) -> str:
    return str(value).translate(_UNSAFE_CHARS)


def _ssh_summary(events: list[dict[str, Any]], top: int = 10, idle_seconds: float = 30) -> list[str]:
    """Who is connecting (SSH client banners), what non-password auth they try, and
    which sessions sit silent. Empty for a log from before those events existed."""
    ip_of = {e["session_id"]: e.get("src_ip") for e in events
             if e.get("event") == "session.connect" and "session_id" in e}
    client_of = {e["session_id"]: e.get("client_id") for e in events
                 if e.get("event") == "session.client_version" and "session_id" in e}
    attempts = [e for e in events if e.get("event") == "auth.attempt"]
    lines: list[str] = []

    if client_of:
        counts = Counter(client_of.values())
        lines.append(f"\nSSH client versions ({len(client_of)} sessions, {len(counts)} distinct):")
        lines += [f"  {n:5d}  {_printable(v)}" for v, n in counts.most_common(top)]

    if attempts:
        methods = Counter(a.get("method") for a in attempts)
        keys: dict[str, dict[str, Any]] = {}
        for a in attempts:
            if a.get("method") == "publickey" and a.get("key_fingerprint"):
                k = keys.setdefault(a["key_fingerprint"], {"type": a.get("key_type"), "ips": set(), "n": 0})
                k["ips"].add(a.get("src_ip"))
                k["n"] += 1
        summary = ", ".join(f"{_printable(m)} {n}" for m, n in methods.most_common())
        lines.append(f"\nNon-password auth attempts: {len(attempts)} ({summary}), "
                     f"{len(keys)} distinct public keys")
        shared = sorted(((len(k["ips"]), fp, k) for fp, k in keys.items() if len(k["ips"]) > 1),
                        key=lambda t: (-t[0], t[1]))
        if shared:
            lines.append("  Keys offered from more than one source IP (one campaign or toolkit):")
            lines += [f"    {n_ips:3d} IPs  {_printable(k['type'])}  {_printable(fp)}" for n_ips, fp, k in shared[:top]]
        users = Counter(a.get("username") for a in attempts)
        lines.append("  Usernames: " + ", ".join(f"{_printable(u)} x{n}" for u, n in users.most_common(top)))

    # Sessions that stayed connected a while without ever trying a login or a command.
    active = {e["session_id"] for e in events
              if e.get("event") in ("login.success", "login.failed", "command.input") and "session_id" in e}
    methods_of: dict[str, set[str]] = {}
    for a in attempts:
        methods_of.setdefault(a.get("session_id"), set()).add(str(a.get("method")))
    silent: Counter[tuple[Any, Any, tuple[str, ...]]] = Counter()
    for e in events:
        if (e.get("event") == "session.closed" and e.get("session_id") not in active
                and isinstance(e.get("duration_seconds"), (int, float)) and e["duration_seconds"] > idle_seconds):
            sid = e.get("session_id")
            silent[(ip_of.get(sid), client_of.get(sid), tuple(sorted(methods_of.get(sid, ()))))] += 1
    if silent:
        lines.append(f"\nSessions held open > {idle_seconds:g}s without trying a login or command "
                     f"({sum(silent.values())}):")
        for (ip, client, kinds), n in silent.most_common(top):
            lines.append(f"  {n:4d}  {(_printable(ip) if ip else '?'):16s} {_printable(client) if client else '-'}  "
                         f"{'/'.join(_printable(k) for k in kinds) or 'no auth attempt'}")
    return lines


def _download_line(d: dict) -> str:
    """One row of the download list. Stage-two fetches (URLs found by
    scanning a captured script) are tagged so they are not mistaken for
    something the attacker typed, and ELF samples show their architecture --
    the RISC-V ones are what this whole project is looking for."""
    tag = f"[stage {_printable(d['stage'])}] " if d.get("stage") else ""
    arch = ""
    if d.get("detected_machine"):
        flags = d.get("detected_flags")
        details = [f"{d['detected_bitness']}-bit" if d.get("detected_bitness") else None,
                   d.get("detected_endianness"),
                   # the decoded ABI when there is one; otherwise the raw word, unless it is zero
                   d.get("detected_abi") or (f"flags={flags:#x}" if isinstance(flags, int) and flags else None)]
        arch = "  " + _printable(" ".join([d["detected_machine"], *[str(x) for x in details if x]]))
    return (f"  {_printable(d.get('timestamp'))}  {_printable(d.get('outcome', '-')):8s}  "
            f"{tag}{_printable(d.get('url'))}{arch}")


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

    print(f"Window:       {_printable(report.first_seen or '-')}  to  {_printable(report.last_seen or '-')}")
    for line in _liveness_lines(all_events, stale_minutes=args.stale_minutes):
        print(line)
    print(f"Volume:       {len(report.sessions)} sessions")
    print(f"Unique IPs:   {len(report.unique_ips)}")
    print(f"Protocols:    {_printable(dict(protocols))}")
    print(f"Logins:       {report.login_success} succeeded / {total_logins} total ({pct:.1f}%)")
    print(f"Off-wordlist: {len(report.off_list_logins)} credential attempts")
    print(f"Downloads:    {len(report.downloads)} attempts, {successful_downloads} succeeded")
    print(f"Repeat IPs:   {len(report.repeat_visitor_ips)} logged in successfully more than once")

    print(f"\nTop {args.top} source IPs:")
    for ip in report.unique_ips[: args.top]:
        print(f"  {report.ip_session_counts[ip]:5d}  {_printable(ip)}")

    for line in _ssh_summary(events, top=args.top):
        print(line)

    patterns = _command_patterns(report)
    blank_count = patterns[()] + patterns[("",)]
    notable = [(p, c) for p, c in patterns.most_common() if p not in ((), ("",))]
    print(f"\nCommand patterns across successful logins ({blank_count} sent nothing -- harvester-style):")
    if notable:
        for pattern, count in notable[: args.top]:
            print(f"  {count:5d}  {_printable(pattern)}")
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
            print(f"  {len(logins):3d} logins  {_printable(ip):16s} usernames: "
                  f"{', '.join(_printable(u) for u in usernames)}")


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
