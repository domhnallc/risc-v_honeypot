#!/usr/bin/env python3
"""Standalone reporting tool: renders one self-contained HTML dashboard from
the honeypot's own JSONL event logs.

Deliberately NOT part of the `honeypot` package. CLAUDE.md / the build spec
(sec 7) mark a web dashboard and GeoIP enrichment beyond a pluggable stub as
explicitly out of scope for the honeypot itself -- this keeps that scope
intact by living entirely outside `honeypot/` as a separate, read-only
consumer of `var/logs/events.jsonl`. It never touches attacker sessions,
never imports or runs alongside the listeners, and only ever reads files
that already exist on disk. Run it whenever you want a fresh snapshot;
there's no server to keep running.

Usage:
    python3 tools/dashboard.py configs/riscv64.yaml
    python3 tools/dashboard.py configs/riscv64.yaml --geoip var/GeoLite2-City.mmdb
    python3 tools/dashboard.py --events var/logs/events.jsonl --out var/dashboard.html

GeoLite2-City.mmdb is NOT bundled -- MaxMind's license requires a free
signup before you can download it yourself:
    https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
Without --geoip (or without `pip install maxminddb`), the country/map
sections are simply omitted; everything else still renders normally.

Every attacker-supplied field (commands, usernames, passwords, URLs,
filenames) is HTML-escaped before being written into the report -- this
data is 100% attacker-controlled, and the whole point of the tool is that
you're going to load it in a real browser.
"""
from __future__ import annotations

import argparse
import html
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

_WORLD_OUTLINE_PATH = Path(__file__).parent / "geo" / "world_outline.json"

try:
    import maxminddb
except ImportError:
    maxminddb = None  # geolocation sections are skipped without it


# -- log loading -------------------------------------------------------

def _load_events(events_path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if not events_path.exists():
        print(f"warning: {events_path} does not exist, report will be empty", file=sys.stderr)
        return events
    with events_path.open(encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"warning: {events_path}:{line_no}: skipping malformed JSON line", file=sys.stderr)
    return events


# -- aggregation ---------------------------------------------------------

class Report:
    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events
        self.sessions: dict[str, dict[str, Any]] = {}
        self.ip_session_counts: Counter[str] = Counter()
        self.commands: list[dict[str, Any]] = []
        self.downloads: list[dict[str, Any]] = []
        self.username_counts: Counter[str] = Counter()
        self.password_counts: Counter[str] = Counter()
        self.login_success = 0
        self.login_failed = 0
        self.off_list_logins: list[dict[str, Any]] = []
        self.successful_logins_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.timestamps: list[str] = []
        self._aggregate()

    def _aggregate(self) -> None:
        for ev in self.events:
            ts = ev.get("timestamp")
            if ts:
                self.timestamps.append(ts)
            etype = ev.get("event")

            if etype == "session.connect":
                sid = ev.get("session_id", "")
                ip = ev.get("src_ip", "unknown")
                self.sessions[sid] = {"ip": ip, "protocol": ev.get("protocol", "")}
                self.ip_session_counts[ip] += 1

            elif etype == "command.input":
                self.commands.append(ev)

            elif etype == "file.download" and ev.get("outcome") != "requested":
                self.downloads.append(ev)

            elif etype in ("login.success", "login.failed"):
                self.username_counts[ev.get("username", "")] += 1
                self.password_counts[ev.get("password", "")] += 1
                if etype == "login.success":
                    self.login_success += 1
                    self.successful_logins_by_ip[ev.get("src_ip", "")].append(ev)
                else:
                    self.login_failed += 1
                # False (not None/missing) means a wordlist *was*
                # configured and this side wasn't found in it -- a
                # credential a scanner tried that isn't part of any known
                # common-username/password list, worth a human look
                # regardless of whether the login was accepted (e.g. via
                # the allow_list fast path, or under accept_any).
                if ev.get("username_known") is False or ev.get("password_known") is False:
                    self.off_list_logins.append(ev)

        self.commands.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        self.downloads.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        self.off_list_logins.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    @property
    def unique_ips(self) -> list[str]:
        return sorted(self.ip_session_counts, key=self.ip_session_counts.get, reverse=True)

    @property
    def repeat_visitor_ips(self) -> list[tuple[str, list[dict[str, Any]]]]:
        """Source IPs with more than one *successful* login -- the pattern
        worth watching for a Mirai-style two-stage campaign, where a
        harvester bot verifies credentials work now and a separate loader
        bot returns later to actually drop a payload using them. Sorted
        by most logins first."""
        repeats = [(ip, evs) for ip, evs in self.successful_logins_by_ip.items() if len(evs) > 1]
        return sorted(repeats, key=lambda kv: len(kv[1]), reverse=True)

    @property
    def first_seen(self) -> str | None:
        return min(self.timestamps) if self.timestamps else None

    @property
    def last_seen(self) -> str | None:
        return max(self.timestamps) if self.timestamps else None


class GeoLookup:
    """Thin, failure-tolerant wrapper over a GeoLite2-City .mmdb reader.

    Every lookup is independently try/excepted -- a private/reserved IP, a
    corrupt DB, or a missing dependency should degrade the report (skip that
    IP's geolocation), never crash the whole run.
    """

    def __init__(self, mmdb_path: Path | None) -> None:
        self._reader = None
        if mmdb_path is None:
            return
        if maxminddb is None:
            print("warning: --geoip was given but the 'maxminddb' package isn't installed "
                  "(pip install -e '.[dashboard]') -- country/map sections will be omitted",
                  file=sys.stderr)
            return
        try:
            self._reader = maxminddb.open_database(str(mmdb_path))
        except (FileNotFoundError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            print(f"warning: could not open GeoIP database {mmdb_path}: {exc}", file=sys.stderr)

    @property
    def available(self) -> bool:
        return self._reader is not None

    def lookup(self, ip: str) -> dict[str, Any] | None:
        if self._reader is None:
            return None
        try:
            result = self._reader.get(ip)
        except Exception:
            return None
        if not result:
            return None
        country = (result.get("country") or {}).get("names", {}).get("en")
        location = result.get("location") or {}
        lat, lon = location.get("latitude"), location.get("longitude")
        if lat is None or lon is None:
            return None
        return {"country": country or "Unknown", "lat": lat, "lon": lon}


# -- rendering -------------------------------------------------------------

def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "<p class='empty'>No data yet.</p>"
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _word_cloud(counts: Counter[str], empty_label: str) -> str:
    items = [(w, c) for w, c in counts.most_common(60) if w]
    if not items:
        return f"<p class='empty'>{_esc(empty_label)}</p>"
    max_count = max(c for _, c in items)
    spans = []
    for word, count in items:
        # sqrt scaling: a handful of very common credentials shouldn't
        # visually drown out everything else in a linear scale.
        size = 0.85 + 1.9 * math.sqrt(count / max_count)
        spans.append(
            f"<span class='cloud-word' style='font-size:{size:.2f}em' "
            f"title='{count}x'>{_esc(word)}</span>"
        )
    return f"<div class='cloud'>{''.join(spans)}</div>"


def _project(lon: float, lat: float, width: int, height: int) -> tuple[float, float]:
    x = (lon + 180.0) / 360.0 * width
    y = (90.0 - lat) / 180.0 * height
    return x, y


def _render_map(points: list[tuple[float, float, str, int]]) -> str:
    """points: list of (lon, lat, label, count). Renders a self-contained
    inline SVG: a pre-simplified world outline (tools/geo/world_outline.json,
    bundled at build time -- no runtime network fetch) plus one dot per
    geolocated IP, sized by how many sessions came from it."""
    width, height = 720, 360
    try:
        countries = json.loads(_WORLD_OUTLINE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        countries = []

    paths = []
    for country in countries:
        d_parts = []
        for poly in country.get("polys", []):
            for ring in poly:
                if len(ring) < 2:
                    continue
                coords = [_project(lon, lat, width, height) for lon, lat in ring]
                d_parts.append("M" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords) + "Z")
        if d_parts:
            paths.append(f"<path class='land' d='{' '.join(d_parts)}'/>")

    max_count = max((c for *_r, c in points), default=1)
    dots = []
    for lon, lat, label, count in points:
        x, y = _project(lon, lat, width, height)
        r = 2.5 + 4.5 * math.sqrt(count / max_count)
        dots.append(
            f"<circle class='ip-dot' cx='{x:.1f}' cy='{y:.1f}' r='{r:.1f}'>"
            f"<title>{_esc(label)} ({count}x)</title></circle>"
        )

    return (
        f"<svg viewBox='0 0 {width} {height}' class='world-map' role='img' "
        f"aria-label='Attacker source locations'>"
        f"{''.join(paths)}{''.join(dots)}</svg>"
    )


_CSS = """
:root {
  color-scheme: light dark;
  --bg: #0f1420; --panel: #171d2b; --border: #2a3348; --text: #e8ecf4;
  --muted: #8b96ad; --accent: #5fb0ff; --dot: #ff6b6b;
}
@media (prefers-color-scheme: light) {
  :root { --bg: #f4f6fb; --panel: #ffffff; --border: #dde3ee; --text: #16202e;
          --muted: #5b6779; --accent: #1266c9; --dot: #d1364a; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px 16px; background: var(--bg); color: var(--text);
       font: 14px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; }
.wrap { max-width: 1100px; margin: 0 auto; display: flex; flex-direction: column; gap: 20px; }
h1 { font-size: 1.4em; margin: 0 0 4px; }
.subtitle { color: var(--muted); margin: 0 0 8px; font-size: 0.9em; }
.stats { display: flex; flex-wrap: wrap; gap: 12px; }
.stat { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
        padding: 12px 16px; min-width: 130px; flex: 1; }
.stat .n { font-size: 1.6em; font-weight: 600; }
.stat .l { color: var(--muted); font-size: 0.8em; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
         padding: 16px; overflow-x: auto; }
.panel h2 { margin: 0 0 12px; font-size: 1.05em; }
.grid-2 { display: grid; grid-template-columns: 1fr; gap: 20px; }
@media (min-width: 800px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
table { border-collapse: collapse; width: 100%; font-size: 0.85em; white-space: nowrap; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 600; }
td.wrap-cell { white-space: normal; word-break: break-all; }
.empty { color: var(--muted); }
.world-map { width: 100%; height: auto; background: transparent; }
.world-map .land { fill: var(--border); stroke: var(--muted); stroke-width: 0.3; }
.world-map .ip-dot { fill: var(--dot); fill-opacity: 0.75; stroke: var(--dot); stroke-width: 0.5; }
.cloud { display: flex; flex-wrap: wrap; gap: 10px 14px; align-items: baseline; }
.cloud-word { color: var(--accent); font-weight: 600; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 0.8em; }
.pill.ok { background: #1c8a4a33; color: #1c8a4a; }
.pill.bad { background: #c4384033; color: #c43840; }
"""


def render_html(report: Report, geo: GeoLookup) -> str:
    total_sessions = len(report.sessions)
    total_logins = report.login_success + report.login_failed

    stats = [
        (str(total_sessions), "Sessions"),
        (str(len(report.unique_ips)), "Unique source IPs"),
        (str(len(report.commands)), "Commands captured"),
        (str(len(report.downloads)), "Download attempts"),
        (f"{report.login_success} / {total_logins}", "Accepted / total logins"),
        (str(len(report.off_list_logins)), "Off-wordlist credentials"),
        (str(len(report.repeat_visitor_ips)), "Repeat visitor IPs"),
    ]
    stats_html = "".join(
        f"<div class='stat'><div class='n'>{_esc(n)}</div><div class='l'>{_esc(l)}</div></div>"
        for n, l in stats
    )

    ip_rows = []
    country_counts: Counter[str] = Counter()
    map_points: list[tuple[float, float, str, int]] = []
    for ip in report.unique_ips[:25]:
        count = report.ip_session_counts[ip]
        geo_info = geo.lookup(ip)
        country = geo_info["country"] if geo_info else "-"
        if geo_info:
            country_counts[geo_info["country"]] += count
            map_points.append((geo_info["lon"], geo_info["lat"], f"{ip} ({country})", count))
        ip_rows.append([_esc(ip), str(count), _esc(country)])
    ip_table = _table(["Source IP", "Sessions", "Country"], ip_rows)

    repeat_rows = []
    for ip, logins in report.repeat_visitor_ips:
        timestamps = sorted(ev.get("timestamp", "") for ev in logins)
        usernames = sorted({ev.get("username", "") for ev in logins})
        geo_info = geo.lookup(ip)
        country = geo_info["country"] if geo_info else "-"
        repeat_rows.append([
            _esc(ip), str(len(logins)), _esc(timestamps[0]), _esc(timestamps[-1]),
            _esc(", ".join(usernames)), _esc(country),
        ])
    repeat_table = _table(
        ["Source IP", "Successful logins", "First seen", "Last seen", "Usernames used", "Country"],
        repeat_rows,
    )

    country_rows = [[_esc(c), str(n)] for c, n in country_counts.most_common(15)]
    country_table = _table(["Country", "Sessions"], country_rows)

    command_rows = [
        [_esc(ev.get("timestamp", "")), _esc(ev.get("session_id", "")[:8]),
         f"<span class='wrap-cell'>{_esc(ev.get('raw', ''))}</span>"]
        for ev in report.commands[:10]
    ]
    command_table = _table(["Timestamp", "Session", "Command"], command_rows)

    download_rows = []
    for ev in report.downloads[:10]:
        outcome = ev.get("outcome", "")
        pill = f"<span class='pill {'ok' if outcome == 'success' else 'bad'}'>{_esc(outcome)}</span>"
        detected = ev.get("detected_type") or "-"
        if ev.get("detected_machine"):
            endian = f", {ev['detected_endianness']}-endian" if ev.get("detected_endianness") else ""
            detected = f"{detected} / {ev.get('detected_machine')} ({ev.get('detected_bitness')}-bit{endian})"
        arch = ev.get("arch_mismatch")
        arch_label = "-" if arch is None else ("MISMATCH" if arch else "match")
        download_rows.append([
            _esc(ev.get("timestamp", "")),
            pill,
            f"<span class='wrap-cell'>{_esc(ev.get('url', ''))}</span>",
            _esc(ev.get("requested_filename", "")),
            _esc(ev.get("size_bytes", "-")),
            f"<span class='wrap-cell'>{_esc((ev.get('sha256') or '-')[:16])}</span>",
            _esc(detected),
            _esc(arch_label),
        ])
    download_table = _table(
        ["Timestamp", "Outcome", "URL", "Filename", "Bytes", "SHA256", "Detected type", "Arch vs. persona"],
        download_rows,
    )

    off_list_rows = []
    for ev in report.off_list_logins[:20]:
        outcome = "success" if ev.get("event") == "login.success" else "failed"
        pill = f"<span class='pill {'ok' if outcome == 'success' else 'bad'}'>{_esc(outcome)}</span>"
        which = ", ".join(
            label for label, known in (("username", ev.get("username_known")), ("password", ev.get("password_known")))
            if known is False
        ) or "-"
        off_list_rows.append([
            _esc(ev.get("timestamp", "")),
            _esc(ev.get("src_ip", "")),
            _esc(ev.get("username", "")),
            _esc(ev.get("password", "")),
            pill,
            _esc(which),
        ])
    off_list_table = _table(
        ["Timestamp", "Source IP", "Username", "Password", "Outcome", "Not on wordlist"],
        off_list_rows,
    )
    wordlists_configured = any(
        ev.get("username_known") is not None or ev.get("password_known") is not None
        for ev in report.events if ev.get("event") in ("login.success", "login.failed")
    )
    if wordlists_configured:
        off_list_body = off_list_table
    else:
        off_list_body = (
            "<p class='empty'>No username/password wordlist configured on the honeypot "
            "(credentials.username_wordlist_path / password_wordlist_path) -- nothing to compare against.</p>"
        )
    off_list_section = f"""
    <div class="panel">
      <h2>Credential attempts not on the known wordlist ({len(report.off_list_logins)})</h2>
      {off_list_body}
    </div>"""

    map_section = ""
    if geo.available:
        map_section = f"""
        <div class="panel">
          <h2>Source locations</h2>
          {_render_map(map_points)}
        </div>"""
    else:
        map_section = """
        <div class="panel">
          <h2>Source locations</h2>
          <p class="empty">No GeoIP database configured -- pass --geoip path/to/GeoLite2-City.mmdb
          to enable the map and country breakdown.</p>
        </div>"""

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Honeypot Dashboard</title><style>{_CSS}</style></head>
<body><div class="wrap">
  <div>
    <h1>RISC-V Honeypot Dashboard</h1>
    <p class="subtitle">Data from {_esc(report.first_seen or '-')} to {_esc(report.last_seen or '-')}
    &middot; generated by tools/dashboard.py, a standalone read-only report -- not part of the honeypot itself.</p>
  </div>
  <div class="stats">{stats_html}</div>
  {map_section}
  <div class="grid-2">
    <div class="panel"><h2>Top source IPs</h2>{ip_table}</div>
    <div class="panel"><h2>Top countries</h2>{country_table}</div>
  </div>
  <div class="panel">
    <h2>Repeat successful logins ({len(report.repeat_visitor_ips)})</h2>
    {repeat_table if report.repeat_visitor_ips else
      "<p class='empty'>None yet -- worth watching for: a Mirai-style campaign often splits "
      "into a harvester bot that just verifies credentials work, and a separate loader bot "
      "that returns later (sometimes hours/days) to actually drop a payload using them. "
      "An IP showing up here is your signal to watch it for a download attempt.</p>"}
  </div>
  <div class="panel"><h2>Last 10 commands</h2>{command_table}</div>
  <div class="panel"><h2>Last 10 file downloads</h2>{download_table}</div>
  {off_list_section}
  <div class="grid-2">
    <div class="panel"><h2>Attempted usernames</h2>{_word_cloud(report.username_counts, "No login attempts yet.")}</div>
    <div class="panel"><h2>Attempted passwords</h2>{_word_cloud(report.password_counts, "No login attempts yet.")}</div>
  </div>
</div></body></html>
"""


# -- CLI -------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("config", nargs="?", help="honeypot config YAML, used to find the events log by default")
    parser.add_argument("--events", help="explicit path to events.jsonl (overrides --config-derived path)")
    parser.add_argument("--geoip", help="path to a GeoLite2-City.mmdb file (optional)")
    parser.add_argument("--out", default="var/dashboard.html", help="output HTML path (default: var/dashboard.html)")
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

    events = _load_events(events_path)
    report = Report(events)
    geo = GeoLookup(Path(args.geoip) if args.geoip else None)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(report, geo), encoding="utf-8")
    print(f"wrote {out_path} ({len(report.sessions)} sessions, {len(report.commands)} commands, "
          f"{len(report.downloads)} downloads)", file=sys.stderr)


if __name__ == "__main__":
    main()
