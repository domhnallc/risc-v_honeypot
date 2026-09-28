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

Rotated logs (events.jsonl.1, events.jsonl.2.gz, ...) next to the one you name
are read too, oldest first, so the report spans every day still on disk; pass
--no-rotated to look at the named file alone.

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
import gzip
import html
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_WORLD_OUTLINE_PATH = Path(__file__).parent / "geo" / "world_outline.json"

try:
    import maxminddb
except ImportError:
    maxminddb = None  # geolocation sections are skipped without it


# -- log loading -------------------------------------------------------

# logrotate (deploy/logrotate-riscv-honeypot.conf) renames events.jsonl to
# events.jsonl.1 at midnight UTC, then .2.gz, .3.gz ... as it ages. Reading only
# events.jsonl therefore shows just "today so far" -- a fresh rotation looks
# exactly like the honeypot having gone quiet -- so by default every numbered
# sibling is read too, oldest first.
_ROTATED_SUFFIX = re.compile(r"^\.(\d+)(\.gz)?$")

# Rotated files never change once written, but the live dashboard re-reads the
# log on every refresh: gunzipping and re-parsing a month of history every 15
# seconds would be wasteful. Keyed on (path, mtime, size), so a file that is
# replaced or grows is parsed again.
_ROTATED_CACHE: dict[tuple[str, int, int], list[dict[str, Any]]] = {}


def rotated_siblings(events_path: Path) -> list[Path]:
    """logrotate's numbered copies of `events_path`, oldest first (.10.gz before .2.gz before .1)."""
    found: list[tuple[int, Path]] = []
    for path in events_path.parent.glob(events_path.name + ".*"):
        match = _ROTATED_SUFFIX.match(path.name[len(events_path.name):])
        if match:
            found.append((int(match.group(1)), path))
    return [path for _, path in sorted(found, reverse=True)]


def _parse_file(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        opened = (gzip.open(path, "rt", encoding="utf-8") if path.suffix == ".gz"
                  else path.open(encoding="utf-8"))
        with opened as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"warning: {path}:{line_no}: skipping malformed JSON line", file=sys.stderr)
    except (OSError, EOFError) as exc:  # unreadable, or a gzip cut short by a full disk
        print(f"warning: {path}: {type(exc).__name__}: {exc}; keeping the {len(events)} events read before it",
              file=sys.stderr)
    return events


def _parse_rotated(path: Path) -> list[dict[str, Any]]:
    try:
        stat = path.stat()
    except OSError:
        return []
    key = (str(path), stat.st_mtime_ns, stat.st_size)
    if key not in _ROTATED_CACHE:
        for stale in [k for k in _ROTATED_CACHE if k[0] == key[0]]:
            del _ROTATED_CACHE[stale]
        _ROTATED_CACHE[key] = _parse_file(path)
    return _ROTATED_CACHE[key]


def _load_events(events_path: Path, include_rotated: bool = True) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    if include_rotated:
        for rotated in rotated_siblings(events_path):
            events.extend(_parse_rotated(rotated))
    if events_path.exists():
        events.extend(_parse_file(events_path))
    elif not events:
        print(f"warning: {events_path} does not exist, report will be empty", file=sys.stderr)
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


_HTTP_STATUS_RE = re.compile(r"^HTTP (\d{3})$")


def _failure_reason(error: str | None) -> str:
    """Collapse a fetch failure's raw `error` string into a short, stable bucket
    for grouping -- e.g. every "HTTP 404" together, regardless of which URL.
    Unlike honeypot/session/manager.py's _wget_error_text (which deliberately
    generalises what the *attacker* sees, to avoid leaking network detail back
    to them), this is for the operator's own dashboard, so the real reason is
    kept -- just bucketed so 50 timeouts don't become 50 separate rows.
    """
    error = error or "(unknown)"
    m = _HTTP_STATUS_RE.match(error)
    if m:
        return f"HTTP {m.group(1)}"
    if error.startswith("blocked non-public destination"):
        return "blocked: non-public destination (SSRF guard)"
    if error.startswith("protocol ") and "not permitted" in error:
        return "protocol not permitted (fetcher.allowed_protocols)"
    if "not yet implemented" in error:
        return "protocol not implemented (tftp/ftp)"
    if "exceeded max_file_size_bytes" in error:
        return "oversized transfer (max_file_size_bytes)"
    if "per-session download limit" in error:
        return "per-session download limit reached"
    if "timed out waiting for isolated fetcher" in error:
        return "isolated fetcher did not respond (queued mode)"
    return error[:80] + ("..." if len(error) > 80 else "")


# Related machines lumped into one family for the at-a-glance donut below -- e.g.
# EM_MIPS/EM_MIPS_RS3_LE (told apart only by endianness, i.e. MIPS vs. MIPSEL) are
# one slice here. The endianness/ABI/e_flags detail this collapses is not lost --
# it is still in every raw file.download event and in tools/status_check.py's
# per-download listing -- it is just not what a "which CPUs, roughly" chart needs.
_MACHINE_FAMILY = {
    "EM_RISCV": "RISC-V",
    "EM_ARM": "ARM",
    "EM_AARCH64": "AArch64",  # genuinely distinct from 32-bit ARM, not lumped in with it
    "EM_MIPS": "MIPS", "EM_MIPS_RS3_LE": "MIPS",
    "EM_X86_64": "x86-64",
    "EM_386": "x86",
    "EM_PPC": "PowerPC", "EM_PPC64": "PowerPC",
    "EM_SPARC": "SPARC", "EM_SPARC32PLUS": "SPARC", "EM_SPARCV9": "SPARC",
    "EM_SH": "SuperH",
    "EM_68K": "m68k",
}

# A non-ELF download (a captured script, a stray HTML/gzip/etc. page) isn't a CPU
# architecture at all -- it's a different dimension (file *type*, not machine
# identity) that this chart isn't about. Rather than compete for one of the 8
# identity slots (and risk colliding with a real architecture -- e.g. "script" is
# the single most common non-ELF capture, since every dropper run starts with one,
# so it routinely co-occurs with RISC-V/ARM/etc in the very same chart), every
# non-ELF label folds into this one neutral bucket, same treatment as "Other".
# The type distinction (script vs. unknown junk vs. gzip, ...) isn't lost -- it's
# still in every raw file.download event and status_check.py -- just not diagrammed
# here, per this chart's own "which CPUs are droppers serving" subtitle.
_NON_ELF_LABEL = "(non-ELF file)"

# Fixed *display* order: known families are legend-ordered/kept-when-capping in this
# order (RISC-V first, since a match there is the actual point of the project);
# anything unlisted (an EM_UNKNOWN(n) or otherwise unmapped machine) sorts
# alphabetically after these, still ahead of the final "Other" catch-all. This is
# NOT the color mapping -- see _slot_for_label below for why a fixed *position*
# in a list that shrinks/grows per render cannot double as a stable color key.
_FAMILY_ORDER = ["RISC-V", "ARM", "AArch64", "MIPS", "x86-64", "x86", "PowerPC", "SPARC", "SuperH", "m68k"]

# Fixed *color* slot per family, independent of which other families happen to be
# present in a given render. Assigning by position in the (per-render) rows list
# instead would mean ARM silently inherits RISC-V's blue on a day RISC-V had zero
# downloads -- exactly the "recolor on filter" anti-pattern, just triggered by the
# data changing day to day instead of a UI filter. Only 8 families get a
# guaranteed-unique slot (there are only 8 validated slots); anything else --
# an exotic/unmapped ELF machine this file doesn't have a family for yet -- gets a
# slot from its own label text (never Python's hash(): that is salted per-process
# and would repaint the chart on every single run) rather than sharing one of the
# 8 guaranteed slots. Collisions there are accepted as a rare edge case; the
# mainline one (architecture vs. non-ELF file type) is handled separately, above.
_FAMILY_SLOT = {name: f"s{i + 1}" for i, name in enumerate(
    ["RISC-V", "ARM", "AArch64", "MIPS", "x86-64", "x86", "PowerPC", "SPARC"])}


# The ARM sub-chart's possible labels are a small, fully enumerable, closed set
# (unlike CPU families, which are open-ended) -- so, unlike _FAMILY_SLOT, every
# possible value gets a guaranteed slot here, no hash fallback/collision risk at
# all. Disjoint from every CPU-family label's own text, so sharing one
# _slot_for_label with the main donut below is safe (no cross-dict overlap).
_ARM_EABI_ORDER = ["EABI5", "EABI4", "EABI3", "EABI2", "EABI1", "EABI0", "pre-EABI", "unknown"]
_ARM_EABI_SLOT = {name: f"s{i + 1}" for i, name in enumerate(_ARM_EABI_ORDER)}


def _slot_for_label(label: str) -> str:
    if label in ("Other", _NON_ELF_LABEL):
        return "other"
    if label in _FAMILY_SLOT:
        return _FAMILY_SLOT[label]
    if label in _ARM_EABI_SLOT:
        return _ARM_EABI_SLOT[label]
    return f"s{sum(ord(c) for c in label) % 8 + 1}"


_MAX_DONUT_SLICES = 6  # a donut reads at a glance only up to ~6 segments (dataviz skill)

_ARM_EABI_RE = re.compile(r"^(EABI\d+|pre-EABI)\b")


def _arch_family(ev: dict[str, Any]) -> str:
    """The lumped family label for one successful download's detected type."""
    if ev.get("detected_type") != "elf":
        return _NON_ELF_LABEL
    machine = ev.get("detected_machine") or ""
    return _MACHINE_FAMILY.get(machine, machine or "(unknown machine)")


def _arm_eabi_bucket(ev: dict[str, Any]) -> str:
    """Which EABI version an ARM download's decoded ABI names, or 'unknown' when
    e_flags wasn't decodable (see honeypot/fetcher/elf.py's ARM decoding)."""
    abi = ev.get("detected_abi")
    if not abi:
        return "unknown"
    m = _ARM_EABI_RE.match(abi)
    return m.group(1) if m else "unknown"


def _lump_and_cap(counts: "Counter[str]", order: list[str],
                  max_slices: int = _MAX_DONUT_SLICES) -> list[tuple[str, int]]:
    """counts (label -> n) into at most `max_slices` (label, n) pairs, most of
    `order` first (so slot/color assignment is stable across re-renders even as
    counts shift), unlisted labels next alphabetically, and -- only once there
    are more than `max_slices` distinct labels -- the smallest tail folded into
    a trailing ("Other", n). The labels kept are always the biggest, so nothing
    that matters gets folded away to make room for something smaller.
    """
    if not counts:
        return []
    ordered = [l for l in order if l in counts] + sorted(l for l in counts if l not in order)
    if len(ordered) <= max_slices:
        return [(l, counts[l]) for l in ordered]
    kept = set(sorted(ordered, key=lambda l: -counts[l])[: max_slices - 1])
    rows = [(l, counts[l]) for l in ordered if l in kept]
    rows.append(("Other", sum(n for l, n in counts.items() if l not in kept)))
    return rows


def _architecture_donut(downloads: list[dict[str, Any]]) -> "_DonutData | None":
    """Successful downloads grouped into the lumped families above, for the main
    "which CPUs are droppers actually serving" donut -- the RISC-V capture side
    of this project cares about this more than any other single view. A family
    that has any arch_mismatch judgement at all (only ever RISC-V, per
    honeypot/fetcher/elf.py's arch_matches_persona -- it judges nothing else) gets
    its match/mismatch counts annotated, since that is the one architecture this
    honeypot's own persona can actually be compared against."""
    counts: Counter[str] = Counter()
    match: dict[str, int] = {}
    mismatch: dict[str, int] = {}
    for ev in downloads:
        if ev.get("outcome") != "success":
            continue
        family = _arch_family(ev)
        counts[family] += 1
        if ev.get("arch_mismatch") is False:
            match[family] = match.get(family, 0) + 1
        elif ev.get("arch_mismatch") is True:
            mismatch[family] = mismatch.get(family, 0) + 1
    rows = _lump_and_cap(counts, _FAMILY_ORDER)
    if not rows:
        return None
    return _DonutData(rows, {l: (match.get(l, 0), mismatch.get(l, 0)) for l, _ in rows})


def _arm_version_donut(downloads: list[dict[str, Any]]) -> "_DonutData | None":
    """ARM successful downloads only, broken down by EABI version -- e_flags does
    NOT carry the ARM CPU architecture level (v5/v6/v7 lives in a section
    honeypot/fetcher/elf.py deliberately never walks), so this is EABI version and
    float ABI, the finest-grained split the detector can actually make."""
    counts: Counter[str] = Counter(
        _arm_eabi_bucket(ev) for ev in downloads
        if ev.get("outcome") == "success" and _arch_family(ev) == "ARM"
    )
    rows = _lump_and_cap(counts, _ARM_EABI_ORDER)
    return _DonutData(rows, {}) if rows else None


def _failure_breakdown(downloads: list[dict[str, Any]]) -> list[list[str]]:
    """One row per failure-reason bucket, most common first."""
    groups: dict[str, dict[str, int]] = {}
    for ev in downloads:
        if ev.get("outcome") != "failed":
            continue
        reason = _failure_reason(ev.get("error"))
        g = groups.setdefault(reason, {"count": 0, "stage2": 0})
        g["count"] += 1
        if ev.get("stage"):
            g["stage2"] += 1
    return [
        [_esc(reason), str(g["count"]), str(g["stage2"]) if g["stage2"] else "-"]
        for reason, g in sorted(groups.items(), key=lambda kv: -kv[1]["count"])
    ]


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "<p class='empty'>No data yet.</p>"
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


@dataclass
class _DonutData:
    # [(label, count), ...] -- already lumped/capped/ordered by _lump_and_cap.
    rows: list[tuple[str, int]]
    # label -> (match_count, mismatch_count), for the one family (if any) this
    # honeypot's persona architecture can actually be judged against. Empty dict
    # when nothing in this donut carries that judgement (e.g. the ARM chart).
    persona: dict[str, tuple[int, int]]


# Categorical slots (validated: node scripts/validate_palette.js against both
# #ffffff/light and #171d2b/dark, this file's own --panel colors -- see
# dataviz skill references/palette.md). Slot assignment is _slot_for_label above,
# not render position. Applied as a CSS class rather than an inline
# `stroke="var(...)"` presentation attribute -- same reason the existing
# world-map dots above use `class="ip-dot"` rather than an inline color: var()
# resolution inside an SVG presentation *attribute* (as opposed to an actual
# style/stylesheet property) is not reliably specified, so every themed color
# in this file goes through a class and a real CSS rule.
_DONUT_GAP_PX = 2  # the mark spec's "2px surface gap" between adjacent segments


def _donut_svg(data: "_DonutData", center_label: str, chart_id: str) -> str:
    """An SVG ring chart + an always-visible text legend (label, count, percent) --
    the legend carries the exact numbers so nothing here is hover-only (a native
    <title> per arc still gives a hover tooltip, same convention as the world map's
    <circle> dots above). A part-to-whole donut is deliberately capped at <=6
    segments by _lump_and_cap before it ever reaches here (a donut only reads "at a
    glance"; past that a table is the honest form -- see status_check.py for one).
    """
    rows = data.rows
    total = sum(n for _, n in rows)
    if not rows or total == 0:
        return "<p class='empty'>No data yet.</p>"

    size, stroke = 148, 26
    r = (size - stroke) / 2
    cx = cy = size / 2
    circumference = 2 * math.pi * r
    cumulative = 0.0
    arcs, legend = [], []
    for label, count in rows:
        frac = count / total
        seg_len = frac * circumference
        dash = max(seg_len - _DONUT_GAP_PX, 0) if len(rows) > 1 else seg_len
        slot_class = _slot_for_label(label)
        arcs.append(
            f"<circle class='donut-arc {slot_class}' cx='{cx}' cy='{cy}' r='{r:.2f}' "
            f"stroke-width='{stroke}' stroke-linecap='butt' "
            f"stroke-dasharray='{dash:.2f} {circumference - dash:.2f}' "
            f"stroke-dashoffset='{-cumulative:.2f}'>"
            f"<title>{_esc(label)}: {count} ({frac * 100:.0f}%)</title></circle>"
        )
        cumulative += seg_len

        note = ""
        m, mm = data.persona.get(label, (0, 0))
        if m or mm:
            parts = []
            if m:
                parts.append(f"<span class='donut-match'>&check; {m} match</span>")
            if mm:
                parts.append(f"<span class='donut-mismatch'>&ne; {mm} mismatch</span>")
            note = f"<span class='donut-legend-note'>{' '.join(parts)}</span>"
        legend.append(
            "<div class='donut-legend-row'>"
            f"<span class='swatch {slot_class}'></span>"
            f"<span class='donut-legend-label'>{_esc(label)}</span>"
            f"<span class='donut-legend-count'>{count} &middot; {frac * 100:.0f}%</span>"
            f"{note}</div>"
        )

    svg = (
        f"<svg viewBox='0 0 {size} {size}' width='{size}' height='{size}' role='img' "
        f"aria-label='{_esc(center_label)}: {total} total'>"
        f"<g transform='rotate(-90 {cx} {cy})'>{''.join(arcs)}</g>"
        f"<text x='{cx}' y='{cy - 3}' text-anchor='middle' class='donut-total'>{total}</text>"
        f"<text x='{cx}' y='{cy + 15}' text-anchor='middle' class='donut-total-label'>"
        f"{_esc(center_label)}</text></svg>"
    )
    return f"<div class='donut' id='{chart_id}'>{svg}<div class='donut-legend'>{''.join(legend)}</div></div>"


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
  /* Categorical series (dark step): validated against this file's own dark
     --panel #171d2b with the dataviz skill's validator -- worst adjacent CVD
     Delta E 8.4 (>=8 target), worst normal-vision Delta E 19.3 (>=15 floor),
     all 8 >= 3:1 contrast. Order is fixed and never re-cycled -- see
     _FAMILY_SLOT in this file for why RISC-V is always slot 1. */
  --series-1: #3987e5; --series-2: #d95926; --series-3: #199e70; --series-4: #c98500;
  --series-5: #d55181; --series-6: #008300; --series-7: #9085e9; --series-8: #e66767;
}
@media (prefers-color-scheme: light) {
  :root { --bg: #f4f6fb; --panel: #ffffff; --border: #dde3ee; --text: #16202e;
          --muted: #5b6779; --accent: #1266c9; --dot: #d1364a;
          /* Light step: validated against #ffffff -- worst adjacent CVD Delta E 9.1,
             worst normal-vision Delta E 19.6. Three slots (3/5/... aqua/magenta family)
             sit below 3:1 on this light surface by design; every use here pairs the
             color with visible text (legend label + count), never color alone. */
          --series-1: #2a78d6; --series-2: #eb6834; --series-3: #1baf7a; --series-4: #eda100;
          --series-5: #e87ba4; --series-6: #008300; --series-7: #4a3aa7; --series-8: #e34948; }
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
.donut { display: flex; flex-wrap: wrap; align-items: center; gap: 18px 24px; }
.donut svg { flex: none; }
.donut-arc { fill: none; }
.donut-arc.s1, .swatch.s1 { --slot: var(--series-1); }
.donut-arc.s2, .swatch.s2 { --slot: var(--series-2); }
.donut-arc.s3, .swatch.s3 { --slot: var(--series-3); }
.donut-arc.s4, .swatch.s4 { --slot: var(--series-4); }
.donut-arc.s5, .swatch.s5 { --slot: var(--series-5); }
.donut-arc.s6, .swatch.s6 { --slot: var(--series-6); }
.donut-arc.s7, .swatch.s7 { --slot: var(--series-7); }
.donut-arc.s8, .swatch.s8 { --slot: var(--series-8); }
.donut-arc.other, .swatch.other { --slot: var(--muted); }
.donut-arc { stroke: var(--slot); }
.donut-total { font-size: 26px; font-weight: 700; fill: var(--text); }
.donut-total-label { font-size: 10px; fill: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.donut-legend { display: flex; flex-direction: column; gap: 7px; flex: 1 1 200px; min-width: 200px; }
.donut-legend-row { display: flex; align-items: center; gap: 8px; font-size: 0.85em; flex-wrap: wrap; }
.swatch { width: 11px; height: 11px; min-width: 11px; border-radius: 3px; background: var(--slot); }
.donut-legend-label { flex: 1; }
.donut-legend-count { color: var(--muted); font-variant-numeric: tabular-nums; }
.donut-legend-note { flex-basis: 100%; padding-left: 19px; font-size: 0.9em; }
.donut-match { color: #0ca30c; font-weight: 600; }
.donut-mismatch { color: #d03b3b; font-weight: 600; }
"""


def render_html(report: Report, geo: GeoLookup) -> str:
    total_sessions = len(report.sessions)
    total_logins = report.login_success + report.login_failed

    stats = [
        (str(total_sessions), "Sessions"),
        (str(len(report.unique_ips)), "Unique source IPs"),
        (str(len(report.commands)), "Commands captured"),
        (str(len(report.downloads)), "Download attempts"),
        (str(sum(1 for d in report.downloads if d.get("stage"))), "Stage-2 downloads"),
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
            abi = f", {ev['detected_abi']}" if ev.get("detected_abi") else ""
            detected = f"{detected} / {ev.get('detected_machine')} ({ev.get('detected_bitness')}-bit{endian}{abi})"
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

    architecture_donut_data = _architecture_donut(report.downloads)
    architecture_donut = (
        _donut_svg(architecture_donut_data, "downloads", "donut-architecture")
        if architecture_donut_data else "<p class='empty'>No successful downloads yet.</p>"
    )
    arm_donut_data = _arm_version_donut(report.downloads)
    arm_section = ""
    if arm_donut_data:
        arm_section = f"""
    <div class="panel">
      <h2>ARM builds by EABI version</h2>
      <p class="subtitle" style="margin:-4px 0 10px">e_flags does not carry the ARM CPU
      architecture level (v5/v6/v7 lives in a section honeypot/fetcher/elf.py deliberately
      never walks) -- EABI version and float ABI is the finest split the detector can make.</p>
      {_donut_svg(arm_donut_data, "ARM downloads", "donut-arm")}
    </div>"""

    failure_table = _table(
        ["Reason", "Count", "Stage-2"],
        _failure_breakdown(report.downloads),
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
  <div class="grid-2">
    <div class="panel"{'' if arm_section else " style='grid-column:1/-1'"}>
      <h2>Downloads by architecture</h2>
      <p class="subtitle" style="margin:-4px 0 10px">Successful downloads, grouped into CPU families
      (related machines lumped together, e.g. MIPS/MIPSEL) -- a &check; next to RISC-V is this honeypot's
      own persona architecture actually being matched, the whole point of the project.</p>
      {architecture_donut}
    </div>{arm_section}
  </div>
  <div class="panel"><h2>Failed downloads by reason</h2>{failure_table}</div>
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
    parser.add_argument("--no-rotated", action="store_true",
                         help="read only the named log, not its rotated events.jsonl.N[.gz] siblings")
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

    events = _load_events(events_path, include_rotated=not args.no_rotated)
    report = Report(events)
    geo = GeoLookup(Path(args.geoip) if args.geoip else None)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(report, geo), encoding="utf-8")
    print(f"wrote {out_path} ({len(report.sessions)} sessions, {len(report.commands)} commands, "
          f"{len(report.downloads)} downloads)", file=sys.stderr)


if __name__ == "__main__":
    main()
