"""Tests for tools/dashboard.py -- the standalone, read-only HTML report
generator built from the honeypot's own JSONL event logs.

Deliberately kept in tests/ even though the tool itself lives outside
honeypot/ (see that file's module docstring for why): every field this
report renders is 100% attacker-controlled, so escaping it correctly is a
real safety property worth a regression test, not just a nice-to-have.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from dashboard import GeoLookup, Report, _render_map, _word_cloud, render_html  # noqa: E402


def _events(*rows):
    return list(rows)


def test_empty_log_renders_without_crashing():
    report = Report([])
    out = render_html(report, GeoLookup(None))
    assert out.startswith("<!doctype html>")
    assert "No data yet." in out or "No login attempts" in out


def test_attacker_controlled_fields_are_escaped():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "session.connect",
         "session_id": "abc123", "src_ip": "1.2.3.4", "protocol": "ssh"},
        {"timestamp": "2026-01-01T00:00:01Z", "event": "command.input",
         "session_id": "abc123", "raw": "<script>alert(1)</script>"},
        {"timestamp": "2026-01-01T00:00:02Z", "event": "login.failed",
         "username": "<img src=x onerror=alert(1)>", "password": 'p"onmouseover=alert(1)'},
        {"timestamp": "2026-01-01T00:00:03Z", "event": "file.download", "outcome": "success",
         "url": "http://evil/<script>pwn()</script>", "requested_filename": "f.bin",
         "size_bytes": 10, "sha256": "a" * 64, "detected_type": "elf"},
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "<script>" not in out
    assert "<img src=x" not in out
    # the raw text is expected to still appear (that's the point of the
    # report), but only ever as an escaped, inert entity -- never as a
    # live tag the browser would parse and execute.
    assert "&lt;img src=x onerror=alert(1)&gt;" in out
    assert "&lt;script&gt;pwn()&lt;/script&gt;" in out


def test_last_ten_commands_ordered_most_recent_first():
    events = [
        {"timestamp": f"2026-01-01T00:00:{i:02d}Z", "event": "command.input",
         "session_id": "s", "raw": f"cmd{i}"}
        for i in range(15)
    ]
    report = Report(events)
    assert [ev["raw"] for ev in report.commands[:3]] == ["cmd14", "cmd13", "cmd12"]
    assert len(report.commands) == 15  # trimming to 10 happens at render time


def test_download_requested_events_are_excluded():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "file.download", "outcome": "requested"},
        {"timestamp": "2026-01-01T00:00:01Z", "event": "file.download", "outcome": "success"},
    )
    report = Report(events)
    assert len(report.downloads) == 1
    assert report.downloads[0]["outcome"] == "success"


def test_geo_unavailable_shows_fallback_and_no_map():
    geo = GeoLookup(None)
    assert not geo.available
    assert geo.lookup("8.8.8.8") is None
    out = render_html(Report([]), geo)
    assert "No GeoIP database configured" in out


def test_word_cloud_empty_and_scaled():
    from collections import Counter
    assert "No entries" in _word_cloud(Counter(), "No entries")
    out = _word_cloud(Counter({"root": 50, "admin": 1}), "empty")
    assert "root" in out and "admin" in out


def test_render_map_produces_valid_svg_with_points():
    svg = _render_map([(-0.1, 51.5, "London", 5), (139.7, 35.7, "Tokyo", 2)])
    assert svg.startswith("<svg")
    assert svg.count("<circle") == 2
    assert "<path" in svg


def test_off_wordlist_logins_are_collected_and_shown():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.failed", "src_ip": "1.2.3.4",
         "username": "zzz_probe", "password": "zzz_probe",
         "username_known": False, "password_known": False},
        {"timestamp": "2026-01-01T00:00:01Z", "event": "login.success", "src_ip": "5.6.7.8",
         "username": "root", "password": "123456",
         "username_known": True, "password_known": True},
    )
    report = Report(events)
    assert len(report.off_list_logins) == 1
    assert report.off_list_logins[0]["username"] == "zzz_probe"
    out = render_html(report, GeoLookup(None))
    assert "zzz_probe" in out
    assert "Credential attempts not on the known wordlist (1)" in out


def test_repeat_visitor_ips_are_identified():
    events = _events(
        # 1.2.3.4 logs in successfully twice -- the harvester-then-loader pattern
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.success", "src_ip": "1.2.3.4", "username": "root"},
        {"timestamp": "2026-01-02T00:00:00Z", "event": "login.success", "src_ip": "1.2.3.4", "username": "admin"},
        # 5.6.7.8 only logs in once -- not a repeat
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.success", "src_ip": "5.6.7.8", "username": "root"},
    )
    report = Report(events)
    assert report.repeat_visitor_ips == [
        ("1.2.3.4", report.successful_logins_by_ip["1.2.3.4"]),
    ]
    out = render_html(report, GeoLookup(None))
    assert "Repeat successful logins (1)" in out
    assert "1.2.3.4" in out
    assert "admin, root" in out  # usernames sorted alphabetically


def test_no_repeat_visitors_shows_explanatory_message():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.success", "src_ip": "5.6.7.8", "username": "root"},
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "Repeat successful logins (0)" in out
    assert "harvester bot" in out


def test_off_wordlist_section_explains_itself_when_not_configured():
    events = _events(
        {"timestamp": "2026-01-01T00:00:00Z", "event": "login.failed", "src_ip": "1.2.3.4",
         "username": "root", "password": "root", "username_known": None, "password_known": None},
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "No username/password wordlist configured" in out


# -- architecture breakdown ---------------------------------------------------------

def _dl(**kw):
    kw.setdefault("event", "file.download")
    kw.setdefault("timestamp", "2026-01-01T00:00:00Z")
    kw.setdefault("outcome", "success")
    kw.setdefault("url", "http://c2/x")
    return kw


def test_architecture_breakdown_groups_by_machine_bitness_endianness_and_abi():
    from dashboard import _architecture_breakdown
    rows = _architecture_breakdown([
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_MIPS",
            detected_bitness=32, detected_endianness="big", detected_abi="MIPS32 o32"),
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_MIPS",     # same sample refetched
            detected_bitness=32, detected_endianness="big", detected_abi="MIPS32 o32"),
        _dl(sha256="b" * 64, detected_type="elf", detected_machine="EM_MIPS",     # same machine, LE (MIPSEL)
            detected_bitness=32, detected_endianness="little", detected_abi="MIPS32 o32"),
    ])
    assert len(rows) == 2
    be, le = sorted(rows, key=lambda r: r["cells"][2])   # "big" < "little"
    assert be["cells"][:6] == ["EM_MIPS", "32-bit", "big", "MIPS32 o32", "2", "1"]
    assert le["cells"][:6] == ["EM_MIPS", "32-bit", "little", "MIPS32 o32", "1", "1"]


def test_architecture_breakdown_sorts_most_downloaded_first():
    from dashboard import _architecture_breakdown
    rows = _architecture_breakdown([
        _dl(sha256=str(i), detected_type="elf", detected_machine="EM_ARM", detected_bitness=32)
        for i in range(3)
    ] + [_dl(sha256="x" * 64, detected_type="elf", detected_machine="EM_X86_64", detected_bitness=64)])
    assert [r["cells"][0] for r in rows] == ["EM_ARM", "EM_X86_64"]


def test_architecture_breakdown_highlights_only_rows_that_match_the_persona():
    from dashboard import _architecture_breakdown
    rows = _architecture_breakdown([
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_RISCV",
            detected_bitness=64, arch_mismatch=False),
        _dl(sha256="b" * 64, detected_type="elf", detected_machine="EM_RISCV",
            detected_bitness=32, arch_mismatch=True),
    ])
    matched = next(r for r in rows if r["cells"][1] == "64-bit")
    mismatched = next(r for r in rows if r["cells"][1] == "32-bit")
    assert matched["match"] is True and "MATCHES PERSONA" in matched["cells"][0]
    assert mismatched["match"] is False and "MATCHES PERSONA" not in mismatched["cells"][0]
    assert matched["cells"][-1] == "1 match" and mismatched["cells"][-1] == "1 mismatch"


def test_architecture_breakdown_counts_stage2_and_non_elf_types_separately():
    from dashboard import _architecture_breakdown
    rows = _architecture_breakdown([
        _dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_ARM", detected_bitness=32, stage=2),
        _dl(sha256="b" * 64, detected_type="script"),
        _dl(sha256="c" * 64, detected_type="unknown"),
        _dl(url="http://c2/y", outcome="requested"),          # excluded: not a completed download
        _dl(url="http://c2/z", outcome="failed", error="HTTP 404"),   # excluded: not a success
    ])
    by_machine = {r["cells"][0]: r for r in rows}
    assert len(rows) == 3
    assert by_machine["EM_ARM"]["cells"][6] == "1"                  # stage-2 count shown
    assert by_machine["script"]["cells"][1:4] == ["-", "-", "-"]     # non-ELF: no bitness/endianness/abi
    assert by_machine["script"]["cells"][6] == "-"                  # no stage: shown as "-", not "0"
    assert "unknown" in by_machine


def test_architecture_breakdown_falls_back_to_raw_flags_when_undecoded():
    from dashboard import _architecture_breakdown
    rows = _architecture_breakdown([_dl(sha256="a" * 64, detected_type="elf", detected_machine="EM_PPC",
                                        detected_bitness=32, detected_flags=0x10000, detected_abi=None)])
    assert rows[0]["cells"][3] == "flags=0x10000"


def test_architecture_breakdown_empty_for_no_successful_downloads():
    from dashboard import _architecture_breakdown
    assert _architecture_breakdown([]) == []
    assert _architecture_breakdown([_dl(outcome="failed", error="HTTP 404")]) == []


# -- failure-reason breakdown --------------------------------------------------------

def test_failure_reason_buckets_by_type_not_by_literal_url_or_message():
    from dashboard import _failure_reason
    assert _failure_reason("HTTP 404") == "HTTP 404"
    assert _failure_reason("HTTP 500") == "HTTP 500"
    assert _failure_reason("blocked non-public destination: 169.254.169.254 is link-local") == \
        "blocked: non-public destination (SSRF guard)"
    assert _failure_reason("protocol 'tftp' not permitted by fetcher config") == \
        "protocol not permitted (fetcher.allowed_protocols)"
    assert _failure_reason("protocol 'tftp' not yet implemented") == "protocol not implemented (tftp/ftp)"
    assert _failure_reason("payload exceeded max_file_size_bytes (52428800)") == \
        "oversized transfer (max_file_size_bytes)"
    assert _failure_reason("per-session download limit reached") == "per-session download limit reached"
    assert _failure_reason("timed out waiting for isolated fetcher") == \
        "isolated fetcher did not respond (queued mode)"
    assert _failure_reason(None) == "(unknown)"


def test_failure_reason_truncates_long_unrecognised_errors():
    from dashboard import _failure_reason
    long_error = "Cannot connect to host " + "a" * 100
    reason = _failure_reason(long_error)
    assert len(reason) <= 83 and reason.endswith("...")


def test_failure_breakdown_groups_counts_and_flags_stage2():
    from dashboard import _failure_breakdown
    rows = _failure_breakdown([
        _dl(outcome="failed", error="HTTP 404"),
        _dl(outcome="failed", error="HTTP 404"),
        _dl(outcome="failed", error="HTTP 404", stage=2),
        _dl(outcome="failed", error="protocol 'tftp' not permitted by fetcher config"),
        _dl(outcome="success"),   # excluded: not a failure
    ])
    assert rows[0] == ["HTTP 404", "3", "1"]
    assert ["protocol not permitted (fetcher.allowed_protocols)", "1", "-"] in rows


def test_architecture_and_failure_tables_appear_in_the_rendered_page():
    events = _events(
        _dl(detected_type="elf", detected_machine="EM_RISCV", detected_bitness=64,
            detected_endianness="little", detected_abi="RVC double-float",
            arch_mismatch=False, sha256="a" * 64, stage=2),
        _dl(outcome="failed", error="HTTP 404"),
    )
    out = render_html(Report(events), GeoLookup(None))
    assert "Downloads by architecture" in out and "EM_RISCV" in out and "MATCHES PERSONA" in out
    assert "Failed downloads by reason" in out and "HTTP 404" in out
    assert "<div class='n'>1</div><div class='l'>Stage-2 downloads</div>" in out   # not just the label


def test_architecture_and_failure_error_text_is_escaped():
    events = _events(_dl(outcome="failed", error="Cannot connect to <script>pwn()</script>"))
    out = render_html(Report(events), GeoLookup(None))
    assert "<script>pwn()</script>" not in out
    assert "&lt;script&gt;pwn()&lt;/script&gt;" in out


def test_empty_architecture_and_failure_sections_show_fallback_text():
    out = render_html(Report([]), GeoLookup(None))
    assert "No successful downloads yet." in out
