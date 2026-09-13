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
