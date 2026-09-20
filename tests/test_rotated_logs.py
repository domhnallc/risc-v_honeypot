"""Rotation-aware log reading (tools/dashboard.py `_load_events`, used by
dashboard.py, dashboard_server.py and status_check.py).

logrotate renames events.jsonl to events.jsonl.1 at midnight UTC, then .2.gz,
.3.gz, ... Reading only events.jsonl shows "today so far", and a fresh rotation
looks exactly like the honeypot going quiet -- which is what happened the
first time this was looked at.
"""
from __future__ import annotations

import gzip
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import dashboard  # noqa: E402
import status_check  # noqa: E402
from dashboard import Report, _load_events, rotated_siblings  # noqa: E402
from status_check import _liveness_lines  # noqa: E402


def _line(ts: str, event: str = "session.connect", **extra) -> str:
    return json.dumps({"timestamp": ts, "event": event, **extra}) + "\n"


def _write(path: Path, *lines: str) -> None:
    path.write_text("".join(lines))


def _write_gz(path: Path, *lines: str) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        fh.write("".join(lines))


def _clear_cache():
    dashboard._ROTATED_CACHE.clear()


def test_rotated_siblings_are_ordered_oldest_first_numerically(tmp_path):
    live = tmp_path / "events.jsonl"
    live.write_text("")
    for name in ("events.jsonl.1", "events.jsonl.2.gz", "events.jsonl.10.gz", "events.jsonl.3.gz"):
        (tmp_path / name).write_text("")
    for junk in ("events.jsonl.bak", "events.jsonl.1.tmp", "events.jsonl.gz", "events.jsonl.old.gz",
                 "other.jsonl.1", "events.jsonl~"):
        (tmp_path / junk).write_text("")

    assert [p.name for p in rotated_siblings(live)] == [
        "events.jsonl.10.gz", "events.jsonl.3.gz", "events.jsonl.2.gz", "events.jsonl.1"]


def test_load_reads_every_rotated_day_then_the_live_file_in_time_order(tmp_path):
    _clear_cache()
    _write_gz(tmp_path / "events.jsonl.10.gz", _line("2026-09-10T12:00:00Z"))
    _write_gz(tmp_path / "events.jsonl.2.gz", _line("2026-09-18T12:00:00Z"))
    _write(tmp_path / "events.jsonl.1", _line("2026-09-19T23:55:40Z"))
    _write(tmp_path / "events.jsonl", _line("2026-09-20T09:08:55Z"))
    _write(tmp_path / "events.jsonl.bak", _line("1999-01-01T00:00:00Z"))   # not a rotation: ignored

    stamps = [e["timestamp"] for e in _load_events(tmp_path / "events.jsonl")]
    assert stamps == ["2026-09-10T12:00:00Z", "2026-09-18T12:00:00Z",
                      "2026-09-19T23:55:40Z", "2026-09-20T09:08:55Z"]


def test_no_rotated_reads_only_the_named_file(tmp_path):
    _clear_cache()
    _write(tmp_path / "events.jsonl.1", _line("2026-09-19T23:55:40Z"))
    _write(tmp_path / "events.jsonl", _line("2026-09-20T09:08:55Z"))
    stamps = [e["timestamp"] for e in _load_events(tmp_path / "events.jsonl", include_rotated=False)]
    assert stamps == ["2026-09-20T09:08:55Z"]


def test_a_missing_live_file_still_reads_the_rotated_ones(tmp_path):
    """Right after a rotation, before the first new event, only .1 exists."""
    _clear_cache()
    _write(tmp_path / "events.jsonl.1", _line("2026-09-19T23:55:40Z"))
    assert len(_load_events(tmp_path / "events.jsonl")) == 1


def test_a_truncated_gzip_keeps_what_it_can_and_does_not_stop_the_rest(tmp_path, capsys):
    _clear_cache()
    full = tmp_path / "full.gz"
    _write_gz(full, *[_line(f"2026-09-1{d}T00:00:00Z") for d in range(1, 6)])
    (tmp_path / "events.jsonl.2.gz").write_bytes(full.read_bytes()[:-12])     # cut short, as by a full disk
    _write(tmp_path / "events.jsonl.1", _line("2026-09-19T23:55:40Z"))
    _write(tmp_path / "events.jsonl", _line("2026-09-20T09:08:55Z"))

    events = _load_events(tmp_path / "events.jsonl")
    stamps = [e["timestamp"] for e in events]
    assert stamps[-2:] == ["2026-09-19T23:55:40Z", "2026-09-20T09:08:55Z"]
    assert "events.jsonl.2.gz" in capsys.readouterr().err


def test_rotated_files_are_parsed_once_but_the_live_file_every_time(tmp_path, monkeypatch):
    _clear_cache()
    _write_gz(tmp_path / "events.jsonl.2.gz", _line("2026-09-18T12:00:00Z"))
    _write(tmp_path / "events.jsonl.1", _line("2026-09-19T23:55:40Z"))
    live = tmp_path / "events.jsonl"
    _write(live, _line("2026-09-20T09:08:55Z"))

    parsed: list[str] = []
    real = dashboard._parse_file
    monkeypatch.setattr(dashboard, "_parse_file", lambda p: (parsed.append(p.name), real(p))[1])

    _load_events(live)
    assert sorted(parsed) == ["events.jsonl", "events.jsonl.1", "events.jsonl.2.gz"]
    parsed.clear()
    _write(live, _line("2026-09-20T09:08:55Z"), _line("2026-09-20T09:09:15Z"))   # the live log grew
    assert len(_load_events(live)) == 4
    assert parsed == ["events.jsonl"]

    parsed.clear()
    _write(tmp_path / "events.jsonl.1", _line("2026-09-19T23:55:40Z"), _line("2026-09-19T23:59:00Z"))
    assert len(_load_events(live)) == 5          # a rotated file that was replaced is re-read
    assert "events.jsonl.1" in parsed


# -- status_check ------------------------------------------------------------------

def _two_day_log(tmp_path: Path) -> Path:
    _clear_cache()
    _write(tmp_path / "events.jsonl.1",
           _line("2026-09-19T23:50:00Z", session_id="a", src_ip="1.1.1.1", protocol="ssh"),
           _line("2026-09-19T23:55:40Z", session_id="b", src_ip="2.2.2.2", protocol="ssh"))
    _write(tmp_path / "events.jsonl",
           _line("2026-09-20T09:08:55Z", session_id="c", src_ip="3.3.3.3", protocol="telnet"))
    return tmp_path / "events.jsonl"


def test_status_check_covers_both_sides_of_a_midnight_rotation(tmp_path, monkeypatch, capsys):
    live = _two_day_log(tmp_path)
    monkeypatch.setattr(sys, "argv", ["status_check.py", "--events", str(live)])
    status_check.main()
    out = capsys.readouterr()
    assert "Volume:       3 sessions" in out.out
    assert "Window:       2026-09-19T23:50:00Z  to  2026-09-20T09:08:55Z" in out.out
    assert "also read 1 rotated log file(s)" in out.err


def test_status_check_no_rotated_shows_only_today(tmp_path, monkeypatch, capsys):
    live = _two_day_log(tmp_path)
    monkeypatch.setattr(sys, "argv", ["status_check.py", "--events", str(live), "--no-rotated"])
    status_check.main()
    assert "Volume:       1 sessions" in capsys.readouterr().out


# -- liveness -------------------------------------------------------------------

NOW = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)


def test_liveness_reports_age_and_no_warning_when_fresh():
    events = [{"timestamp": "2026-09-20T09:56:00Z", "event": "session.connect"}]
    lines = _liveness_lines(events, now=NOW, stale_minutes=30)
    assert lines == ["Newest event: 2026-09-20T09:56:00Z  (4m ago)"]


def test_liveness_warns_after_a_long_silence():
    """The overnight scare: last event 23:55:41Z, checked at 10:00Z."""
    events = [{"timestamp": "2026-09-19T23:55:41Z", "event": "session.closed"}]
    lines = _liveness_lines(events, now=NOW, stale_minutes=30)
    assert lines[0] == "Newest event: 2026-09-19T23:55:41Z  (10h04m ago)"
    assert lines[-1].startswith("WARNING:") and "10h04m" in lines[-1] and "docker compose ps" in lines[-1]


def test_liveness_uses_the_newest_event_of_any_type_and_reports_heartbeats():
    events = [
        {"timestamp": "2026-09-20T05:00:00Z", "event": "session.connect"},
        {"timestamp": "2026-09-20T09:55:00Z", "event": "honeypot.heartbeat"},
        {"timestamp": "2026-09-20T09:40:00Z", "event": "honeypot.heartbeat"},
    ]
    lines = _liveness_lines(events, now=NOW, stale_minutes=30)
    assert lines[0].startswith("Newest event: 2026-09-20T09:55:00Z")
    assert lines[1] == "Heartbeat:    last 2026-09-20T09:55:00Z, 2 in this log"
    assert len(lines) == 2      # a heartbeat five minutes ago is not stale


def test_liveness_survives_junk_and_empty_logs():
    assert _liveness_lines([], now=NOW) == ["Newest event: (none in this log)"]
    junk = [{"timestamp": "yesterday"}, {"timestamp": None}, {"event": "x"}]
    assert _liveness_lines(junk, now=NOW) == ["Newest event: (none in this log)"]
