"""Attacker-controlled text must not reach the operator's terminal through the logs.

asyncssh logs `Beginning auth for user <username>` at INFO with the username as
sent. Before the SafeFormatter, a username carrying an escape sequence came out
of `docker compose logs honeypot` unchanged (retitling the terminal, overwriting
lines), and one carrying a newline could forge a log line. events.jsonl was
never affected -- JSON encoding escapes control characters.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import sys
from pathlib import Path

import asyncssh

from honeypot.config.schema import CredentialPolicy, HoneypotConfig, PersonaConfig
from honeypot.listeners.ssh import start_ssh_listener
from honeypot.logging.events import EventLogger
from honeypot.logging.sanitize import SafeFormatter, escape_control_chars, setup_logging

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import status_check  # noqa: E402


def test_escape_control_chars_shows_them_and_leaves_normal_text_alone():
    hostile = "a\x1b]0;PWNED\x07b\r\nc\x7f\x9b31m\u202ed\u200be\ufeff\u2028"
    shown = escape_control_chars(hostile)
    assert shown == "a\\x1b]0;PWNED\\x07b\\x0d\\x0ac\\x7f\\x9b31m\\u202ed\\u200be\\ufeff\\u2028"
    assert escape_control_chars("root@host: /tmp # ls -la  é 日本語 http://1.2.3.4/a?b=c") == \
        "root@host: /tmp # ls -la  é 日本語 http://1.2.3.4/a?b=c"


def test_multiline_mode_keeps_only_newline_and_tab():
    assert escape_control_chars("a\nb\tc\x1bd\r", keep_newlines=True) == "a\nb\tc\\x1bd\\x0d"


def test_the_escape_table_matches_the_one_in_status_check():
    """status_check runs on a bare host where honeypot/ is not importable, so it carries its
    own copy of the table; if the two drift, one of them stops protecting something."""
    from honeypot.logging import sanitize
    assert sanitize._UNSAFE == status_check._UNSAFE_CHARS


def _record(msg, *args, exc_info=None):
    return logging.LogRecord("honeypot.test", logging.INFO, __file__, 1, msg, args, exc_info)


def test_formatter_escapes_the_message_arguments_and_all_newlines():
    formatter = SafeFormatter("%(levelname)s %(name)s: %(message)s")
    out = formatter.format(_record("Beginning auth for user %s", "x\x1b[2J\nFAKE INFO asyncssh: forged"))
    assert out == "INFO honeypot.test: Beginning auth for user x\\x1b[2J\\x0aFAKE INFO asyncssh: forged"
    assert "\n" not in out and "\x1b" not in out          # one record can only ever be one line


def test_formatter_restores_the_record_for_other_handlers():
    record = _record("user %s", "a\x1bb")
    SafeFormatter("%(message)s").format(record)
    assert record.getMessage() == "user a\x1bb"           # a JSON/file handler still sees the real data


def test_formatter_keeps_traceback_lines_but_escapes_the_exception_text():
    try:
        raise ValueError("bad input \x1b]0;PWNED\x07 here")
    except ValueError:
        out = SafeFormatter("%(message)s").format(_record("boom", exc_info=sys.exc_info()))
    assert out.startswith("boom\nTraceback (most recent call last):\n")     # still a readable traceback
    assert "ValueError: bad input \\x1b]0;PWNED\\x07 here" in out
    assert "\x1b" not in out and "\x07" not in out


def test_setup_logging_keeps_the_line_format_and_is_idempotent():
    root = logging.getLogger()
    before_level = root.level
    stream = io.StringIO()
    try:
        setup_logging("INFO", stream)
        handler = setup_logging("INFO", stream)          # second call replaces, not duplicates
        assert len([h for h in root.handlers if getattr(h, "_honeypot_safe", False)]) == 1
        logging.getLogger("asyncssh").info("[conn=1] Accepted SSH client connection")
    finally:
        root.removeHandler(handler)
        root.setLevel(before_level)
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} INFO asyncssh: \[conn=1\] Accepted SSH client connection\n",
                        stream.getvalue())


def test_a_hostile_ssh_username_cannot_reach_the_logs_raw_but_is_still_recorded(tmp_path, monkeypatch):
    """The reproduction: a client that does not filter usernames (asyncssh's own client applies
    SASLprep and refuses control characters, so that filter is switched off here)."""
    username = "a\x1b]0;PWNED\x07b\nFAKE 2026-01-01 00:00:00,000 INFO asyncssh: [conn=9] Auth succeeded for user root"
    stream = io.StringIO()
    root = logging.getLogger()
    before_level = root.level
    handler = setup_logging("INFO", stream)

    async def scenario() -> list[dict]:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"), credentials=CredentialPolicy(accept_any=False),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        server = await start_ssh_listener(config, EventLogger(config.logging.log_dir, "events.jsonl"),
                                          host_key_path=tmp_path / "host_key")
        monkeypatch.setattr("asyncssh.connection.saslprep", lambda s: s)
        try:
            await asyncssh.connect("127.0.0.1", server.get_addresses()[0][1], username=username, password="x",
                                   known_hosts=None, client_keys=None, agent_path=None)
        except asyncssh.PermissionDenied:
            pass
        await asyncio.sleep(0.3)
        server.close()
        return [json.loads(line) for line in (tmp_path / "logs" / "events.jsonl").read_text().splitlines()]

    try:
        events = asyncio.run(scenario())
    finally:
        root.removeHandler(handler)
        root.setLevel(before_level)

    out = stream.getvalue()
    assert "Beginning auth for user" in out                               # the asyncssh line this is about
    assert "\x1b" not in out and "\x07" not in out                        # nothing that acts on a terminal
    assert "a\\x1b]0;PWNED\\x07b\\x0aFAKE" in out                         # ...shown visibly instead
    assert not any(line.startswith("FAKE") for line in out.splitlines())  # a newline cannot forge a line
    # The analysis data is untouched: the attempt is recorded with the username exactly as sent.
    assert [e["username"] for e in events if e["event"] == "login.failed"] == [username]


# -- the entry points really install it ------------------------------------------------

def test_the_honeypot_process_installs_the_safe_handler(tmp_path, monkeypatch):
    import pytest
    from honeypot.main import run
    from tests.test_heartbeat import _config_file

    installed = []
    monkeypatch.setattr("honeypot.main.setup_logging", lambda level: installed.append(level))
    with pytest.raises(TimeoutError):
        asyncio.run(asyncio.wait_for(run(str(_config_file(tmp_path, heartbeat_seconds=0))), timeout=1.0))
    assert installed == ["INFO"]


def test_the_fetcher_worker_installs_the_safe_handler_too(tmp_path, monkeypatch):
    import pytest
    from honeypot.fetcher import worker
    from tests.test_heartbeat import _config_file

    installed = []
    monkeypatch.setattr(worker, "setup_logging", lambda level: installed.append(level))

    async def stop(*args, **kwargs):
        raise RuntimeError("stop after startup")
    monkeypatch.setattr(worker, "process_pending", stop)

    with pytest.raises(RuntimeError, match="stop after startup"):
        asyncio.run(worker.run(str(_config_file(tmp_path, heartbeat_seconds=0))))
    assert installed == ["INFO"]
