"""Keeping attacker-controlled text from acting on the terminal that shows the logs.

Anything an attacker sends -- an SSH username, a client banner, a URL -- can end
up in a log line. asyncssh, for one, logs `Beginning auth for user <username>`
at INFO with the username exactly as sent, so a username containing an escape
sequence reached `docker compose logs honeypot` unchanged and could retitle the
operator's terminal, overwrite earlier lines, or (with a newline) forge a whole
log line. events.jsonl was never affected: JSON encoding escapes control
characters.

The fix is at the log handler, so it covers every logger in the process, ours
and the libraries', including text nobody thought to sanitise. Control, C1 and
invisible/bidi-formatting characters are shown as a visible \\xNN / \\uNNNN.
tools/status_check.py carries the same table for the same reason (it runs on a
bare host where this package is not importable); a test keeps the two identical.
"""
from __future__ import annotations

import logging
import sys
from typing import IO

_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

_UNSAFE: dict[int, str] = {c: f"\\x{c:02x}" for c in (*range(0x20), 0x7F, *range(0x80, 0xA0))}
_UNSAFE.update({
    c: f"\\u{c:04x}"
    for c in (*range(0x200B, 0x2010), 0x2028, 0x2029, *range(0x202A, 0x202F),
              *range(0x2060, 0x2065), *range(0x2066, 0x206A), 0xFEFF)
})
# A traceback is legitimately several lines, so it keeps its newlines (and tabs).
_UNSAFE_MULTILINE: dict[int, str] = {c: s for c, s in _UNSAFE.items() if c not in (0x0A, 0x09)}


def escape_control_chars(text: str, keep_newlines: bool = False) -> str:
    return text.translate(_UNSAFE_MULTILINE if keep_newlines else _UNSAFE)


class SafeFormatter(logging.Formatter):
    """A Formatter whose output cannot carry terminal control sequences.

    The message (with its arguments applied) is escaped *entirely*, newlines
    included, so text in a message cannot start what looks like a new log line.
    Exception and stack text keep their own line breaks but are escaped otherwise.
    """

    def format(self, record: logging.LogRecord) -> str:
        original = (record.msg, record.args)
        record.msg, record.args = escape_control_chars(record.getMessage()), None
        try:
            return super().format(record)
        finally:
            record.msg, record.args = original

    def formatException(self, ei) -> str:  # noqa: ANN001 - signature fixed by logging
        return escape_control_chars(super().formatException(ei), keep_newlines=True)

    def formatStack(self, stack_info: str) -> str:
        return escape_control_chars(super().formatStack(stack_info), keep_newlines=True)


def setup_logging(level: str | int = "INFO", stream: IO[str] | None = None) -> logging.Handler:
    """Send all logging to `stream` (stderr by default) through SafeFormatter.

    Same line format as the previous logging.basicConfig call. Idempotent: a
    handler installed by an earlier call is replaced, not duplicated.
    """
    root = logging.getLogger()
    for old in [h for h in root.handlers if getattr(h, "_honeypot_safe", False)]:
        root.removeHandler(old)
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(SafeFormatter(_FORMAT))
    handler._honeypot_safe = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)
    return handler
