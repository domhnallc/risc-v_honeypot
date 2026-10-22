#!/usr/bin/env python3
"""Print one session transcript (var/transcripts/<session_id>.jsonl) as readable text.

TranscriptWriter stores each chunk of session I/O base64-encoded so the file can
hold any bytes at all. This decodes them for reading -- and those bytes are
attacker-controlled: escape sequences that retitle the window or overwrite earlier
lines, bidi overrides, raw telnet IAC negotiation. So, as in status_check.py, every
control, C1 and invisible/bidi character is shown as a visible \\xNN / \\uNNNN, and
bytes that aren't valid UTF-8 are shown as \\xNN too. Only newlines and tabs are
kept as themselves (CRLF is folded to a newline; a lone CR is shown as \\x0d).
Nothing is executed, fetched or interpreted -- this only ever prints text.

Consecutive chunks in the same direction are merged into one block, so telnet's
byte-at-a-time input reads as a line rather than one block per keystroke.

Usage:
    python3 tools/transcript.py var/transcripts/44cf314d4f344e03.jsonl
    python3 tools/transcript.py 44cf314d4f344e03                 # looked up in --dir
    python3 tools/transcript.py 44cf314d4f344e03 --input-only    # just what the client sent
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).parent))
from status_check import _UNSAFE_CHARS  # noqa: E402

# A transcript is multi-line by nature, so (like sanitize's traceback handling) it keeps
# newlines and tabs; everything else in the table is still escaped.
_UNSAFE_MULTILINE = {c: s for c, s in _UNSAFE_CHARS.items() if c not in (0x0A, 0x09)}

_LABELS = {"recv": "client ->", "send": "<- honeypot"}
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]+")


def render_bytes(data: bytes) -> str:
    """Attacker bytes -> text that is safe to print to a terminal."""
    text = data.replace(b"\r\n", b"\n").decode("utf-8", errors="backslashreplace")
    return text.translate(_UNSAFE_MULTILINE)


def merged_runs(lines: Iterator[str]) -> Iterator[tuple[str, str, bytes]]:
    """(timestamp of first chunk, direction, bytes) for each run of same-direction chunks.
    Malformed lines are reported as their own ("?", "error", message) run, not skipped silently."""
    current: tuple[str, str, bytearray] | None = None
    for lineno, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
            direction = entry["direction"]
            data = base64.b64decode(entry["data_b64"], validate=True)
            timestamp = str(entry.get("timestamp", "?"))
        except (ValueError, KeyError, TypeError, binascii.Error) as exc:
            if current:
                yield current[0], current[1], bytes(current[2])
                current = None
            yield "?", "error", f"line {lineno}: unreadable entry ({type(exc).__name__})".encode()
            continue
        if current and current[1] == direction:
            current[2].extend(data)
        else:
            if current:
                yield current[0], current[1], bytes(current[2])
            current = (timestamp, direction, bytearray(data))
    if current:
        yield current[0], current[1], bytes(current[2])


def render_transcript(lines: Iterator[str], input_only: bool = False) -> Iterator[str]:
    for timestamp, direction, data in merged_runs(lines):
        if input_only and direction != "recv":
            continue
        label = _LABELS.get(direction, "[" + render_bytes(direction.encode()) + "]")
        yield f"--- {render_bytes(timestamp.encode())}  {label}"
        body = render_bytes(data)
        for text_line in body.split("\n")[:-1] if body.endswith("\n") else body.split("\n"):
            yield f"    {text_line}"


def resolve(target: str, transcript_dir: Path) -> Path:
    path = Path(target)
    if path.is_file():
        return path
    if not _SESSION_ID.fullmatch(target):
        sys.exit(f"no such transcript file: {render_bytes(target.encode())}")
    path = transcript_dir / f"{target}.jsonl"
    if not path.is_file():
        sys.exit(f"no transcript for session {target} in {transcript_dir}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("transcript", help="path to a transcript .jsonl, or a bare session id")
    parser.add_argument("--dir", type=Path, default=Path("var/transcripts"),
                        help="where to look up a bare session id (default: var/transcripts)")
    parser.add_argument("--input-only", action="store_true", help="show only what the client sent")
    args = parser.parse_args()

    path = resolve(args.transcript, args.dir)
    print(f"# transcript {render_bytes(str(path).encode())}")
    with path.open(encoding="utf-8", errors="replace") as fh:
        for out_line in render_transcript(fh, input_only=args.input_only):
            print(out_line)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # `transcript.py ... | head`: see the same handler in status_check.py.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
