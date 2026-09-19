"""Stage two: statically extract follow-on download URLs from a captured script.

A Mirai-style dropper's first download is usually a small shell script
(`bins.sh`) whose only job is to fetch one binary per CPU architecture. The
honeypot never runs that script (guarantee #1), so without this module the
architecture binaries -- the RISC-V ones are the whole point -- are never
requested.

This is *text processing only*: the script is split into segments, tokenised
with shlex and compared against fixed command names, exactly as the fake shell
handles attacker input. Nothing is executed, evaluated or handed to a shell.
Supported, deliberately small subset:

  * `wget`/`curl` (also via `busybox` or an absolute path), with the URL taken
    the same way the interactive shell takes it;
  * plain `NAME=value` assignments and `$NAME` / `${NAME}` substitution;
  * one level of `for NAME in a b c; do ... done`, expanded per value.

Anything it cannot resolve statically (command substitution, unresolved
variables, nested loops, base64 blobs) is skipped and counted, never guessed.
No regex here is built from attacker text; the two patterns are fixed and
linear-time, for the same reason grep/sed in the fake shell avoid regexes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from honeypot.shell.commands import (
    DOWNLOAD_COMMANDS,
    parse_download_args,
    split_command_line,
    tokenize,
)

# Bounds on how much attacker-controlled text we are willing to chew through.
MAX_SCRIPT_BYTES = 256 * 1024
_MAX_LINES = 5000
_MAX_SEGMENTS = 20000
_SEGMENTS_PER_LINE = 500
_MAX_LOOP_VALUES = 64
_MAX_LOOP_BODY = 200

_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_VARIABLE_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")

_BINARY_MAGIC = (b"\x7fELF", b"MZ", b"PK\x03\x04", b"\x1f\x8b")
_LOOP_KEYWORDS = ("for", "while", "until")


def looks_like_script(data: bytes) -> bool:
    """True for mostly-printable text that is not a known binary format.

    The ELF/shebang detector only recognises a script that starts with `#!`;
    droppers frequently omit it, so detection here is by content instead.
    """
    head = data[:4096]
    if not head or head.startswith(_BINARY_MAGIC) or b"\x00" in head:
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127)
    return printable / len(head) >= 0.95


@dataclass
class ScriptScan:
    urls: list[str] = field(default_factory=list)
    # Download commands found but not turned into a fetchable http(s) URL:
    # tftp/ftp (unsupported) or arguments containing an unresolved `$`.
    skipped: int = 0


def _has_unresolved(text: str) -> bool:
    return "$" in text or "`" in text


def _expand(text: str, variables: dict[str, str]) -> str:
    return _VARIABLE_REF.sub(
        lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), text)


def _first_word(segment: str) -> str:
    parts = segment.split(None, 1)
    return parts[0] if parts else ""


class _Scanner:
    def __init__(self, max_urls: int) -> None:
        self.max_urls = max_urls
        self.variables: dict[str, str] = {}
        self.urls: list[str] = []
        self.skipped = 0

    @property
    def full(self) -> bool:
        return len(self.urls) >= self.max_urls

    def run(self, segments: list[str]) -> None:
        i = 0
        while i < len(segments) and not self.full:
            if _first_word(segments[i]) == "for":
                i = self._for_loop(segments, i)
            else:
                self._segment(segments[i], self.variables)
                i += 1

    def _for_loop(self, segments: list[str], start: int) -> int:
        """Expand `for NAME in a b c` / `do` / body / `done`; returns the index
        after the loop. A malformed or nested construct is skipped, not guessed."""
        header = tokenize(segments[start])
        if len(header) < 4 or header[2] != "in":
            return start + 1
        name = header[1]
        expanded = [_expand(t, self.variables) for t in header[3:]]
        # One unresolved word (e.g. `$(ls /)`, which whitespace-splitting turns
        # into `$(ls` and `/)`) poisons the whole list: expand to nothing
        # rather than loop over a fragment.
        values = [] if any(_has_unresolved(w) for w in expanded) else \
            [v for w in expanded for v in w.split()][:_MAX_LOOP_VALUES]

        j = start + 1
        if j >= len(segments) or _first_word(segments[j]) != "do":
            return start + 1
        body: list[str] = []
        first = segments[j].split(None, 1)
        if len(first) == 2:
            body.append(first[1])
        j += 1
        depth = 0
        while j < len(segments) and len(body) < _MAX_LOOP_BODY:
            word = _first_word(segments[j])
            if word in _LOOP_KEYWORDS:
                depth += 1
            elif word == "done":
                if depth == 0:
                    break
                depth -= 1
            body.append(segments[j])
            j += 1

        for value in values:
            if self.full:
                break
            env = dict(self.variables)
            env[name] = value
            for seg in body:
                self._segment(seg, env)
        return j + 1

    def _segment(self, segment: str, env: dict[str, str]) -> None:
        tokens = tokenize(segment)
        if tokens and tokens[0] in ("do", "then", "else"):
            tokens = tokens[1:]
        if tokens and tokens[0] == "export":
            tokens = tokens[1:]
        # `NAME=value [NAME=value ...] [command ...]`
        while tokens:
            m = _ASSIGNMENT.match(tokens[0])
            if not m:
                break
            value = _expand(m.group(2), env)
            if not _has_unresolved(value):
                env[m.group(1)] = value
            tokens = tokens[1:]
        while tokens and (tokens[0] == "busybox" or tokens[0].endswith("/busybox")):
            tokens = tokens[1:]
        if not tokens:
            return
        cmd = tokens[0].rsplit("/", 1)[-1]
        if cmd not in DOWNLOAD_COMMANDS:
            return

        args = [_expand(t, env) for t in tokens[1:]]
        if any(_has_unresolved(a) for a in args):
            self.skipped += 1
            return
        req = parse_download_args(cmd, args)
        if req is None:
            return
        if req.protocol not in ("http", "https"):
            self.skipped += 1
            return
        if req.url not in self.urls and not self.full:
            self.urls.append(req.url)


def scan_script(text: str, max_urls: int) -> ScriptScan:
    segments: list[str] = []
    for line in text.splitlines()[:_MAX_LINES]:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        segments.extend(seg for _, seg in split_command_line(line, limit=_SEGMENTS_PER_LINE))
        if len(segments) >= _MAX_SEGMENTS:
            break
    scanner = _Scanner(max_urls)
    scanner.run(segments)
    return ScriptScan(urls=scanner.urls, skipped=scanner.skipped)
