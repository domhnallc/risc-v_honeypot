"""Fake shell command dispatcher (spec sec 4.3).

This is the single most safety-critical module in the codebase: every
attacker-supplied command line passes through here, and *nothing* in this
file ever reaches a real shell, interpreter, or the `exec`/`eval` builtins.
Parsing uses shlex.split purely to tokenize text; the result is only ever
compared against fixed Python strings and formatted back out through f-strings
built from trusted templates -- attacker text is interpolated as inert data,
never as a format string or code target.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from urllib.parse import urlsplit

from honeypot.config.schema import PersonaConfig
from honeypot.shell import persona as persona_render
from honeypot.shell.filesystem import FakeFilesystem

_DOWNLOAD_COMMANDS = {"wget", "curl", "tftp"}


@dataclass
class DownloadRequest:
    protocol: str
    url: str
    requested_filename: str


@dataclass
class CommandResult:
    output: str = ""
    download_request: DownloadRequest | None = None
    execution_attempt: str | None = None  # target path, if this command tried to run something
    exit_session: bool = False


def _tokenize(raw: str) -> list[str]:
    try:
        return shlex.split(raw)
    except ValueError:
        # Unbalanced quotes etc: fall back to naive whitespace split rather
        # than raising -- attacker input is never well-formed by assumption.
        return raw.split()


def _parse_download_args(cmd: str, args: list[str]) -> DownloadRequest | None:
    url = None
    explicit_out = None
    it = iter(range(len(args)))
    for i in it:
        tok = args[i]
        if "://" in tok:
            url = tok
        elif tok in ("-O", "-o") and i + 1 < len(args):
            explicit_out = args[i + 1]
        elif tok.startswith("-O") and len(tok) > 2:
            explicit_out = tok[2:]

    if cmd == "tftp":
        host = next((a for a in args if not a.startswith("-") and "://" not in a), None)
        remote_file = None
        for i, a in enumerate(args):
            if a == "-r" and i + 1 < len(args):
                remote_file = args[i + 1]
        if host is None:
            return None
        filename = explicit_out or remote_file or "tftp-payload"
        return DownloadRequest(protocol="tftp", url=host, requested_filename=filename)

    if url is None:
        return None
    scheme = urlsplit(url).scheme or "http"
    path = urlsplit(url).path
    filename = explicit_out or (path.rsplit("/", 1)[-1] if path else "") or "index.html"
    return DownloadRequest(protocol=scheme, url=url, requested_filename=filename)


def dispatch(raw: str, fs: FakeFilesystem, persona: PersonaConfig) -> CommandResult:
    raw = raw.rstrip("\n").rstrip("\r")
    stripped = raw.strip()
    if not stripped:
        return CommandResult(output="")

    tokens = _tokenize(stripped)
    cmd, args = tokens[0], tokens[1:]

    # busybox wget/tftp/curl are commonly invoked as `busybox wget ...`
    if cmd == "busybox" and args:
        cmd, args = args[0], args[1:]

    if cmd in _DOWNLOAD_COMMANDS:
        req = _parse_download_args(cmd, args)
        if req is None:
            return CommandResult(output=f"{cmd}: missing URL")
        return CommandResult(output="", download_request=req)

    if cmd == "chmod":
        # chmod +x <file>: acknowledge silently (real chmod prints nothing on
        # success) but never touch anything -- FakeFilesystem holds no
        # executable bit at all, so there's nothing to "flip" here on
        # purpose. Logged as an execution_attempt per spec sec 4.3.
        return CommandResult(output="", execution_attempt=f"chmod {' '.join(args)}".strip())

    if cmd in ("sh", "/bin/busybox") or cmd.startswith("./") or cmd.startswith("/"):
        return CommandResult(output="", execution_attempt=stripped)

    if cmd == "cd":
        err = fs.chdir(args[0] if args else "/root")
        return CommandResult(output=err or "")

    if cmd == "pwd":
        return CommandResult(output=fs.cwd_display())

    if cmd == "ls":
        target = args[0] if args and not args[0].startswith("-") else None
        entries = fs.listdir(target)
        if isinstance(entries, str):
            return CommandResult(output=entries)
        return CommandResult(output="  ".join(entries))

    if cmd == "cat":
        if not args:
            return CommandResult(output="")
        outputs = []
        for path in args:
            content = fs.read_file(path)
            if content is None:
                outputs.append(f"cat: {path}: No such file or directory")
            else:
                outputs.append(content.rstrip("\n"))
        return CommandResult(output="\n".join(outputs))

    if cmd == "echo":
        text = " ".join(args)
        if ">" in args:
            idx = args.index(">")
            text_to_write = " ".join(args[:idx])
            target = args[idx + 1] if idx + 1 < len(args) else None
            if target:
                fs.write_file(target, text_to_write + "\n")
            return CommandResult(output="")
        return CommandResult(output=text)

    if cmd == "mkdir":
        for path in args:
            if not path.startswith("-"):
                fs.make_dir(path)
        return CommandResult(output="")

    if cmd == "touch":
        for path in args:
            if fs.read_file(path) is None:
                fs.write_file(path, "")
        return CommandResult(output="")

    if cmd == "rm":
        for path in args:
            if not path.startswith("-"):
                fs.remove(path)
        return CommandResult(output="")

    if cmd == "uname":
        if "-a" in args:
            return CommandResult(output=persona_render.uname_a(persona))
        if "-m" in args:
            return CommandResult(output=persona_render.uname_m(persona))
        if "-r" in args:
            return CommandResult(output=persona.kernel_version)
        return CommandResult(output="Linux")

    if cmd == "whoami":
        return CommandResult(output="root")

    if cmd == "id":
        return CommandResult(output="uid=0(root) gid=0(root) groups=0(root)")

    if cmd == "ps":
        return CommandResult(output="  PID USER     COMMAND\n    1 root     init\n   84 root     -ash")

    if cmd == "free":
        return CommandResult(output="              total        used        free\nMem:         256000       48212      207788")

    if cmd == "df":
        return CommandResult(output="Filesystem           1K-blocks      Used Available Use% Mounted on\n/dev/root               129024     54212     74812  42% /")

    if cmd in ("exit", "logout"):
        return CommandResult(output="", exit_session=True)

    if cmd == "reboot":
        return CommandResult(output="", exit_session=True)

    return CommandResult(output=f"-ash: {cmd}: not found")
