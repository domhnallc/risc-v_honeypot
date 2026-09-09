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

import re
import shlex
import textwrap
from dataclasses import dataclass
from urllib.parse import urlsplit

from honeypot.config.schema import PersonaConfig
from honeypot.shell import persona as persona_render
from honeypot.shell.filesystem import FakeDir, FakeFilesystem
from honeypot.shell.help_text import HELP_TEXT

_DOWNLOAD_COMMANDS = {"wget", "curl", "tftp"}

# Deliberately NOT in HELP_TEXT / this short-circuit: cd, exit, logout. Real
# BusyBox ash implements those as shell builtins with no --help handling of
# their own, so e.g. `cd --help` genuinely tries to chdir into a directory
# literally named "--help" on a real device -- letting it fall through to
# the normal `cd` handler below reproduces that "No such file or directory"
# behavior for free, which is more authentic than fabricating help text that
# real BusyBox wouldn't print.

# Hardcoded, fixed-complexity pattern -- matched against (never built from)
# attacker-supplied `awk` program text. Safe against ReDoS because the
# pattern itself is simple/non-backtracking and author-controlled; see the
# no-regex-on-attacker-data note on _grep_matches below for why this is the
# one deliberate exception.
_AWK_PRINT_FIELD = re.compile(r"^\{\s*print\s+\$(\d+)\s*\}$")

_FAKE_IFCONFIG_OUTPUT = (
    "eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  \n"
    "          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0\n"
    "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
    "          RX packets:118273 errors:0 dropped:0 overruns:0 frame:0\n"
    "          TX packets:94215 errors:0 dropped:0 overruns:0 carrier:0\n"
    "          collisions:0 txqueuelen:1000 \n"
    "          RX bytes:132484219 (126.3 MiB)  TX bytes:14882931 (14.1 MiB)\n"
    "\n"
    "lo        Link encap:Local Loopback  \n"
    "          inet addr:127.0.0.1  Mask:255.0.0.0\n"
    "          UP LOOPBACK RUNNING  MTU:65536  Metric:1\n"
    "          RX packets:12 errors:0 dropped:0 overruns:0 frame:0\n"
    "          TX packets:12 errors:0 dropped:0 overruns:0 carrier:0\n"
    "          collisions:0 txqueuelen:1000 \n"
    "          RX bytes:960 (960.0 B)  TX bytes:960 (960.0 B)"
)

_FAKE_IP_ADDR_OUTPUT = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue qlen 1000\n"
    "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
    "    inet 127.0.0.1/8 scope host lo\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000\n"
    "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
    "    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0"
)

_FAKE_TOP_OUTPUT = (
    "Mem: 48212K used, 207788K free, 0K shrd, 0K buff, 12000K cached\n"
    "CPU:   2.3% usr   1.1% sys   0.0% nic  96.6% idle   0.0% io   0.0% irq   0.0% sirq\n"
    "Load average: 0.08 0.03 0.01 1/89 1234\n"
    "  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND\n"
    "    1     0 root     S     1204   0%   0% init\n"
    "   84     1 root     S     1204   0%   0% -ash"
)

def _busybox_banner() -> str:
    """`busybox` invoked bare (or with --help): version banner + the same
    applet list ls /bin shows, so the two never drift out of sync -- both
    are generated from persona_render.bin_listing()."""
    functions_block = "\n".join(
        f"\t{line}" for line in textwrap.wrap(", ".join(sorted(persona_render.bin_listing())), width=68)
    )
    return (
        "BusyBox v1.36.1 (2023-06-02 16:00:00 UTC) multi-call binary.\n"
        "BusyBox is copyrighted by many authors between 1998-2015.\n"
        "Licensed under GPLv2. See source distribution for detailed\n"
        "copyright notices.\n\n"
        "Usage: busybox [function [arguments]...]\n"
        "   or: busybox --list[-full]\n"
        "   or: function [arguments]...\n\n"
        "\tBusyBox is a multi-call binary that combines many common Unix\n"
        "\tutilities into a single executable.  Most people will create a\n"
        "\tlink to busybox for each function they wish to use and BusyBox\n"
        "\twill act like whatever it was invoked as.\n\n"
        "Currently defined functions:\n"
        f"{functions_block}"
    )


_FAKE_MOUNT_OUTPUT = (
    "/dev/root on / type squashfs (ro,relatime)\n"
    "proc on /proc type proc (rw,noexec,nosuid,nodev,relatime)\n"
    "sysfs on /sys type sysfs (rw,noexec,nosuid,nodev,relatime)\n"
    "tmpfs on /tmp type tmpfs (rw,relatime)\n"
    "devpts on /dev/pts type devpts (rw,relatime,mode=600)"
)


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


def _parse_short_flags(args: list[str]) -> tuple[set[str], list[str]]:
    """Expand combined short flags (e.g. '-la' -> {'l','a'}) out of args.

    Returns (flags, positionals). Unknown '--long-opts' are silently
    dropped rather than erroring -- attacker command lines are never
    well-formed by assumption, and a fake shell that crashes on an unknown
    flag would abort the attacker's script early, losing telemetry.
    """
    flags: set[str] = set()
    positionals: list[str] = []
    for a in args:
        if a.startswith("--"):
            continue
        if a.startswith("-") and len(a) > 1:
            flags.update(a[1:])
        else:
            positionals.append(a)
    return flags, positionals


def _grep_matches(needle: str, haystack: str, ignore_case: bool) -> bool:
    """Plain substring search -- deliberately NOT re.search(attacker_pattern,
    ...). Compiling a regex out of attacker-supplied text and running it
    against arbitrarily long input is a real ReDoS vector (Python's re isn't
    guaranteed linear-time), and this fake shell runs on a single asyncio
    event loop shared by every concurrent session -- a catastrophic-
    backtracking pattern would stall all of them. Literal matching only,
    consistent with spec sec 2.3's "no dynamic code paths accept attacker
    input as ... eval targets" for the same underlying reason."""
    if ignore_case:
        needle, haystack = needle.lower(), haystack.lower()
    return needle in haystack


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

    # busybox wget/tftp/curl are commonly invoked as `busybox wget ...`, but
    # `busybox` alone (or with its own --help/--list flags) has real output
    # of its own -- only unwrap to "busybox <applet> ..." when the first arg
    # actually looks like an applet name, not one of busybox's own flags.
    if cmd == "busybox":
        if not args or args[0] == "--help":
            return CommandResult(output=_busybox_banner())
        if args[0] == "--list":
            return CommandResult(output="\n".join(sorted(persona_render.bin_listing())))
        if args[0] == "--list-full":
            return CommandResult(output="\n".join(f"/bin/{a}" for a in sorted(persona_render.bin_listing())))
        if not args[0].startswith("-"):
            cmd, args = args[0], args[1:]

    if "--help" in args and cmd in HELP_TEXT:
        return CommandResult(output=HELP_TEXT[cmd])

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
        flags, positionals = _parse_short_flags(args)
        target = positionals[0] if positionals else None
        nodes = fs.listdir_nodes(target)
        if isinstance(nodes, str):
            return CommandResult(output=nodes)
        names = sorted(nodes.keys())
        if "a" not in flags and "A" not in flags:
            names = [n for n in names if not n.startswith(".")]
        display = (([".", ".."] if "a" in flags else []) + names)
        # bin_listing() covers the applet symlinks; "busybox" itself is the
        # one real ELF binary seeded separately by FakeFilesystem._seed().
        applets = set(persona_render.bin_listing()) | {"busybox"}
        if "l" in flags:
            lines = []
            for name in display:
                if name in (".", ".."):
                    lines.append(f"drwxr-xr-x    2 root     root          4096 Jan  1  2024 {name}")
                    continue
                node = nodes[name]
                if isinstance(node, FakeDir):
                    lines.append(f"drwxr-xr-x    2 root     root          4096 Jan  1  2024 {name}")
                else:
                    perms = "-rwxr-xr-x" if name in applets else "-rw-r--r--"
                    size = len(node.content.encode()) if node.content else 0
                    lines.append(f"{perms}    1 root     root     {size:>8} Jan  1  2024 {name}")
            return CommandResult(output="\n".join(lines))
        if "1" in flags:
            return CommandResult(output="\n".join(display))
        return CommandResult(output="  ".join(display))

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

    if cmd == "cp":
        _, positionals = _parse_short_flags(args)
        if len(positionals) < 2:
            return CommandResult(output="cp: missing file operand")
        err = fs.copy_node(positionals[0], positionals[1])
        return CommandResult(output=err or "")

    if cmd == "mv":
        _, positionals = _parse_short_flags(args)
        if len(positionals) < 2:
            return CommandResult(output="mv: missing file operand")
        err = fs.move_node(positionals[0], positionals[1])
        return CommandResult(output=err or "")

    if cmd == "grep":
        flags, positionals = _parse_short_flags(args)
        if not positionals:
            return CommandResult(output="grep: missing pattern")
        pattern, files = positionals[0], positionals[1:]
        if not files:
            # No stdin/pipe support in this fake shell -- nothing to search.
            return CommandResult(output="")
        ignore_case, invert = "i" in flags, "v" in flags
        count_only, names_only = "c" in flags, "l" in flags
        out_lines: list[str] = []
        for path in files:
            content = fs.read_file(path)
            if content is None:
                out_lines.append(f"grep: {path}: No such file or directory")
                continue
            matched = [line for line in content.splitlines()
                       if _grep_matches(pattern, line, ignore_case) != invert]
            if names_only:
                if matched:
                    out_lines.append(path)
            elif count_only:
                out_lines.append(f"{path}:{len(matched)}" if len(files) > 1 else str(len(matched)))
            else:
                prefix = f"{path}:" if len(files) > 1 else ""
                out_lines.extend(f"{prefix}{m}" for m in matched)
        return CommandResult(output="\n".join(out_lines))

    if cmd == "sed":
        _, positionals = _parse_short_flags(args)
        if not positionals:
            return CommandResult(output="sed: no script specified")
        script, files = positionals[0], positionals[1:]
        if not files:
            return CommandResult(output="")
        # Only the extremely common single s/old/new/[g] form is supported,
        # via plain str.replace -- not a regex engine driven by attacker
        # text, for the same ReDoS reasoning as _grep_matches above.
        if len(script) < 3 or script[0] != "s":
            return CommandResult(output=f"sed: -e expression #1, char {len(script)}: unknown command")
        delim = script[1]
        parts = script[2:].split(delim)
        if len(parts) < 2:
            return CommandResult(output="sed: unterminated 's' command")
        old, new = parts[0], parts[1]
        replace_all = len(parts) > 2 and "g" in parts[2]
        out_lines = []
        for path in files:
            content = fs.read_file(path)
            if content is None:
                out_lines.append(f"sed: can't read {path}: No such file or directory")
                continue
            for line in content.splitlines():
                out_lines.append(line.replace(old, new) if replace_all else line.replace(old, new, 1))
        return CommandResult(output="\n".join(out_lines))

    if cmd == "awk":
        _, positionals = _parse_short_flags(args)
        if not positionals:
            return CommandResult(output="awk: no program specified")
        program, files = positionals[0], positionals[1:]
        match = _AWK_PRINT_FIELD.match(program.strip())
        if not match or not files:
            # Only the common '{print $N}' field-extraction idiom is
            # supported (droppers use it to pull one field out of e.g.
            # /proc/cpuinfo) -- anything else is out of scope for a fake
            # shell, not a real AWK interpreter.
            return CommandResult(output="")
        field_idx = int(match.group(1))
        out_lines = []
        for path in files:
            content = fs.read_file(path)
            if content is None:
                continue
            for line in content.splitlines():
                fields = line.split()
                if field_idx == 0:
                    out_lines.append(line)
                elif 1 <= field_idx <= len(fields):
                    out_lines.append(fields[field_idx - 1])
        return CommandResult(output="\n".join(out_lines))

    if cmd == "ifconfig":
        return CommandResult(output=_FAKE_IFCONFIG_OUTPUT)

    if cmd == "ip":
        sub = args[0] if args else None
        if sub in ("a", "addr", "address"):
            return CommandResult(output=_FAKE_IP_ADDR_OUTPUT)
        if sub is None:
            return CommandResult(output=HELP_TEXT["ip"])
        return CommandResult(output=f'Object "{sub}" is unknown, try "ip help".')

    if cmd == "ping":
        flags, positionals = _parse_short_flags(args)
        count = 4
        for i, a in enumerate(args):
            if a == "-c" and i + 1 < len(args):
                try:
                    count = max(1, min(int(args[i + 1]), 20))
                except ValueError:
                    pass
        host = positionals[-1] if positionals else None
        if host is None:
            return CommandResult(output="ping: missing host")
        lines = [f"PING {host} ({host}): 56 data bytes"]
        lines += [f"64 bytes from {host}: seq={n} ttl=64 time=0.0{40 + n} ms" for n in range(1, count + 1)]
        lines += ["", f"--- {host} ping statistics ---",
                  f"{count} packets transmitted, {count} packets received, 0% packet loss"]
        return CommandResult(output="\n".join(lines))

    if cmd == "top":
        return CommandResult(output=_FAKE_TOP_OUTPUT)

    if cmd == "vi":
        # Full-screen interactive editor: genuinely out of scope for a
        # line-at-a-time fake shell (there's no keystroke-level session
        # state to enter an "editing mode"). Opens and returns silently
        # rather than erroring, so an attacker's script doesn't abort.
        return CommandResult(output="")

    if cmd == "mount":
        if not args:
            return CommandResult(output=_FAKE_MOUNT_OUTPUT)
        # `mount DEVICE NODE`: acknowledged like chmod/exec-attempt commands
        # -- FakeFilesystem's mount table never actually changes.
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
