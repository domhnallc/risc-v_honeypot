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
from honeypot.shell.filesystem import FakeDir, FakeDynamicFile, FakeFilesystem, FakeSymlink
from honeypot.shell import sysstate
from honeypot.shell.help_text import HELP_TEXT

DOWNLOAD_COMMANDS = {"wget", "curl", "tftp"}

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

def _render_ifconfig() -> str:
    # eth0's counters are real device state that only ever climbs since
    # boot -- returning the exact same numbers on every call (the old,
    # static behavior here) is itself a tell. lo's traffic is boring and
    # stays static; nothing meaningfully drops packets over loopback.
    net = sysstate.network_counters()
    rx_human = sysstate.format_bytes_human(net["rx_bytes"])
    tx_human = sysstate.format_bytes_human(net["tx_bytes"])
    return (
        "eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  \n"
        "          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0\n"
        "          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\n"
        f"          RX packets:{net['rx_packets']} errors:0 dropped:0 overruns:0 frame:0\n"
        f"          TX packets:{net['tx_packets']} errors:0 dropped:0 overruns:0 carrier:0\n"
        "          collisions:0 txqueuelen:1000 \n"
        f"          RX bytes:{net['rx_bytes']} ({rx_human})  TX bytes:{net['tx_bytes']} ({tx_human})\n"
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

def _render_top() -> str:
    # Every number here used to be a fixed constant -- calling `top` twice
    # in a row (or across two sessions) returned byte-identical output,
    # which no real device's load/memory figures ever do.
    _total, used, free_kb = sysstate.memory_kb()
    usr, sysp, idle = sysstate.cpu_percentages()
    one, five, fifteen = sysstate.load_average()
    cached = int(used * 0.22)
    zero = 0.0
    return (
        f"Mem: {used}K used, {free_kb}K free, 0K shrd, 0K buff, {cached}K cached\n"
        f"CPU: {usr:5.1f}% usr {sysp:5.1f}% sys {zero:5.1f}% nic {idle:5.1f}% idle"
        f" {zero:5.1f}% io {zero:5.1f}% irq {zero:5.1f}% sirq\n"
        f"Load average: {one:.2f} {five:.2f} {fifteen:.2f} 1/89 1234\n"
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
    # Shell exit status (0 = success). Only consulted by the `&&` / `||`
    # chaining logic in SessionManager -- droppers routinely write
    # `cd /tmp || cd /var/run; wget A || curl B`, and mishandling which arm
    # runs would either skip the download or fetch it twice.
    status: int = 0


# Upper bound on commands per input line. Each segment may trigger an awaited
# download, so an unbounded `wget a; wget b; ...` line is a cheap way to tie a
# session up; real droppers chain a dozen commands at most.
MAX_CHAIN_SEGMENTS = 30


def split_command_line(raw: str, limit: int = MAX_CHAIN_SEGMENTS) -> list[tuple[str, str]]:
    """Split one input line on `;`, newline, `&&` and `||`, honouring quotes.

    Returns [(operator_before, segment), ...]; the first operator is always
    ";". This is a text splitter only -- nothing here interprets or executes
    anything. A lone `|` or `&` is deliberately NOT a separator: pipes have no
    stdin model in this fake shell, and `2>&1` / a trailing `&` must survive
    intact inside their segment. `limit` caps the segment count (the default
    suits interactive input; the stage-two script scanner passes a larger one).
    """
    segments: list[tuple[str, str]] = []
    buf: list[str] = []
    op = ";"
    quote: str | None = None
    i, n = 0, len(raw)

    def flush(next_op: str) -> None:
        nonlocal op
        seg = "".join(buf).strip()
        buf.clear()
        if seg:
            segments.append((op, seg))
            op = next_op
        elif segments:
            op = next_op  # e.g. `a; ; b` or trailing `;` -- keep last real operator

    while i < n and len(segments) < limit:
        c = raw[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < n:
                i += 1
                buf.append(raw[i])
        elif c in "'\"":
            quote = c
            buf.append(c)
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            i += 1
            buf.append(raw[i])
        elif c in ";\n":
            flush(";")
        elif raw.startswith("&&", i):
            flush("&&")
            i += 1
        elif raw.startswith("||", i):
            flush("||")
            i += 1
        else:
            buf.append(c)
        i += 1
    flush(";")
    return segments[:limit]


def tokenize(raw: str) -> list[str]:
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


def parse_download_args(cmd: str, args: list[str]) -> DownloadRequest | None:
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
        # BusyBox: `tftp [-g|-p] [-l LOCAL] [-r REMOTE] [-b SIZE] HOST [PORT]`;
        # tftp-hpa/atftp style: `tftp HOST -c get REMOTE`. Option *values*
        # must be skipped when looking for HOST -- `tftp -r x.sh -g HOST` is
        # the classic Mirai form, and taking the first non-dash word logged
        # "x.sh" as the C2 host.
        host = None
        local_file = remote_file = None
        it = iter(args)
        for a in it:
            if a in ("-l", "-r", "-b"):
                value = next(it, None)
                if a == "-l":
                    local_file = value
                elif a == "-r":
                    remote_file = value
            elif a == "-c":
                command = next(it, None)
                file_arg = next(it, None)
                if command in ("get", "put"):
                    remote_file = file_arg
            elif a.startswith("-"):
                continue
            elif host is None:
                host = a
        if host is None:
            return None
        filename = explicit_out or local_file or remote_file or "tftp-payload"
        return DownloadRequest(protocol="tftp", url=host, requested_filename=filename)

    if url is None:
        return None
    scheme = urlsplit(url).scheme or "http"
    path = urlsplit(url).path
    filename = explicit_out or (path.rsplit("/", 1)[-1] if path else "") or "index.html"
    return DownloadRequest(protocol=scheme, url=url, requested_filename=filename)


def dispatch(raw: str, fs: FakeFilesystem, persona: PersonaConfig,
             username: str | None = None) -> CommandResult:
    raw = raw.rstrip("\n").rstrip("\r")
    stripped = raw.strip()
    if not stripped:
        return CommandResult(output="")

    tokens = tokenize(stripped)
    cmd, args = tokens[0], tokens[1:]

    # busybox wget/tftp/curl are commonly invoked as `busybox wget ...`, but
    # `busybox` alone (or with its own --help/--list flags) has real output
    # of its own -- only unwrap to "busybox <applet> ..." when the first arg
    # actually looks like an applet name, not one of busybox's own flags.
    if cmd in ("busybox", "/bin/busybox"):
        if not args or args[0] == "--help":
            return CommandResult(output=_busybox_banner())
        if args[0] == "--list":
            return CommandResult(output="\n".join(sorted(persona_render.bin_listing())))
        if args[0] == "--list-full":
            return CommandResult(output="\n".join(f"/bin/{a}" for a in sorted(persona_render.bin_listing())))
        if not args[0].startswith("-"):
            applet = args[0]
            if applet in set(persona_render.bin_listing()) | {"busybox"}:
                cmd, args = applet, args[1:]
            else:
                # Mirai-family droppers send `/bin/busybox <MARKER>` and wait
                # for exactly this reply before moving on to the payload
                # stage; silence (or "not found") makes them give up, which
                # is what was ending sessions with zero downloads.
                # A path-shaped argument (`/bin/busybox ./mal`) is still an
                # attempt to run something, so it stays logged as one.
                looks_like_path = "/" in applet or fs.read_file(applet) is not None
                return CommandResult(
                    output=f"{applet}: applet not found",
                    execution_attempt=stripped if looks_like_path else None,
                    status=127,
                )

    if "--help" in args and cmd in HELP_TEXT:
        return CommandResult(output=HELP_TEXT[cmd])

    if cmd in DOWNLOAD_COMMANDS:
        req = parse_download_args(cmd, args)
        if req is None:
            return CommandResult(output=f"{cmd}: missing URL", status=1)
        return CommandResult(output="", download_request=req)

    if cmd == "chmod":
        # chmod +x <file>: acknowledge silently (real chmod prints nothing on
        # success) but never touch anything -- FakeFilesystem holds no
        # executable bit at all, so there's nothing to "flip" here on
        # purpose. Logged as an execution_attempt per spec sec 4.3.
        return CommandResult(output="", execution_attempt=f"chmod {' '.join(args)}".strip())

    if cmd in ("sh", "ash") or cmd.startswith("./") or cmd.startswith("/"):
        return CommandResult(output="", execution_attempt=stripped)

    if cmd == "cd":
        err = fs.chdir(args[0] if args else "/root")
        return CommandResult(output=err or "", status=1 if err else 0)

    if cmd == "pwd":
        return CommandResult(output=fs.cwd_display())

    if cmd == "ls":
        flags, positionals = _parse_short_flags(args)
        target = positionals[0] if positionals else None
        nodes = fs.listdir_nodes(target)
        if isinstance(nodes, str):
            return CommandResult(output=nodes, status=2)
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
                elif isinstance(node, FakeSymlink):
                    # Real BusyBox installs: one real ELF (busybox), every
                    # applet a symlink to it -- shown as its own line type,
                    # sized as the target string's length like a real symlink.
                    lines.append(
                        f"lrwxrwxrwx    1 root     root     {len(node.target):>8} "
                        f"Jan  1  2024 {name} -> {node.target}"
                    )
                elif isinstance(node, FakeDynamicFile):
                    # Real /proc pseudo-files report size 0 via stat() too --
                    # the kernel generates their content on demand rather
                    # than storing it.
                    lines.append(f"-r--r--r--    1 root     root            0 Jan  1  2024 {name}")
                else:
                    perms = "-rwxr-xr-x" if name in applets else "-rw-r--r--"
                    if node.size_override is not None:
                        size = node.size_override
                    else:
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
        missing = False
        for path in args:
            content = fs.read_file(path)
            if content is None:
                missing = True
                outputs.append(f"cat: {path}: No such file or directory")
            else:
                outputs.append(content.rstrip("\n"))
        return CommandResult(output="\n".join(outputs), status=1 if missing else 0)

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
        return CommandResult(output=_render_ifconfig())

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
        return CommandResult(output=_render_top())

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
        # These devices don't have real multi-user separation -- any
        # accepted login effectively runs as root -- but the account name
        # itself should still track whatever the attacker actually logged
        # in as (matching SessionManager.prompt()'s user@host), not be
        # hardcoded to "root" regardless of it: logging in as "admin" and
        # then having whoami/id insist you're "root" is an easy one-command
        # honeypot tell.
        return CommandResult(output=username or "root")

    if cmd == "id":
        user = username or "root"
        return CommandResult(output=f"uid=0({user}) gid=0({user}) groups=0({user})")

    if cmd == "ps":
        return CommandResult(output="  PID USER     COMMAND\n    1 root     init\n   84 root     -ash")

    if cmd == "free":
        total, used, free_kb = sysstate.memory_kb()
        return CommandResult(output=(
            f"              total        used        free\n"
            f"Mem:{total:>15}{used:>12}{free_kb:>12}"
        ))

    if cmd == "df":
        return CommandResult(output="Filesystem           1K-blocks      Used Available Use% Mounted on\n/dev/root               129024     54212     74812  42% /")

    if cmd == "true":
        return CommandResult(output="")

    if cmd == "false":
        return CommandResult(output="", status=1)

    if cmd in ("exit", "logout"):
        return CommandResult(output="", exit_session=True)

    if cmd == "reboot":
        return CommandResult(output="", exit_session=True)

    return CommandResult(output=f"-ash: {cmd}: not found", status=127)
