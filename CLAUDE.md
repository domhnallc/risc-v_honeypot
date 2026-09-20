# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

A medium-interaction SSH/Telnet honeypot, written in Python/asyncio, that impersonates a
RISC-V Linux IoT/embedded device, in order to attract and record Mirai-style malware
droppers that check CPU architecture before deploying a payload — and to safely capture
any dropped binaries without ever executing them. Architecturally modeled loosely on
Cowrie (fake shell + session transcript + structured JSON logging), but purpose-built for
RISC-V bait and payload capture. `riscv-honeypot-spec.md` is the original build spec and
remains the authoritative reference for intent; `SAFETY.md` documents the safety
guarantees and exactly how the code enforces each one — read both before making changes
that touch command dispatch or the fetcher.

## Commands

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'          # installs honeypot + asyncssh/aiohttp/pydantic/pyyaml + pytest

pytest                            # full suite
pytest tests/test_no_dangerous_calls.py   # just the safety static-analysis gate
pytest tests/test_commands.py::test_wget_is_parsed_not_executed   # single test

python -m honeypot.main configs/riscv64.yaml   # run the honeypot (SSH+Telnet, in-process fetcher)
python -m honeypot.fetcher.worker configs/riscv64.yaml   # standalone fetcher process (prod deployment mode)
```

There is no separate lint config; correctness here is enforced by the test suite,
above all `tests/test_no_dangerous_calls.py`.

## Non-negotiable safety constraints

These override every other design decision. Any violation is a bug, even if it makes the
honeypot less convincing to attackers. Full detail and per-guarantee enforcement notes are
in `SAFETY.md`; summary:

1. **Never execute attacker-supplied data.** No `exec()`, real `chmod +x`,
   `subprocess.run(shell=True)`, `dlopen`, or `eval`/`exec` builtins anywhere under
   `honeypot/`. `honeypot/shell/commands.py` tokenizes command lines with `shlex.split`
   purely for parsing; tokens are only ever compared against fixed string literals, never
   handed to a shell/`eval`/`exec`.
2. **Payload fetching is isolated from session handling.** `honeypot/fetcher/fetcher.py`
   is the only module that performs an outbound fetch, and every function in it takes only
   a `DownloadJob` + `FetcherConfig` — no reference to session/shell state — so it can run
   in-process (v1 default, via `SessionManager.handle_command` awaiting it directly) or be
   split out into `honeypot/fetcher/worker.py` as a genuinely separate process.
3. **Quarantine, don't touch.** `fetch_and_quarantine()` writes `<sha256>.bin` and its
   `.json` sidecar with `chmod 0o440` immediately after hashing/detection; nothing after
   that point opens the file for anything but reading bytes.
4. **File-type inspection is static-only.** `honeypot/fetcher/elf.py` is a hand-rolled
   ELF header parser (reads `e_ident`/`e_machine` via `struct.unpack` at fixed offsets,
   plus a small magic-byte table for non-ELF types) — deliberately not `python-magic`/
   libmagic or the `file` binary, to avoid a native-library dependency and keep detection
   auditable in one file. This is a spec-permitted substitution (spec §4.4 step 5 allows
   either).
5. **The fetcher's outbound network path must be constrained** from reaching the
   honeypot's own management/internal network — this is a deployment/network-layer
   guarantee (see "Deploying safely" in README.md), not something enforceable from inside
   one Python process.

`tests/test_no_dangerous_calls.py` is the CI-runnable regression guard for constraint #1:
a grep-based static check (scoped to `honeypot/`, not `tests/`, so its own pattern strings
don't trip themselves) that fails the build if `os.system`, `os.exec*`, `subprocess(...,
shell=True)`, or `eval`/`exec` appear anywhere in the runtime package. Keep it green.

## Architecture

```
SSH Listener (asyncssh) ─┐
                          ├─▶ SessionManager (honeypot/session/manager.py)
Telnet Listener (asyncio)┘         │
                                   ├─▶ FakeFilesystem + dispatch() (honeypot/shell/)
                                   │         │
                                   │         ├─▶ EventLogger + TranscriptWriter (honeypot/logging/)
                                   │         └─▶ fetch_and_quarantine() (honeypot/fetcher/)
                                   │                   — awaited in-process for v1;
                                   │                     honeypot/fetcher/worker.py runs it
                                   │                     as a separate process for production
```

- **`honeypot/session/manager.py`** (`SessionManager`) is the shared state machine both
  listeners feed into, so command parsing/logging is one implementation, not duplicated
  per protocol. It owns login-attempt checking (`config.credentials`), the per-session
  `FakeFilesystem`, and the download round trip: on a `wget`/`curl`/`tftp` command it logs
  a `file.download` `"requested"` event *immediately* (even before the fetch runs), awaits
  `fetch_and_quarantine`, logs a second `"success"`/`"failed"` outcome event, and renders a
  busybox-wget-style response string back to the attacker so their script keeps going.
- **`honeypot/shell/commands.py`** (`dispatch()`) is the safety-critical parser: given a
  raw line + `FakeFilesystem` + `PersonaConfig`, it returns a `CommandResult` with
  `output`, an optional `download_request`, an optional `execution_attempt` (set for
  `chmod +x`, `./file`, `sh file`, `/bin/busybox file` — acknowledged with a plausible fake
  success but never touching real permissions or running anything), and `exit_session`.
  `SessionManager.handle_command` first splits the line on `;`/newline/`&&`/`||`
  (`split_command_line`, quote-aware, text-only, capped at `MAX_CHAIN_SEGMENTS`) and
  dispatches each segment, using `CommandResult.status` to pick the `&&`/`||` arm; the SSH
  listener also runs exec requests (`ssh host "cmd"`) through the same path. Unknown
  `busybox X` replies `X: applet not found`, which Mirai-family droppers wait for.
  A `--help` check runs first for any command with an entry in
  `honeypot/shell/help_text.py` (BusyBox's own applet help text, not GNU man pages) —
  deliberately excluding `cd`/`exit`/`logout`, since those are ash builtins with no real
  `--help` handling, so `cd --help` instead falls through to a genuine "No such file or
  directory" (it tries to chdir into a directory literally named `--help`). `grep`/`sed`/
  `awk` are implemented with plain substring/fixed-pattern matching only — never a regex
  compiled from attacker text — see SAFETY.md guarantee #1's ReDoS note for why.
- **`honeypot/shell/filesystem.py`** (`FakeFilesystem`) is a pure in-memory dict tree
  seeded per-persona (`/proc/cpuinfo`, `/proc/version`, `/etc/os-release`, a fake `/bin`
  busybox-applet listing) — there is no path from any operation here to the real host
  filesystem. `copy_node`/`move_node` back `cp`/`mv` (object-graph copy/reparent, no real
  inode model); `listdir_nodes` backs `ls -l`'s per-entry file-vs-directory distinction.
- **Stage two** (`honeypot/fetcher/script_scan.py`, `stage2.py`): when a fetched file is a
  text script (a dropper's `bins.sh`), the *fetcher side* reads the quarantined bytes,
  scans them as text for `wget`/`curl` URLs (plain `NAME=value` and one-level
  `for ... in ...; do ...; done` expansion; anything unresolvable is skipped and counted)
  and fetches those through the normal `fetch_and_quarantine` path -- the script is never
  run. It lives fetcher-side because the docker session container deliberately cannot read
  `var/quarantine`: in queued mode the worker plans and queues the follow-ups and reports
  them in the parent's result, and `SessionManager` only polls for outcomes to log
  (`file.download` with `stage`/`parent_sha256`, plus `file.stage2_scan`). Bounded by
  `fetcher.stage2_*` (per script, per session, per host, per-URL cooldown, depth) because the
  script is attacker-authored. Disable with `fetcher.stage2_enabled: false`.
- **`honeypot/fetcher/`**: `queue.py` defines `DownloadJob`/`make_job` and the file-based
  atomic job queue (`enqueue_job`/`claim_pending_jobs`, used by the standalone worker, not
  by the in-process v1 path); `elf.py` is the static detector; `fetcher.py` streams the
  HTTP(S) response with a byte cap and timeout, hashes while streaming, then quarantines
  (4xx/5xx is a failure, not a sample; `http_status` is recorded; requests carry BusyBox
  wget's `User-Agent: Wget` -- `fetcher.user_agent` -- and no automatic `Accept*` headers);
  `worker.py` is the `python -m honeypot.fetcher.worker <config>` standalone entry point
  for running the fetcher as a physically separate process.
- **SSH host key**: persisted, not regenerated per rebuild. The docker configs put it at
  `var/keys/ssh_host_key`, a directory `docker-compose.yml` bind-mounts (a test fails if the two
  drift apart). `_load_or_create_host_key` (`honeypot/listeners/ssh.py`) writes it 0600 via
  temp-file + rename and, if the location is unusable, falls back to a temporary in-memory key
  with an ERROR log rather than crashing the container.
- **Tools and rotation**: `tools/dashboard.py`'s `_load_events` (shared by `status_check.py` and
  `dashboard_server.py`) also reads logrotate's `events.jsonl.N[.gz]` siblings, oldest first;
  `--no-rotated` opts out. `status_check.py` prints a `Newest event` line and warns on silence.
- **`honeypot/config/schema.py`** defines the pydantic models (`PersonaConfig`,
  `ListenerConfig`, `CredentialPolicy`, `FetcherConfig`, `LoggingConfig`,
  `HoneypotConfig`) and `load_config()`. Both `configs/riscv64.yaml` and
  `configs/riscv32.yaml` validate against this schema — check it first when a config field
  seems to be missing or misnamed.
- **`honeypot/logging/events.py`** provides `EventLogger` (one JSON object per line to
  `var/logs/events.jsonl`: `session.connect`/`session.closed`, `login.success`/`failed`,
  `command.input`, `file.download`, `file.execution_attempt`, plus
  `session.client_version` (SSH banner, logged once the version exchange has happened),
  `auth.attempt` (offered public keys with fingerprints, and "none" probes that never tried a
  credential), `file.stage2_scan` and `honeypot.heartbeat` -- written at startup and every
  `logging.heartbeat_seconds`, so a silent log can be told from a stopped honeypot) and `TranscriptWriter` (one
  JSONL file per session under `var/transcripts/`, base64-encoded raw send/recv bytes).

**Why `honeypot/logging/` and not a top-level `logging/`**: the spec's directory sketch
(§6) lists `listeners/, session/, shell/, fetcher/, logging/, config/, tests/` at repo
root, but a top-level `logging` package would shadow the standard library `logging` module
for absolute imports done from repo root. Everything except `tests/` is nested under the
`honeypot` package instead, for exactly this reason — preserve that nesting rather than
flattening it back out to match the spec sketch literally.

**Both riscv32 and riscv64 personas are config-driven**, not hardcoded (`configs/*.yaml`),
since droppers branch on `uname -m` and comparing what gets dropped per-arch is a stated
project goal — `fetch_and_quarantine`'s `arch_mismatch` result flags exactly this
(`None` = not judged/not RISC-V, `True`/`False` = definite mismatch/match).

## Explicitly out of scope (spec §7)

- Automatic detonation/sandboxing of captured binaries (quarantine + hash only)
- Deep filesystem emulation for high-interaction fidelity — this is medium-interaction
- GeoIP/threat-intel enrichment beyond a pluggable stub
- Web dashboard/UI
- A real TFTP/FTP fetch implementation — `fetch_and_quarantine` logs the request but
  returns an explicit "not yet implemented" failure for any protocol other than HTTP/HTTPS
