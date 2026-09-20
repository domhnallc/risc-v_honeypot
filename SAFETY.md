# SAFETY.md

This document lists the non-negotiable safety guarantees this honeypot makes,
per `riscv-honeypot-spec.md` sec 2, and exactly how the code enforces each one.
These constraints override every other design decision in this codebase --
any violation is a bug, even if it makes the honeypot less convincing.

## 1. Attacker-supplied data is never executed

The honeypot process never calls `exec()`, real `chmod +x`, `subprocess.*`
with `shell=True`, `dlopen`, or the `eval`/`exec` builtins on anything derived
from attacker input.

- `honeypot/shell/commands.py` parses every command line with `shlex.split`
  purely for tokenization; the tokens are only ever compared against a fixed
  set of Python string literals (`if cmd == "wget":`, etc.) and never handed
  to a shell, `eval`, or `exec`.
- "Execution" commands (`chmod +x`, `./file`, `sh file`, `/bin/busybox file`)
  are pattern-matched and answered with a plausible fake response (see
  `CommandResult.execution_attempt`), but no filesystem permission is ever
  changed and nothing is ever run -- `honeypot/shell/filesystem.py` is a
  pure in-memory dict tree with no `os.chmod`/`os.exec*` calls anywhere in it.
- Enforced by `tests/test_no_dangerous_calls.py`, a static-analysis test that
  fails the build if `os.system`, any `os.exec*`, a `subprocess` call with
  `shell=True`, or the `eval`/`exec` builtins appear anywhere under
  `honeypot/`. Run it directly with `pytest tests/test_no_dangerous_calls.py`.
- The fake `grep`/`sed`/`awk` (`honeypot/shell/commands.py`) never compile a
  regex out of attacker-supplied pattern/script/program text -- `grep` and
  `sed` use plain `str`/substring operations only, and `awk` matches
  attacker text against one fixed, author-written, non-backtracking regex
  (never the reverse). This isn't just style: this fake shell runs on a
  single shared `asyncio` event loop, so a compiled regex with attacker-
  controlled catastrophic backtracking would be a real, synchronous
  denial-of-service against every concurrent session, not merely an
  unrealistic simulation gap.

## 2. Fetching is isolated from session handling

`honeypot/fetcher/fetcher.py` is the only module in the codebase that performs
an outbound fetch of an attacker-supplied URL. Every function in it takes
only a `DownloadJob` (plain data: session id, source IP, URL, protocol,
requested filename) and a `FetcherConfig` -- it never receives a reference to
`SessionManager`, the fake shell, or any other session-handling state, so it
can be lifted out of the session process entirely.

This isolation is only *real* when `fetcher.mode: queued` is set
(`honeypot/config/schema.py`). In that mode `SessionManager` (honeypot
session process) only ever calls `enqueue_job()` and polls a shared directory
for a result file that a separate process writes -- it never imports or calls
`fetch_and_quarantine` itself, which is exactly what
`tests/test_session.py::test_queued_mode_never_calls_fetch_and_quarantine_in_process`
asserts (it monkeypatches `fetch_and_quarantine` to raise if called, then
proves a full enqueue/claim/result round trip still works). The default
`fetcher.mode: inline` (used by `configs/riscv64.yaml`/`riscv32.yaml`) instead
awaits the fetch directly in the session process -- a deliberate development
convenience for single-process/`python -m honeypot.main` use, not the
isolation guarantee itself. **Always use `mode: queued` for any deployment
where the fetcher genuinely runs as a different process/container** --
`configs/riscv64-docker.yaml`/`riscv32-docker.yaml` and `docker-compose.yml`
do this.

`honeypot/fetcher/worker.py` is the standalone entry point for running the
fetcher as a genuinely separate OS process (`python -m honeypot.fetcher.worker
<config>`), reading jobs from a watched directory (`honeypot/fetcher/queue.py`)
rather than a function call. **For production, run this worker on a separate
host or in a separate network namespace/container with no route back to the
honeypot's management or internal network** -- the v1 default of awaiting the
fetch in-process (see `honeypot/session/manager.py`) is a development
convenience the spec explicitly permits, not the recommended production
topology.

## 3. Downloaded files are quarantined read-only and never touched again

`fetch_and_quarantine()` in `honeypot/fetcher/fetcher.py` streams the response
to a temp file, then renames it to `<sha256>.bin` and calls
`os.chmod(final_path, 0o440)` immediately -- read-only for owner, no access
for anyone else, no execute bit for anyone. Every metadata field (hashes,
size, detected type, source session/IP/URL) is written to a `.json` sidecar
next to it, which is also chmod'd `0o440`. Nothing downstream of this point
ever opens the file for anything other than reading bytes for hashing/type
detection, both of which already happened before the chmod.

## 4. File-type detection never executes or partially loads the sample

`honeypot/fetcher/elf.py` reads only the first 64 bytes of a sample and
inspects them with `struct.unpack` against fixed offsets (ELF's `e_ident`/
`e_machine` fields) and a small magic-byte signature table. It never shells
out to the `file` binary, never uses a library that maps or loads the sample,
and never executes anything. This is a deliberate v1 substitute for
`python-magic`/libmagic (spec sec 4.4 step 5 permits either) chosen to avoid
adding a native-library dependency and to keep the detection logic fully
auditable in one small file.

## 5. The fetcher's outbound network path is constrained

Full network-layer isolation (no route from the fetcher's egress to your
logging/storage/management network) is still an infrastructure/deployment
guarantee -- see the production topology note in point 2 above and deploy
per that section's advice. But `FetcherConfig.block_private_networks`
(default `True`) enforces the code-side half of this from inside the
process itself: `honeypot/fetcher/ssrf_guard.py`'s `SafeTCPConnector`
overrides `_resolve_host()` so every connection `fetch_and_quarantine()`
makes -- the attacker's original URL, a literal IP address given directly
(e.g. `wget http://169.254.169.254/...`, no hostname at all), *and* any
HTTP redirect returned mid-fetch -- is rejected if it reaches loopback/
RFC1918/link-local/reserved/multicast. (An earlier version of this guard
only wrapped aiohttp's *resolver*, which aiohttp never calls when the URL's
host is already a literal IP -- confirmed exploitable live: a fetch to a
literal loopback IP with a real server listening went straight through,
unblocked. `_resolve_host` is the one choke point every connection
funnels through regardless of that distinction, and
`test_ssrf_guard.py::test_literal_ip_target_is_actually_blocked_end_to_end`
now guards against this specific regression class live, not just via a
unit test of the address-classification logic.) Leave this `True` in any
deployment reachable from the internet; only a config that deliberately
targets local addresses on purpose (`configs/training.yaml`) sets it
`False`.

Separately, `_render_download_response()` in `honeypot/session/manager.py`
never echoes a fetch failure's raw exception text back to the attacker
(`_wget_error_text()` maps it to one of a small set of generic, realistic
busybox-wget error lines instead) -- otherwise the raw aiohttp/asyncio
error string would tell an attacker probing internal addresses whether a
given host:port was open, closed, filtered, or blocked by this guarantee,
which would itself leak the reconnaissance signal this guarantee exists to
deny them.

## Resource limits on attacker-driven work

Not one of the numbered guarantees, but they bound what a single hostile
client can make this process do:

- **Input size**: Telnet drops a connection at 8192 bytes per line; SSH
  exec commands and interactive lines are truncated to the same
  `MAX_INPUT_CHARS` before being logged, recorded or echoed.
- **Commands per line**: `split_command_line` yields at most
  `MAX_CHAIN_SEGMENTS` (30) segments and stops scanning once it has them.
- **Outbound fetches**: `fetcher.max_downloads_per_session` (default 20)
  caps fetch attempts per session; further `wget`/`curl` are logged as
  failed and answered with an ordinary "can't connect" line. Without it, one
  connection could aim hundreds of requests a minute at a third party.
- **Stage-two fetches** (URLs found inside a captured script): the script is
  scanned as text only and never run. Every follow-up goes through the same
  `fetch_and_quarantine` as an attacker-typed `wget` (SSRF guard, size cap,
  timeout, http/https only) and is bounded per script
  (`stage2_max_urls_per_script`), per session (`stage2_max_per_session`), per
  target host (`stage2_max_per_host`), by a per-URL cooldown
  (`stage2_dedupe_seconds`) and by depth (`stage2_max_depth`). The per-host cap is
  the one that stops a script listing endless distinct URLs at one third party.
  In the docker deployment the session container never reads the quarantine:
  the worker does the scanning, and the session treats the worker's result
  (including job ids) as untrusted. Note the per-host cap covers stage two
  only; the attacker's own typed `wget`s are bounded per session
  (`max_downloads_per_session`) but not per host.
- **Known gap**: `listeners.max_session_seconds` bounds a session's shell or
  exec channel, not the SSH connection itself; an authenticated client can
  keep an idle connection open (bounded per source IP by
  `max_connections_per_ip`).

## Attacker text and the operator's terminal

Usernames, client banners, URLs and command lines are attacker-controlled, and
they end up wherever the honeypot writes or displays data. A string containing a
terminal escape sequence can retitle your terminal, overwrite earlier lines or
hide text; one containing a newline can forge a whole log line. Where each output
stands:

- **`var/logs/events.jsonl`**: safe to `cat`/`tail`. JSON encoding escapes control
  characters, and the record keeps the value exactly as sent, for analysis.
- **Container/process logs** (`docker compose logs`): all logging goes through
  `honeypot/logging/sanitize.py`'s `SafeFormatter` (installed by `honeypot.main` and the
  fetcher worker), which shows control, C1 and invisible/bidi characters as `\xNN`/`\uNNNN`
  and escapes newlines in a message so it can only ever be one line. This was a real hole:
  asyncssh logs `Beginning auth for user <username>` at INFO with the username as sent.
- **`tools/status_check.py`**: escapes the same characters in everything it prints;
  a test keeps its table identical to the logging one.
- **`tools/dashboard.py`**: HTML-escapes attacker fields.
- **Transcripts** (`var/transcripts/*.jsonl`) hold base64, safe until decoded. Anything that
  *replays* raw session bytes in a terminal would execute their escape sequences: use a
  throwaway terminal or a browser-based player.

Not covered: text that an operator decodes or extracts by hand. When in doubt, pipe it
through `cat -v`.

## Verifying these guarantees

Run the full test suite, including the static-analysis check:

```
pytest
```

`tests/test_no_dangerous_calls.py` is the regression guard for guarantee #1
and will fail the build (not just warn) if a disallowed call is introduced
anywhere under `honeypot/`.
