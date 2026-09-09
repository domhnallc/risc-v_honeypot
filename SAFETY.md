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

This is an infrastructure/deployment guarantee, not something enforceable
from inside a single Python process -- see the production topology note in
point 2 above. Concretely: deploy the fetcher in a network namespace or on a
host whose only permitted egress is to the public internet (to reach
attacker-controlled dropper infrastructure) and whose firewall/route table has
**no path** to the honeypot's own logging/storage/management network. The
fetcher writes its output (quarantined files + JSON sidecars) to a
write-only-from-its-side drop location; it never needs read access to
anything the session-handling side owns.

## Verifying these guarantees

Run the full test suite, including the static-analysis check:

```
pytest
```

`tests/test_no_dangerous_calls.py` is the regression guard for guarantee #1
and will fail the build (not just warn) if a disallowed call is introduced
anywhere under `honeypot/`.
