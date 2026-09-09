# RISC-V Medium-Interaction Honeypot

A medium-interaction SSH/Telnet honeypot that impersonates a RISC-V Linux
IoT/embedded device, built to attract and record Mirai-style malware-dropper
activity and safely capture any binaries dropped against it -- **without
ever executing them**. See `riscv-honeypot-spec.md` for the full design spec
this implementation follows, and `SAFETY.md` for the non-negotiable safety
guarantees and how the code enforces them.

## Install

```
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Run

```
python -m honeypot.main configs/riscv64.yaml
```

or `configs/riscv32.yaml` for the 32-bit persona. By default this binds SSH
on `2222` and Telnet on `2223` (edit the config to change ports, or bind
privileged ports `22`/`23` via `setcap`/systemd rather than running as root).
Any username/password is accepted by default (`credentials.accept_any: true`
in the config) to maximize capture of credential-stuffing attempts; set it to
`false` and populate `allow_list` to restrict to specific default IoT creds.

Running both riscv32 and riscv64 personas side by side (two config files,
two sets of ports, or two hosts) lets you compare what droppers serve to
each architecture.

## Test

```
pytest
```

`tests/test_no_dangerous_calls.py` is the CI-runnable static-analysis check
required by the spec: it fails the build if `os.system`, any `os.exec*`, a
`subprocess` call with `shell=True`, or the `eval`/`exec` builtins appear
anywhere under `honeypot/`.

## Deploying safely

**Read `SAFETY.md` first.** The single most important deployment decision is
where the fetcher runs. For v1/development, `honeypot/session/manager.py`
awaits the fetch in-process, which is fine on a single isolated VM used only
for experimentation. For anything facing real attacker traffic:

1. Run the session-handling process (this repo's `honeypot.main`) on an
   isolated VM/container with no sensitive network access at all -- assume it
   will be fully compromised in spirit (it accepts arbitrary input by design).
2. Run the fetcher as a **separate process**, via
   `python -m honeypot.fetcher.worker configs/riscv64.yaml`, on a host or in a
   network namespace whose only permitted egress is the public internet (to
   reach attacker-controlled dropper infrastructure) and which has **no route
   back** to the honeypot's management/logging/storage network. It only needs
   write access to the shared `fetcher.jobs_dir` / `fetcher.quarantine_dir`
   locations.
3. Never expose `var/quarantine/` to anything that opens files for execution.
   Quarantined samples are written `chmod 0440` specifically so that even a
   misconfigured tool can't accidentally run them.
4. Treat every file under `var/quarantine/` as live malware. Reviewing a
   sample should never mean running it (see "Reviewing captured samples"
   below).

## Reviewing captured samples

Each quarantined file `var/quarantine/<sha256>.bin` has a JSON sidecar
`var/quarantine/<sha256>.json` with: source session ID, source IP, requested
URL, protocol, timestamp, size, SHA256 + MD5, detected file type
(`honeypot/fetcher/elf.py` does the static detection -- ELF class/machine/
endianness or a magic-byte guess for non-ELF files), and, when the sample is
an ELF RISC-V binary, whether its bitness matched the persona that received
it (`arch_mismatch`) -- a dropper serving the wrong arch is itself signal
worth investigating.

To look at what was captured without ever executing it:

- Hash lookup: take the `sha256`/`md5` field from the sidecar to VirusTotal /
  MalwareBazaar / any-run, etc.
- Static disassembly only: tools like `objdump -d`, Ghidra, or IDA in
  "load, don't run" mode are fine; anything that maps the sample into a
  running process (a real `file` invocation that could follow symlinks
  strangely, an antivirus "quick scan" that lightly executes heuristics,
  a sandbox detonator) belongs in a separate, deliberately-provisioned
  detonation environment -- not this repo, and explicitly out of scope for
  this build (see spec sec 7).
- The raw session transcript at `var/transcripts/<session_id>.jsonl` (one
  JSON object per line: `timestamp`, `direction` (`recv`/`send`), `data_b64`)
  shows exactly what the attacker typed and received around the download, in
  order, for correlating the dropper's full playbook with the sample it left
  behind.

## Structured logs

`var/logs/events.jsonl` (one JSON object per line) covers `session.connect`,
`session.closed`, `login.success`/`login.failed`, `command.input`,
`file.download` (a `"requested"` event logged immediately, even before the
fetch completes, plus a follow-up `"success"`/`"failed"` event with the
outcome), and `file.execution_attempt`. Ship this to a SIEM by tailing the
file, or extend `honeypot/logging/events.py` with a forwarding sink -- the
spec deliberately keeps this pluggable rather than building a forwarder for
v1.

## Repository layout

```
honeypot/
  config/     pydantic schema + YAML loader for personas/listeners/fetcher/logging
  listeners/  SSH (asyncssh) and Telnet (custom asyncio protocol) listeners
  session/    SessionManager: the shared state machine both listeners feed into
  shell/      persona rendering, fake in-memory filesystem, command dispatcher
  fetcher/    isolated fetch+hash+quarantine logic, static ELF detector, job queue
  logging/    JSON event log + raw per-session transcripts
configs/      sample riscv64 and riscv32 persona configs
tests/        pytest suite, including the static-analysis safety check
```

`listeners/`, `session/`, `shell/`, `fetcher/`, `logging/`, and `config/` are
nested under a top-level `honeypot` package (rather than living at repo root
as the spec's directory sketch shows) specifically so that
`honeypot/logging/` never risks shadowing the standard library `logging`
module that several files in this codebase import.
