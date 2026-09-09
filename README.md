# RISC-V Medium-Interaction Honeypot

A medium-interaction SSH/Telnet honeypot that impersonates a RISC-V Linux
IoT/embedded device, built to attract and record Mirai-style malware-dropper
activity and safely capture any binaries dropped against it -- **without
ever executing them**. See `riscv-honeypot-spec.md` for the full design spec
this implementation follows, and `SAFETY.md` for the non-negotiable safety
guarantees and how the code enforces them.

## Installation

Requires Python 3.11+ (the codebase uses `X | Y` union type hints and
`asyncio.TaskGroup`, both 3.11+). No system packages are needed -- unlike the
spec's suggestion of `python-magic`/libmagic, this implementation uses a
hand-rolled static ELF parser (`honeypot/fetcher/elf.py`) specifically to
avoid a native-library dependency.

```
git clone <this repo>            # or just cd into it if already local
cd risc-v_honeypot
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'          # editable install + asyncssh/aiohttp/pydantic/pyyaml + pytest
```

Omit `[dev]` (`pip install -e .`) for a runtime-only install with no test
dependencies -- useful on a deployment host that will only ever run
`honeypot.main` or `honeypot.fetcher.worker`, never `pytest`.

Verify the install:

```
pytest -q
```

All tests should pass, including `tests/test_no_dangerous_calls.py` (see
"Test" below). If `pip install` fails building `cryptography` (an `asyncssh`
dependency) on an unusual platform, that's the one component that may need a
system C toolchain / OpenSSL headers; every other dependency ships prebuilt
wheels.

## Running

```
python -m honeypot.main configs/riscv64.yaml
```

or `configs/riscv32.yaml` for the 32-bit persona. This runs in the
foreground and logs startup ("SSH listener on ...", "Telnet listener on
...") to stderr; stop it with Ctrl-C (or `kill` the process/`systemctl stop`
if you've wrapped it in a unit -- there's no separate daemonization step in
the codebase itself, so use your process supervisor of choice for
backgrounding/restart-on-crash).

By default this binds SSH on `2222` and Telnet on `2223` on all interfaces
(`listeners.bind_host: 0.0.0.0` in the config). To use the standard `22`/`23`
without running as root, either:

- grant the interpreter the capability once: `sudo setcap
  'cap_net_bind_service=+ep' "$(readlink -f .venv/bin/python3)"`, then set
  `ssh_port: 22` / `telnet_port: 23` in the config, or
- front it with a systemd socket unit / port-forwarding rule instead of
  changing the app's bind ports at all.

Any username/password is accepted by default (`credentials.accept_any: true`
in the config) to maximize capture of credential-stuffing attempts; set it to
`false` and populate `allow_list` to restrict to specific default IoT creds.

While it's running, everything lands under `var/`: `var/logs/events.jsonl`
(structured events), `var/transcripts/<session_id>.jsonl` (raw per-session
I/O), and `var/quarantine/` (captured samples + JSON sidecars) -- see
"Structured logs" and "Reviewing captured samples" below. Confirm it's
actually listening with `ss -ltnp | grep -E ':(2222|2223)'` (or your
configured ports).

Running both riscv32 and riscv64 personas side by side (two config files,
two sets of ports, or two hosts) lets you compare what droppers serve to
each architecture. For running the fetcher as a separate, network-isolated
process instead of in-process, see "Deploying safely" below.

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
where the fetcher runs and which fetch `mode` the config uses. With
`fetcher.mode: inline` (the default in `configs/riscv64.yaml`/`riscv32.yaml`),
`honeypot/session/manager.py` awaits the fetch in-process -- fine for a single
isolated VM used only for experimentation, but the session process itself
performs the outbound request in that mode. For anything facing real attacker
traffic, switch to `fetcher.mode: queued` (see `configs/riscv64-docker.yaml`/
`riscv32-docker.yaml` for a working example) and:

1. Run the session-handling process (this repo's `honeypot.main`) on an
   isolated VM/container with no sensitive network access at all -- assume it
   will be fully compromised in spirit (it accepts arbitrary input by design).
2. Run the fetcher as a **separate process**, via
   `python -m honeypot.fetcher.worker configs/riscv64-docker.yaml`, on a host
   or in a network namespace whose only permitted egress is the public
   internet (to reach attacker-controlled dropper infrastructure) and which
   has **no route back** to the honeypot's management/logging/storage
   network. It only needs write access to the shared `fetcher.jobs_dir` /
   `fetcher.quarantine_dir` locations.
3. Never expose `var/quarantine/` to anything that opens files for execution.
   Quarantined samples are written `chmod 0440` specifically so that even a
   misconfigured tool can't accidentally run them.
4. Treat every file under `var/quarantine/` as live malware. Reviewing a
   sample should never mean running it (see "Reviewing captured samples"
   below).

### Deploying with Docker Compose

`docker-compose.yml` implements the two-process split above as two
containers that share **no Docker network** -- the only channel between them
is the bind-mounted `./var/jobs` directory, so there is no IP path from the
fetcher container (which reaches attacker-controlled infrastructure by
design) back to the honeypot container. This has been built and
live-tested: a real login → `wget` → quarantine round trip through the
`honeypot` container, with the actual fetch happening only inside the
`fetcher` container, and a direct connection attempt from the `honeypot`
container to the `fetcher` container's IP confirmed to time out.

```
mkdir -p var/jobs var/quarantine var/logs var/transcripts
sudo chown -R 10001:10001 var       # both containers run as fixed UID 10001
docker compose up -d
docker compose logs -f              # both services' stdout/stderr
```

This uses `configs/riscv64-docker.yaml` (edit `docker-compose.yml`'s two
`command:` lines to switch to `riscv32-docker.yaml`). Privileged ports work
directly through Docker's `ports:` mapping (e.g. change `"2222:2222"` to
`"22:2222"`) -- no `setcap` needed in this deployment path. See the comments
at the top of `docker-compose.yml` for the full rationale, and harden the
`egress` network's actual internet access at your host firewall per point 2
above -- Docker's network separation here stops the fetcher from reaching
the honeypot container, but a host firewall is still the right place to
constrain what the fetcher's egress network can reach on your real network.

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
configs/      sample riscv64/riscv32 persona configs, plus -docker variants (fetcher.mode: queued)
tests/        pytest suite, including the static-analysis safety check
Dockerfile, docker-compose.yml, .dockerignore   two-container deployment (see "Deploying with Docker Compose")
```

`listeners/`, `session/`, `shell/`, `fetcher/`, `logging/`, and `config/` are
nested under a top-level `honeypot` package (rather than living at repo root
as the spec's directory sketch shows) specifically so that
`honeypot/logging/` never risks shadowing the standard library `logging`
module that several files in this codebase import.
