# RISC-V Medium-Interaction Honeypot — Build Spec

## 1. Purpose

Build a medium-interaction SSH/Telnet honeypot, written in Python, that impersonates
a RISC-V Linux IoT/embedded device. The goal is to attract and record automated
malware-dropper activity (Mirai-style botnets, IoT worms) that specifically checks
architecture before deploying a payload, and to **safely capture** any binaries
dropped against it — without ever executing them.

This is modeled loosely on Cowrie's architecture (fake shell + session transcript +
structured JSON logging) but purpose-built for RISC-V bait and payload capture, with
execution safety as a hard non-negotiable requirement.

---

## 2. Non-Negotiable Safety Requirements

These constraints override every other design decision in this spec. Claude Code
should treat any violation of these as a bug, even if it makes the honeypot less
convincing.

1. **The honeypot process must never execute, `exec()`, `chmod +x`, `subprocess.run(shell=True)`,
   dlopen, or otherwise run any attacker-supplied binary or script.** All attacker
   "commands" are parsed and *simulated* — none are passed to a real shell or
   interpreter.
2. **Downloaded payloads are fetched by a separate, isolated fetcher component**
   (not the session-handling process), written to a quarantine directory as
   **read-only, non-executable** (`chmod 0440` or stricter), and never touched again
   except for hashing/metadata extraction.
3. **No dynamic code paths accept attacker input as format strings, eval targets, or
   template input.** All attacker text is treated as untrusted data for logging and
   pattern-matching only.
4. **The fetcher's outbound network path must be constrained** (documented, even if
   enforcement is via external firewall/network namespace rather than in-app) — it
   should be assumed to reach attacker-controlled infrastructure, so it must not be
   able to reach the honeypot's own management network or other internal hosts.
5. **File type inspection (e.g. `file`, ELF header parsing) must use a safe, static
   parsing library — never a tool that itself executes or partially loads the sample.**

Include a short `SAFETY.md` in the repo documenting these guarantees and how the code
enforces them, plus a unit/integration test that asserts no `os.system`, `os.exec*`,
`subprocess` call with `shell=True`, or `eval`/`exec` builtin appears anywhere in the
codebase (a simple static grep-based CI check is fine).

---

## 3. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Honeypot Host (isolated VM)                │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐                              │
│  │ SSH Listener │   │Telnet Listener│                              │
│  └──────┬───────┘   └──────┬───────┘                              │
│         └─────────┬────────┘                                      │
│                    ▼                                               │
│           ┌─────────────────┐                                     │
│           │ Session Manager  │  (per-connection state machine)     │
│           └────────┬────────┘                                     │
│                    ▼                                               │
│           ┌─────────────────┐        ┌──────────────────┐         │
│           │ Fake Shell /     │───────▶│ Command Parser    │         │
│           │ Fake Filesystem  │        │ (busybox/IoT cmds)│         │
│           └────────┬────────┘        └─────────┬─────────┘         │
│                    │                            │                   │
│                    ▼                            ▼                   │
│           ┌─────────────────┐        ┌──────────────────┐         │
│           │ Session Logger   │        │ Download Request  │         │
│           │ (transcript+JSON)│        │ Queue              │         │
│           └─────────────────┘        └─────────┬─────────┘         │
└──────────────────────────────────────────────────┼──────────────────┘
                                                     ▼
                                    ┌───────────────────────────────┐
                                    │ Isolated Fetcher Process/Host   │
                                    │ (separate network namespace)    │
                                    │ - fetches URL only               │
                                    │ - hashes, quarantines, read-only │
                                    │ - never executes                 │
                                    └───────────────────────────────┘
```

Recommend running the **fetcher as a physically or network-namespace-separated
component** from the session handler, even if both are Python processes on the same
box during initial development. Document the production deployment as two
containers/VMs with the fetcher having no route back to the honeypot's internal
logging/storage network except a write-only drop location.

---

## 4. Components to Build

### 4.1 Network Listeners
- **SSH server**: implement using `asyncssh` or `paramiko` (asyncssh preferred —
  async, actively maintained). Accept any username/password combo (or a configurable
  allow-list of common IoT default creds: `root:root`, `admin:admin`, `root:12345`,
  `root:xc3511`, etc.) to maximize capture of credential-stuffing attempts.
- **Telnet server**: implement using `asyncio` raw socket handling (Telnet has no
  mature async library equivalent to asyncssh; a lightweight custom implementation is
  fine, following RFC 854 basics — most IoT malware Telnet clients don't negotiate
  much).
- Both listeners feed into the same **Session Manager** abstraction so command
  parsing/logging is shared code, not duplicated per protocol.
- Config-driven **listening ports** (default SSH 22 or 2222, Telnet 23 or 2223 —
  support binding to privileged ports via setcap/systemd rather than running as root).

### 4.2 RISC-V Device Fingerprint / Fake Environment
Build a config-driven fake environment so the device is self-consistent:
- `uname -a` → e.g. `Linux buildroot 5.10.0 #1 SMP PREEMPT riscv64 GNU/Linux`
- `/proc/cpuinfo` → plausible RISC-V fields (`isa: rv64imafdc`, `mmu: sv39`,
  `uarch`, `hart` count)
- `/proc/version`, `/etc/os-release` → embedded Linux (Buildroot/OpenWrt-style)
  banners, since that's the realistic OS for RISC-V IoT boards
- Fake `/bin`, `/usr/bin` directory listing including `busybox` and common
  symlinked applets (`wget`, `tftp`, `chmod`, `cat`, `sh`)
- SSH banner / Telnet login banner impersonating a common RISC-V board
  (e.g. SiFive/StarFive/Allwinner D1-style bootloader or login prompt) — make this
  configurable so you can A/B test different device personas
- **Both 32-bit and 64-bit RISC-V personas should be supported via config**, since
  malware droppers may probe `uname -m` and choose `riscv32` vs `riscv64` payloads
  differently — running a fleet of honeypots split across both personas lets you
  compare what gets dropped for each.

### 4.3 Fake Shell / Command Interpreter
Simulate (never execute) the following command classes, matching what Cowrie
supports plus IoT-botnet-specific commands:
- Filesystem navigation: `cd`, `ls`, `pwd`, `cat`, `echo`, `mkdir`, `rm`, `touch`
- System info: `uname`, `whoami`, `id`, `ps`, `cat /proc/cpuinfo`, `cat /proc/version`,
  `free`, `df`
- **Download commands** (the key ones): `wget`, `curl`, `tftp -g`, `busybox wget`
  — parse the URL/filename argument and hand off to the Download Handler (§4.4)
  rather than doing anything shell-like
- **Execution attempts**: `chmod +x <file>`, `./<file>`, `sh <file>`,
  `/bin/busybox <file>` — these must be **acknowledged with a plausible fake success
  response** (so the attacker's script doesn't error out and abandon the session) but
  must **never actually alter permissions or run anything**. Log these attempts
  explicitly as "execution attempted" events — this is high-value telemetry.
- Unknown/unmatched commands → return a generic `command not found` matching
  BusyBox's ash shell style, and log the raw command string.

### 4.4 Download / Payload Capture Handler
When a `wget`/`curl`/`tftp` command is parsed:
1. Extract URL, method (HTTP/HTTPS/FTP/TFTP), and target filename.
2. Log the full request as a structured event immediately (URL, protocol, requested
   filename, session ID, timestamp) — **even if the fetch later fails**, this alone is
   valuable threat intel (C2/dropper infrastructure).
3. Hand off the URL to the isolated Fetcher component via a queue (file-based queue,
   Redis, or simple local socket — keep it simple for v1, e.g. write a JSON job file
   to a watched directory).
4. Fetcher retrieves the file over the network **from its isolated context**, with:
   - A byte-size cap (configurable, e.g. 50MB) to avoid disk exhaustion attacks
   - A timeout
   - TLS verification disabled tolerantly but logged (malware C2 often uses
     self-signed certs)
5. Fetcher computes SHA256 (and MD5 for cross-referencing with common malware
   databases), runs a **static-only** ELF/ file-type check (e.g. Python's `python-magic`
   or a manual ELF header parser — not the external `file` binary via subprocess if
   avoidable, to minimize subprocess surface, though a sandboxed `file` call is
   acceptable if `shell=False` and no attacker-controlled args reach it directly)
6. Stores it in quarantine as `<sha256>.bin`, permissions `0440`, plus a JSON sidecar
   with metadata: source session ID, source IP, URL, timestamp, size, hashes, detected
   file type, requested filename, detected architecture (32/64-bit RISC-V or other —
   flag mismatches, since a dropper may serve the wrong arch by mistake, which is
   itself interesting).
7. Simulate a plausible download progress / success response back to the fake shell
   session so the attacker's script continues (this is what makes it "medium
   interaction" — real enough to keep the attacker engaged through their full
   playbook).
8. If the fetch fails (timeout, 404, connection refused), log that too and return a
   fake shell error consistent with what BusyBox wget would print.

### 4.5 Session Logging (Cowrie-style transcript)
- Full **raw transcript** of the session: every byte sent and received, timestamped,
  stored per-session (e.g. as a TTY-log format compatible with `ttyrec`/`asciinema`
  playback, or a simpler newline-delimited JSON event stream if replay tooling isn't
  a priority for v1).
- Structured **JSON event log** (one JSON object per line, Cowrie-style) covering:
  - `session.connect` / `session.closed` (with duration)
  - `login.success` / `login.failed` (username, password, source IP/port)
  - `command.input` (raw command string, parsed command name + args)
  - `file.download` (see §4.4 metadata)
  - `file.execution_attempt` (command that tried to run a dropped file)
- Log rotation and a config option for log destination (local file, or optionally
  a syslog/HTTP forwarder for shipping to a SIEM — stub this as a pluggable output,
  don't over-build it for v1).

### 4.6 Standard Attack Data to Capture
Ensure every session records, at minimum:
- Source IP, source port, destination port, protocol (SSH/Telnet)
- Timestamp (connect, each command, disconnect)
- Client identification (SSH client version string / Telnet negotiation options if
  any)
- All credential attempts (username + password pairs, whether "accepted")
- Full command sequence issued during the session, in order, with timestamps
- Every download attempt: URL, protocol, filename, resulting hash(es), file size,
  detected architecture/type
- Every execution attempt on a dropped file
- Session duration and disconnect reason (attacker closed / timeout / honeypot
  closed)
- Optional: GeoIP lookup on source IP (stub with a pluggable interface — use a local
  MaxMind GeoLite2 DB if available, don't require an external API call by default)

### 4.7 Configuration
Single YAML or TOML config file covering:
- Listener ports and enabled protocols
- Device persona (riscv32 vs riscv64, banner text, hostname, `/proc/cpuinfo` values)
- Accepted credentials (list, or "accept anything")
- Fetcher settings: max file size, timeout, quarantine directory path, allowed
  outbound protocols
- Logging: output paths, log level, optional forwarding endpoint

---

## 5. Suggested Tech Stack

| Concern | Recommendation |
|---|---|
| SSH server | `asyncssh` |
| Telnet server | custom `asyncio` protocol |
| Async runtime | `asyncio` throughout, single event loop |
| File type detection | `python-magic` (libmagic bindings) for static inspection |
| Config | `pydantic` + YAML for validated config loading |
| Storage/metadata | flat files + JSON sidecars for v1; note SQLite as a v2 option |
| Logging | Python `logging` with a JSON formatter, or `structlog` |
| Job queue (session → fetcher) | simplest viable: local Unix socket or watched
  directory with JSON job files; avoid adding Redis/Celery unless there's a reason to
  scale later |

---

## 6. Deliverables to Request from Claude Code

1. Repo scaffold with clear separation: `listeners/`, `session/`, `shell/`,
   `fetcher/`, `logging/`, `config/`, `tests/`
2. `SAFETY.md` documenting the non-negotiable constraints from §2 and how they're
   enforced in code
3. A static-analysis test (CI-runnable) that fails the build if any `exec`, `eval`,
   `os.system`, or `shell=True` subprocess call appears in the codebase
4. Working SSH + Telnet listeners with the fake RISC-V persona from §4.2
5. Fake shell supporting the command set in §4.3, with download interception per
   §4.4
6. Isolated fetcher component (can run in-process for v1 but structured so it can be
   split into a separate service/container later) that quarantines files per the
   safety spec
7. JSON structured logging per §4.5/§4.6, plus raw session transcripts
8. Sample config file with two personas (riscv32 and riscv64 device)
9. README covering: how to run it, how to deploy it safely (network isolation
   guidance for the fetcher), and how to review captured samples

---

## 7. Explicitly Out of Scope for This Build

- Automatic detonation/sandboxing of captured binaries (this is a separate,
  higher-risk project — quarantine and hash only, for now)
- Full filesystem emulation deep enough to fool sophisticated interactive attackers
  (medium interaction is the target fidelity, not high interaction)
- GeoIP/threat-intel enrichment beyond a pluggable stub
- Web dashboard/UI (structured JSON logs are the deliverable; visualization can be a
  follow-up project)
