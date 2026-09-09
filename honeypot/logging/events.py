"""Structured JSON event logging and raw session transcripts (spec sec 4.5/4.6).

Deliberately simple for v1: one append-only JSONL file for structured events,
one JSONL transcript file per session for raw traffic. No attacker-controlled
value is ever used as a format string or template -- every field below is
serialized through json.dumps, which treats it strictly as data.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any, TextIO


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"


class EventLogger:
    """Appends one JSON object per line to a shared structured event log.

    Event types (spec 4.5): session.connect, session.closed, login.success,
    login.failed, command.input, file.download, file.execution_attempt.
    """

    def __init__(self, log_dir: str | Path, filename: str = "events.jsonl") -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.log_dir / filename
        self._lock = threading.Lock()

    def log(self, event_type: str, **fields: Any) -> None:
        record = {"timestamp": _now(), "event": event_type, **fields}
        line = json.dumps(record, default=str) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    # Convenience wrappers for the event types spec 4.5/4.6 requires.
    def session_connect(self, session_id: str, src_ip: str, src_port: int,
                         dst_port: int, protocol: str, client_id: str | None = None) -> None:
        self.log("session.connect", session_id=session_id, src_ip=src_ip,
                  src_port=src_port, dst_port=dst_port, protocol=protocol,
                  client_id=client_id)

    def session_closed(self, session_id: str, duration_seconds: float, reason: str) -> None:
        self.log("session.closed", session_id=session_id,
                  duration_seconds=duration_seconds, reason=reason)

    def login_attempt(self, session_id: str, username: str, password: str,
                       accepted: bool, src_ip: str) -> None:
        self.log("login.success" if accepted else "login.failed",
                  session_id=session_id, username=username, password=password,
                  src_ip=src_ip)

    def command_input(self, session_id: str, raw: str, command: str, args: list[str]) -> None:
        self.log("command.input", session_id=session_id, raw=raw,
                  command=command, args=args)

    def file_download(self, session_id: str, **metadata: Any) -> None:
        self.log("file.download", session_id=session_id, **metadata)

    def execution_attempt(self, session_id: str, raw: str, target: str) -> None:
        self.log("file.execution_attempt", session_id=session_id, raw=raw, target=target)


class TranscriptWriter:
    """Per-session raw transcript: one JSONL file of timestamped I/O events.

    Simpler than a ttyrec-compatible format (spec 4.5 explicitly allows this
    for v1 if replay tooling isn't a priority); still enough to fully
    reconstruct what was sent and received, in order, with timing.
    """

    def __init__(self, transcript_dir: str | Path, session_id: str) -> None:
        self.dir = Path(transcript_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / f"{session_id}.jsonl"
        self._fh: TextIO = self.path.open("a", encoding="utf-8")

    def record(self, direction: str, data: bytes) -> None:
        assert direction in ("recv", "send")
        entry = {
            "timestamp": _now(),
            "direction": direction,
            "data_b64": base64.b64encode(data).decode("ascii"),
        }
        self._fh.write(json.dumps(entry) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()
