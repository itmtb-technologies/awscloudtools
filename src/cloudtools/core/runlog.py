"""The run log: structured JSON lines recording who ran what with which settings and
every AWS call made (requirements §Logging). A redaction filter runs on every line as a
safety net (R10.1); request and response bodies are never passed in."""
from __future__ import annotations

import json
import os
import threading
import re
import sys
import time
from datetime import datetime, timezone
from typing import Callable, Iterable

# Shapes that must never reach a log, whatever a caller passes by mistake.
_PATTERNS = [
    (re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b"), r"\1****"),
    (re.compile(r"(?i)(aws_secret_access_key|secret|password|passwd|token|api[_-]?key)"
                r"(\"?\s*[:=]\s*\"?)[^\s\",}]+"), r"\1\2****"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[private key redacted]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "[jwt redacted]"),
]


def redact(text: str) -> str:
    for pat, repl in _PATTERNS:
        text = pat.sub(repl, text)
    return text


Sink = Callable[[dict], None]


def file_sink(path) -> Sink:
    def write(event: dict) -> None:
        # 0600 like every other output (CT-20): the log names the caller and every call.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(redact(json.dumps(event, default=str)) + "\n")
    return write


def stderr_sink(event: dict) -> None:
    sys.stderr.write(redact(json.dumps(event, default=str)) + "\n")


class RunLog:
    def __init__(self, run_id: str, sinks: Iterable[Sink] = (), level: str = "info"):
        self.run_id = run_id
        self.sinks = list(sinks)
        self.level = level
        self.events: list[dict] = []        # kept for the report and tests
        self._lock = threading.Lock()

    def emit(self, event: str, **fields) -> dict:
        rec = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
               "event": event, "run_id": self.run_id, **fields}
        # Round-trip through the filter so what is kept equals what is written.
        rec = json.loads(redact(json.dumps(rec, default=str)))
        with self._lock:              # collectors emit from a pool; Windows appends aren't atomic
            self.events.append(rec)
            for s in self.sinks:
                s(rec)
        return rec


class Timer:
    def __enter__(self):
        self.t0 = time.monotonic()
        return self

    def __exit__(self, *a):
        self.ms = int((time.monotonic() - self.t0) * 1000)
