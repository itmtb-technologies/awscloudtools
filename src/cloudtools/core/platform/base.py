"""The platform object: the ONLY place one deployment of cloudtools differs from another.

Every capability asks it six things: who is running, which AWS credentials, is this
allowed, where logs go, where outputs are stored, how results are returned. This package
ships the standalone one; a hosted deployment supplies its own (see `current`)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable, Protocol

from ..capability import Manifest


class Refused(PermissionError):
    """authorize() said no. `code` is an upper-case error code (FORBIDDEN, ...)."""

    def __init__(self, message: str, code: str = "FORBIDDEN"):
        super().__init__(message)
        self.code = code


@dataclass
class Principal:
    id: str                         # caller ARN (standalone) or a hosted user id
    tenant: str = ""                # empty standalone; the organization when hosted
    initiator: str = "cli"          # cli | mcp | http | job
    scopes: frozenset = field(default_factory=frozenset)
    correlation_id: str = ""


@dataclass
class CapabilityJob:
    """What `submit` is handed by a front door that returned 202: a capability, its inputs
    and the run id the caller was already given. A closure can't cross a queue, so a hosted
    platform sends the data fields to its worker; standalone just calls it (`run` is the
    in-process body, never serialised). `context` carries platform-only fields (for example
    which connected account a hosted job is for)."""
    capability: str
    inputs: dict
    run_id: str
    tier: int = 0
    initiator: str = "http"
    context: dict = field(default_factory=dict)
    run: Callable[[], object] | None = field(default=None, repr=False, compare=False)

    def __call__(self):
        if self.run is None:
            raise RuntimeError(f"{self.capability}: job {self.run_id} has no in-process body")
        return self.run()

    def to_dict(self) -> dict:
        return {"capability": self.capability, "inputs": dict(self.inputs),
                "run_id": self.run_id, "tier": self.tier, "initiator": self.initiator,
                "context": dict(self.context)}

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilityJob":
        return cls(capability=str(d["capability"]), inputs=dict(d.get("inputs") or {}),
                   run_id=str(d["run_id"]), tier=int(d.get("tier") or 0),
                   initiator=str(d.get("initiator") or "job"),
                   context=dict(d.get("context") or {}))


class Store(Protocol):
    def put(self, key: str, data: bytes, content_type: str = "application/json") -> str: ...
    def get(self, key: str) -> bytes | None: ...
    def list(self, prefix: str) -> list[str]: ...


class Platform(Protocol):
    name: str

    def principal(self) -> Principal: ...
    def aws_env(self, run_id: str, log=None, region: str | None = None): ...
    def authorize(self, manifest: Manifest, confirm: bool = False) -> None: ...
    def log_sinks(self, run_id: str) -> list: ...
    def secret_salt(self) -> str: ...
    def submit(self, job) -> None: ...
    @property
    def store(self) -> Store: ...


def current(**kwargs) -> Platform:
    """Pick the platform from CLOUDTOOLS_PLATFORM: `standalone` (the default), or
    `<module>:<Class>` for a platform supplied by a hosted deployment. That module is
    imported only here and only when named, so a standalone run never loads it."""
    name = os.environ.get("CLOUDTOOLS_PLATFORM", "standalone")
    if name == "standalone":
        from .standalone import StandalonePlatform
        return StandalonePlatform(**kwargs)
    module, sep, cls = name.partition(":")
    if not (sep and module and cls):
        raise ValueError(f"CLOUDTOOLS_PLATFORM must be standalone or <module>:<Class>, not {name!r}")
    import importlib
    return getattr(importlib.import_module(module), cls)(**kwargs)
