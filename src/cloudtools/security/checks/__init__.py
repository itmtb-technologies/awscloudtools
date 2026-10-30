"""Check registry (requirements §Check contract).

A check is a pure function over a Snapshot: `fn(ctx) -> CheckResult`. Its spec is the
manifest the CLI, `doctor`, the policy generator and the agent tools read. Checks never
call AWS (R3.2); every unreadable input becomes a Gap (R3.4, R8.1).
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Callable

from ...core.collect import COLLECTORS, GLOBAL, Snapshot
from ...core.model import (SEVERITIES, CheckResult, Evidence, Fact, Finding, Gap,
                           apply_accepted_risk)

CATEGORIES = ("network", "server", "identity", "secrets", "vulnerability", "data",
              "logging")


@dataclass(frozen=True)
class CheckSpec:
    id: str                              # net.open-admin-ports
    title: str
    category: str
    default_severity: str
    collectors: tuple                    # collector keys it reads
    tier: int = 0
    mvp: bool = True
    config: dict = field(default_factory=dict)       # defaults; profile may override
    references: tuple = ()
    covers: str = ""                     # R5.5
    does_not_cover: str = ""
    false_positives: str = ""

    def required_actions(self) -> list[str]:
        acts: set[str] = set()
        for k in self.collectors:
            acts |= set(COLLECTORS[k].actions) if k in COLLECTORS else set()
        return sorted(acts)


@dataclass
class CheckCtx:
    snapshot: Snapshot
    spec: CheckSpec
    config: dict
    crown_jewels: dict = field(default_factory=dict)

    @property
    def account(self) -> str:
        return self.snapshot.account

    @property
    def now(self):
        """The snapshot's collection time, never the wall clock: ages computed from it
        keep checks deterministic when an old snapshot is re-evaluated (R3.2)."""
        from datetime import datetime, timezone
        ts = self.snapshot.meta.get("collected_at")
        return (datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts
                else datetime.now(timezone.utc))

    def per_region(self, key: str) -> dict:
        return self.snapshot.regions_of(key)

    def glob(self, key: str, default=None):
        return self.snapshot.get(key, GLOBAL, default)

    def finding(self, resource: dict, title: str, evidence: list, remediation: dict,
                severity: str | None = None, qualifiers: dict | None = None,
                tags: dict | None = None, confidence: float = 1.0, cve: dict | None = None,
                secret: dict | None = None) -> Finding:
        """One finding, with the account filled in, the profile's severity override
        applied and the accepted-risk tag honoured (R8.2)."""
        resource = {"account": self.account, **resource}
        sev = self.config.get("_severity_override") or severity or self.spec.default_severity
        f = Finding(self.spec.id, resource, title, sev,
                    [e if isinstance(e, Evidence) else Evidence(*e) for e in evidence],
                    remediation, qualifiers or {}, confidence,
                    list(self.spec.references), cve=cve, secret=secret)
        return apply_accepted_risk(f, tags)

    def fact(self, src: str, type_: str, dst: str, evidence: list, qualifiers=None,
             conditions=(), confidence: float = 1.0) -> Fact:
        return Fact(src, type_, dst, self.spec.id,
                    [e if isinstance(e, Evidence) else Evidence(*e) for e in evidence],
                    qualifiers or {}, "possible" if conditions else "confirmed",
                    confidence, list(conditions))

    def gap(self, what: str, why: str, needs: list, region: str = "") -> Gap:
        """A per-item gap (one bucket's policy unreadable), beside the per-collector ones."""
        return Gap(self.spec.id, what, why, list(needs), region)

    def gaps(self) -> list[Gap]:
        """Every miss on a collector this check reads becomes a gap for this check."""
        out = []
        for key in self.spec.collectors:
            for m in self.snapshot.missed(key):
                out.append(Gap(self.spec.id, f"{key} in {m.region}",
                               ("access denied" if m.denied else "error") + f" ({m.why})",
                               list(m.needs), "" if m.region == GLOBAL else m.region))
        return out


@dataclass
class Check:
    spec: CheckSpec
    fn: Callable[[CheckCtx], CheckResult]


CHECKS: dict[str, Check] = {}


def check(spec: CheckSpec):
    if spec.category not in CATEGORIES:
        raise ValueError(f"{spec.id}: unknown category {spec.category}")
    if spec.default_severity not in SEVERITIES:
        raise ValueError(f"{spec.id}: unknown severity {spec.default_severity}")

    def deco(fn):
        if spec.id in CHECKS:
            raise ValueError(f"{spec.id}: registered twice")
        CHECKS[spec.id] = Check(spec, fn)
        return fn
    return deco


def select(include=("*",), exclude=(), max_tier: int = 0, mvp_only: bool = False) -> list[Check]:
    out = []
    for cid in sorted(CHECKS):
        c = CHECKS[cid]
        if c.spec.tier > max_tier or (mvp_only and not c.spec.mvp):
            continue
        if not any(fnmatch.fnmatch(cid, p) for p in include):
            continue
        if any(fnmatch.fnmatch(cid, p) for p in exclude):
            continue
        out.append(c)
    return out


def load_all() -> None:
    from . import network, server, identity, data, logging, extra, vuln  # noqa: F401 (registers)
    from ...creds import checks, checks_config, collectors  # noqa: F401 (credential checks join the scan)
