"""Collectors and the snapshot (requirements §Architecture, R3.1/R3.6/R3.8/R3.9).

A collector is the ONLY code that calls AWS. It runs at most once per run, per region
(or once per account for a global service), and returns plain JSON-able data. Checks
read the snapshot and never call AWS, so they are deterministic and re-runnable on an
old snapshot.

AccessDenied or an error in one collector becomes a recorded miss (later a Gap), never
an aborted run: ported from aws-cost-sentinel `finops/collect.py` `_guard`.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from botocore.exceptions import ClientError

from .aws import AwsEnv, UndeclaredRead, WriteRefused, is_access_denied

GLOBAL = "global"


@dataclass(frozen=True)
class CollectorSpec:
    key: str                         # "ec2.security_groups"
    fn: Callable[[AwsEnv, str], object]
    scope: str                       # regional | global
    actions: tuple                   # IAM actions it needs
    early: bool = False              # slow async input; start first (R3.9)


COLLECTORS: dict[str, CollectorSpec] = {}


def collector(key: str, actions: list[str], scope: str = "regional", early: bool = False):
    if scope not in ("regional", GLOBAL):
        raise ValueError("scope must be regional or global")

    def deco(fn):
        COLLECTORS[key] = CollectorSpec(key, fn, scope, tuple(actions), early)
        return fn
    return deco


@dataclass
class Miss:
    key: str
    region: str
    why: str                         # "AccessDenied" | error code
    denied: bool
    needs: tuple = ()


@dataclass
class Snapshot:
    account: str
    regions: list[str]
    data: dict = field(default_factory=dict)        # key -> {region|global: payload}
    misses: list[Miss] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def get(self, key: str, region: str = GLOBAL, default=None):
        return self.data.get(key, {}).get(region, default)

    def regions_of(self, key: str) -> dict:
        """{region: payload} for one collector; empty if never collected."""
        return dict(self.data.get(key, {}))

    def missed(self, key: str) -> list[Miss]:
        return [m for m in self.misses if m.key == key]

    def to_json(self) -> str:
        return json.dumps({"account": self.account, "regions": self.regions,
                           "data": self.data, "meta": self.meta,
                           "misses": [m.__dict__ | {"needs": list(m.needs)}
                                      for m in self.misses]},
                          sort_keys=True, default=str)

    @classmethod
    def from_json(cls, text: str) -> "Snapshot":
        d = json.loads(text)
        return cls(account=d["account"], regions=d["regions"], data=d["data"],
                   meta=d.get("meta", {}),
                   misses=[Miss(**{**m, "needs": tuple(m.get("needs", ()))})
                           for m in d.get("misses", [])])


def _run_one(env: AwsEnv, spec: CollectorSpec, region: str):
    try:
        return spec.fn(env, region), None
    except UndeclaredRead as e:                # refused, and a bug: one gap, not a dead scan
        return None, Miss(spec.key, region, f"UndeclaredRead {e.operation}: a cloudtools bug, "
                          "please report it", False, spec.actions)
    except WriteRefused:
        raise                                  # a write: a bug, never swallowed
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Error")
        return None, Miss(spec.key, region, code, is_access_denied(e), spec.actions)
    except Exception as e:                     # R-reliability: one failure is a gap
        return None, Miss(spec.key, region, type(e).__name__, False, spec.actions)


def collect(env: AwsEnv, keys: list[str], regions: list[str], account: str,
            workers: int = 8, log=None) -> Snapshot:
    unknown = [k for k in keys if k not in COLLECTORS]
    if unknown:
        raise KeyError(f"no collector registered for {unknown}")
    specs = sorted({COLLECTORS[k] for k in keys}, key=lambda s: (not s.early, s.key))
    tasks = []
    for s in specs:
        tasks += [(s, GLOBAL)] if s.scope == GLOBAL else [(s, r) for r in regions]
    snap = Snapshot(account=account, regions=list(regions))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [(s, r, pool.submit(_run_one, env, s, r)) for s, r in tasks]
        for s, r, fut in futures:
            payload, miss = fut.result()
            if miss:
                snap.misses.append(miss)
                if log:
                    log.emit("collect.miss", collector=s.key, region=r, why=miss.why)
            else:
                snap.data.setdefault(s.key, {})[r] = payload
    return snap
