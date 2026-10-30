"""The scan pipeline: collect -> evaluate -> correlate -> publish (requirements §Architecture).

`collect_snapshot` is the only stage that calls AWS. `evaluate` is pure over a snapshot
and is what `scanner evaluate --snapshot` re-runs. A failing check or region never fails
the run: it becomes a gap (requirements §Non-functional "Reliability")."""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from .. import __version__
from ..core.collect import Snapshot, collect
from ..core.model import CheckResult, Gap
from ..core.report import REPORT_SCHEMA, config_hash, summarize
from . import collectors, collectors_cve, collectors_extra  # noqa: F401  (registers collectors)
from .checks import CHECKS, CheckCtx, load_all, select

load_all()

QUICK = {"max_tier": 0, "mvp_only": True, "include": ["*"], "exclude": []}


def new_run_id() -> str:
    return "r-" + datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ") + "-" + uuid.uuid4().hex[:6]


def needed_collectors(checks) -> list[str]:
    return sorted({k for c in checks for k in c.spec.collectors})


def collect_snapshot(env, regions: list[str], checks, log=None) -> Snapshot:
    scope = env.resolve_scope()
    t0 = time.monotonic()
    snap = collect(env, needed_collectors(checks), regions, scope.account_id, log=log)
    snap.meta = {"collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "caller": scope.caller_arn, "tool_version": __version__,
                 "collect_ms": int((time.monotonic() - t0) * 1000)}
    return snap


def _check_config(spec, profile: dict) -> dict:
    cfg = dict(spec.config)
    cfg.update((profile.get("settings") or {}).get(spec.id, {}))
    override = (profile.get("severity_overrides") or {}).get(spec.id)
    if override:
        cfg["_severity_override"] = override
    return cfg


def evaluate(snapshot: Snapshot, profile: dict, log=None, skip: set | None = None):
    """Run the selected checks over a snapshot, minus `skip` (blocked by the preflight).
    Returns (results by check id, check rows)."""
    checks = [c for c in select(profile.get("include", ["*"]), profile.get("exclude", []),
                                profile.get("max_tier", 0), profile.get("mvp_only", False))
              if c.spec.id not in (skip or ())]
    out: dict[str, CheckResult] = {}
    rows = []
    for c in checks:
        if log:
            log.emit("check.start", check_id=c.spec.id)
        t0 = time.monotonic()
        try:
            r = c.fn(CheckCtx(snapshot, c.spec, _check_config(c.spec, profile),
                              profile.get("crown_jewels") or {}))
            err = None
        except Exception as e:                      # reliability: a broken check is a gap
            r = CheckResult(gaps=[Gap(c.spec.id, "the whole check", f"check error: {type(e).__name__}: {e}")])
            err = f"{type(e).__name__}: {e}"
        ms = int((time.monotonic() - t0) * 1000)
        out[c.spec.id] = r
        status = "error" if err else ("partial" if r.gaps else "ran")
        rows.append({"id": c.spec.id, "title": c.spec.title, "category": c.spec.category,
                     "status": status, "findings": len(r.findings), "gaps": len(r.gaps),
                     "duration_ms": ms, **({"error": err} if err else {}),
                     **({"stats": r.stats} if r.stats else {})})
        if log:
            log.emit("check.end", check_id=c.spec.id, duration_ms=ms, findings=len(r.findings),
                     gaps=len(r.gaps), error=err)
    return out, rows


def _merge_nodes(results) -> list[dict]:
    nodes: dict[str, dict] = {}
    for r in results.values():
        for n in r.nodes:
            cur = nodes.setdefault(n.id, {**n.__dict__, "labels": list(n.labels), "attrs": dict(n.attrs)})
            cur["labels"] = sorted(set(cur["labels"]) | set(n.labels))
            cur["attrs"].update(n.attrs)
            for k in ("name", "region", "account"):
                cur[k] = cur[k] or getattr(n, k)
    return [nodes[k] for k in sorted(nodes)]


def build_report(snapshot: Snapshot, results: dict, rows: list, profile: dict, run: dict,
                 graph_out: dict | None = None) -> dict:
    findings, accepted, facts, gaps = [], [], {}, []
    for cid in sorted(results):
        r = results[cid]
        for f in r.findings:
            (accepted if f.status == "accepted" else findings).append(f.to_dict())
        for fa in r.facts:
            facts[fa.id] = fa.to_dict()           # same fact from two checks: one edge
        gaps += [g.to_dict() for g in r.gaps]
    for f in findings + accepted:
        f["diff"] = f.get("diff") or "new"
    findings.sort(key=lambda f: (-["info", "low", "medium", "high", "critical"].index(
        f["severity"]["contextual"]), f["check_id"], f["id"]))
    g = graph_out or {"paths": [], "chokepoints": []}
    return {
        "schema_version": REPORT_SCHEMA, "tool": "security",
        "run": {**run, "account": snapshot.account, "regions": snapshot.regions,
                "config_hash": config_hash(profile), "max_tier": profile.get("max_tier", 0),
                "collected_at": snapshot.meta.get("collected_at"),
                "profile_resolved": profile},
        "summary": summarize(findings, accepted, gaps),
        "findings": findings, "accepted": accepted, "gaps": gaps,
        "facts": [facts[k] for k in sorted(facts)], "nodes": _merge_nodes(results),
        "paths": g["paths"], "chokepoints": g["chokepoints"], "checks": rows,
    }


def check_catalogue() -> list[dict]:
    return [{"id": c.spec.id, "title": c.spec.title, "category": c.spec.category,
             "tier": c.spec.tier, "mvp": c.spec.mvp, "default_severity": c.spec.default_severity,
             "collectors": list(c.spec.collectors), "required_actions": c.spec.required_actions(),
             "config": c.spec.config, "references": list(c.spec.references),
             "covers": c.spec.covers, "does_not_cover": c.spec.does_not_cover,
             "false_positives": c.spec.false_positives}
            for c in (CHECKS[k] for k in sorted(CHECKS))]
