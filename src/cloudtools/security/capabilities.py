"""The security tool's capabilities: one manifest each, the single source for the CLI,
the HTTP routes and an agent declaration. Every function takes
the platform object first, then the manifest's inputs."""
from __future__ import annotations

import json

from ..core.capability import UNTRUSTED_NOTE, Manifest, capability
from ..core.model import SEVERITIES
from . import doctor as doctor_mod
from . import graph, profiles, runner, scan

S = lambda n: {"type": "string", "maxLength": n}  # noqa: E731
I = lambda lo, hi: {"type": "integer", "minimum": lo, "maximum": hi}  # noqa: E731


def _obj(**props):
    return {"type": "object", "properties": props, "additionalProperties": False}


RUN_ID = S(64)
READ, SCAN = "security:read", "security:scan"
# Tier 0 only: a role or policy built from `required_aws_actions` must never grant the
# tier-1 content reads (lambda:GetFunction, ...). Those are optional, for an opt-in tier.
ACTIONS = tuple(sorted({a for c in scan.CHECKS.values() if c.spec.tier == 0
                        for a in c.spec.required_actions()}))
TIER_ACTIONS = tuple(sorted({a for c in scan.CHECKS.values() if c.spec.tier > 0
                             for a in c.spec.required_actions()} - set(ACTIONS)))


def _regions(csv: str | None) -> list[str] | None:
    return [r.strip() for r in csv.split(",") if r.strip()] if csv else None


def _with_tier(prof: dict, tier: int) -> dict:
    """`--tier N` / the `tier` input: opt in to tier-N checks for this run (tier 1 reads
    configuration content). 0 keeps the profile's own tier."""
    if tier not in (0, 1, 2):
        raise ValueError("tier must be 0, 1 or 2")
    return {**prof, "max_tier": tier} if tier else prof


def _brief(report: dict) -> dict:
    return {"run_id": report["run"]["run_id"], "account": report["run"]["account"],
            "regions": report["run"]["regions"], "summary": report["summary"],
            "paths": len(report["paths"]), "top_fixes": [c["headline"] + ": " + c["fix"]
                                                          for c in report["chokepoints"][:5]],
            "outputs": report["run"].get("outputs", {}), "exit_code": report["run"].get("exit_code")}


@capability(Manifest(
    id="security.scan", title="Run a security scan", kind="job", permission=SCAN,
    description="Scan the AWS account read-only with a profile (quick, full or ci) and store a "
                "report with findings, attack paths and fixes. Returns the run id and a summary; "
                "read details with the list/explain tools. " + UNTRUSTED_NOTE,
    input_schema=_obj(profile=S(16), regions=S(512), wait={"type": "boolean"}, tier=I(0, 2)),
    required_aws_actions=ACTIONS, optional_aws_actions=TIER_ACTIONS))
def scan_cap(platform, profile: str = "quick", regions: str = "", wait: bool = True,
             tier: int = 0, full: bool = False, repos: list[str] | None = None) -> dict:
    # `repos` is a CLI-only argument (local paths), deliberately not in the input schema,
    # so no agent or hosted caller can point the scanner at a disk.
    prof = _with_tier(profiles.load(profile), tier)
    if not wait:                         # R11.4: return now, poll security.get_run_status
        rid = scan.new_run_id()
        runner.set_status(platform.store, rid, state="queued", profile=prof.get("profile"))
        platform.submit(lambda: runner.run_scan(platform, prof, _regions(regions), run_id=rid,
                                                repos=repos))
        return {"run_id": rid, "state": "queued", "poll": "security.get_run_status"}
    report = runner.run_scan(platform, prof, _regions(regions), repos=repos)
    return report if full else _brief(report)


@capability(Manifest(
    id="security.get_run_status", title="Status of a scan", kind="view", permission=READ,
    description="State of a scan started with wait=false: queued, running (with its stage), "
                "succeeded (with the summary) or failed (with the error). Poll this, then read "
                "results with the list/explain tools.",
    input_schema=_obj(run_id=RUN_ID)))
def get_run_status(platform, run_id: str) -> dict:
    raw = platform.store.get(runner.status_key(run_id))
    if not raw:
        raise LookupError(f"no scan with run id {run_id}")
    return json.loads(raw)


@capability(Manifest(
    id="security.run_check", title="Run one security check", kind="job", permission=SCAN,
    description="Run a single check by id (for example net.open-admin-ports) and store its "
                "report. Useful after fixing something. " + UNTRUSTED_NOTE,
    input_schema=_obj(check_id=S(64), regions=S(512)), required_aws_actions=ACTIONS))
def run_check(platform, check_id: str, regions: str = "", full: bool = False, tier: int = 0) -> dict:
    # `tier` is CLI-only (`security run --tier`); the manifest is unchanged.
    if check_id not in scan.CHECKS:
        raise KeyError(f"unknown check {check_id!r}; see security.list_checks")
    prof = {**_with_tier(profiles.load("full"), tier), "include": [check_id],
            "profile": f"check:{check_id}", "baseline": "none"}
    report = runner.run_scan(platform, prof, _regions(regions))
    return report if full else _brief(report)


@capability(Manifest(
    id="security.evaluate", title="Re-evaluate a saved snapshot", kind="job", permission=READ,
    agent_visible=False, hosted=False,
    description="Re-run the checks on a saved snapshot file with no AWS calls at all (R3.6). "
                "Standalone only: it takes a local file path.",
    input_schema=_obj(snapshot=S(1024), profile=S(16))))
def evaluate(platform, snapshot: str, profile: str = "quick", full: bool = False) -> dict:
    from pathlib import Path
    prof = {**profiles.load(profile), "baseline": "none"}
    report = runner.run_scan(platform, prof, snapshot_text=Path(snapshot).read_text(encoding="utf-8"))
    return report if full else _brief(report)


@capability(Manifest(
    id="security.list_findings", title="List security findings", kind="view", permission=READ,
    description="Findings from a stored scan, filtered and paged. run_id defaults to the latest. "
                "min_severity is info, low, medium, high or critical; diff is new, unchanged or "
                "regressed. " + UNTRUSTED_NOTE,
    input_schema=_obj(run_id=RUN_ID, min_severity=S(8), check_prefix=S(64), diff=S(16),
                      region=S(32), page=I(1, 1000), page_size=I(1, 100))))
def list_findings(platform, run_id: str = "latest", min_severity: str = "info",
                  check_prefix: str = "", diff: str = "", region: str = "",
                  page: int = 1, page_size: int = 25) -> dict:
    rep = runner.load_report(platform.store, run_id)
    lo = SEVERITIES.index(min_severity) if min_severity in SEVERITIES else 0
    rows = [f for f in rep["findings"]
            if SEVERITIES.index(f["severity"]["contextual"]) >= lo
            and f["check_id"].startswith(check_prefix)
            and (not diff or f.get("diff") == diff)
            and (not region or f["resource"].get("region") == region)]
    start = (page - 1) * page_size
    return {"run_id": rep["run"]["run_id"], "total": len(rows), "page": page,
            "findings": [{k: f[k] for k in ("id", "check_id", "title", "severity", "diff",
                                             "resource", "on_paths")}
                         for f in rows[start:start + page_size]],
            "notice": UNTRUSTED_NOTE}


@capability(Manifest(
    id="security.explain_finding", title="Explain one finding", kind="view", permission=READ,
    description="Evidence, gaps, attack paths and the fix for one finding id from a stored "
                "scan. " + UNTRUSTED_NOTE,
    input_schema=_obj(run_id=RUN_ID, finding_id=S(64))))
def explain_finding(platform, finding_id: str, run_id: str = "latest") -> dict:
    rep = runner.load_report(platform.store, run_id)
    f = next((x for x in rep["findings"] + rep["accepted"] if x["id"] == finding_id), None)
    if f is None:
        raise KeyError(f"no finding {finding_id} in run {rep['run']['run_id']}")
    paths = [p for p in rep["paths"] if p["id"] in f.get("on_paths", [])]
    return {"finding": f, "paths": [{"id": p["id"], "summary": p["summary"],
                                     "steps": [s["text"] for s in p["steps"]]} for p in paths],
            "gaps": [g for g in rep["gaps"] if g["check_id"] == f["check_id"]],
            "notice": UNTRUSTED_NOTE}


@capability(Manifest(
    id="security.list_paths", title="List attack paths", kind="view", permission=READ,
    description="Attack paths from entry points (the internet, outside accounts) to crown "
                "jewels (admin, sensitive data), each narrated step by step with its evidence. "
                "Narration describes exposure, not exploitation. " + UNTRUSTED_NOTE,
    input_schema=_obj(run_id=RUN_ID, target=S(256), page=I(1, 1000), page_size=I(1, 50))))
def list_paths(platform, run_id: str = "latest", target: str = "", page: int = 1,
               page_size: int = 10) -> dict:
    rep = runner.load_report(platform.store, run_id)
    rows = [p for p in rep["paths"] if not target or p["target"] == target]
    start = (page - 1) * page_size
    return {"run_id": rep["run"]["run_id"], "total": len(rows),
            "paths": rows[start:start + page_size], "notice": UNTRUSTED_NOTE}


def _graph_rows(rep: dict, sources, targets, page: int, page_size: int) -> dict:
    nodes = {n["id"]: n for n in rep["nodes"]}
    prof = rep["run"].get("profile_resolved") or {}
    rows = graph.find_paths(rep["facts"], nodes, prof, sources=sources, targets=targets)
    start = (page - 1) * page_size
    return {"run_id": rep["run"]["run_id"], "total": len(rows),
            "paths": rows[start:start + page_size], "notice": UNTRUSTED_NOTE}


@capability(Manifest(
    id="security.find_paths", title="Paths between two points", kind="view", permission=READ,
    description="Attack paths that end at target (a resource id or ARN, or admin_equivalent), "
                "optionally only those starting at entry (internet, a resource id, or a leaked "
                "key id). Computed from a stored scan; no AWS calls. " + UNTRUSTED_NOTE,
    input_schema=_obj(run_id=RUN_ID, entry=S(512), target=S(512), page=I(1, 1000),
                      page_size=I(1, 50))))
def find_paths(platform, target: str, entry: str = "", run_id: str = "latest", page: int = 1,
               page_size: int = 10) -> dict:
    rep = runner.load_report(platform.store, run_id)
    return _graph_rows(rep, {entry} if entry else None, {target}, page, page_size)


@capability(Manifest(
    id="security.why_reachable", title="Why a resource is reachable", kind="view",
    permission=READ,
    description="Every attack path from any entry point (the internet, outside accounts, "
                "leaked keys) to one resource, with each step's evidence. " + UNTRUSTED_NOTE,
    input_schema=_obj(run_id=RUN_ID, resource=S(512), page=I(1, 1000), page_size=I(1, 50))))
def why_reachable(platform, resource: str, run_id: str = "latest", page: int = 1,
                  page_size: int = 10) -> dict:
    rep = runner.load_report(platform.store, run_id)
    return _graph_rows(rep, None, {resource}, page, page_size)


@capability(Manifest(
    id="security.chokepoints", title="Fixes that break the most paths", kind="view",
    permission=READ,
    description="The fixes ranked by how many attack paths each one breaks, with the "
                "findings each fix resolves. " + UNTRUSTED_NOTE,
    input_schema=_obj(run_id=RUN_ID, top=I(1, 25))))
def chokepoints(platform, run_id: str = "latest", top: int = 10) -> dict:
    rep = runner.load_report(platform.store, run_id)
    return {"run_id": rep["run"]["run_id"], "paths": len(rep["paths"]),
            "chokepoints": rep["chokepoints"][:top]}


@capability(Manifest(
    id="security.what_if", title="Paths removed by a fix", kind="view", permission=READ,
    description="Recompute attack paths as if the given findings (comma-separated ids) were "
                "fixed, and list the paths that disappear. Changes nothing in AWS.",
    input_schema=_obj(run_id=RUN_ID, finding_ids=S(512))))
def what_if(platform, finding_ids: str, run_id: str = "latest") -> dict:
    rep = runner.load_report(platform.store, run_id)
    prof = rep["run"].get("profile_resolved") or {}
    return graph.what_if(rep, prof, fix_findings=_regions(finding_ids))


@capability(Manifest(
    id="security.list_checks", title="List the security checks", kind="view", permission=READ,
    description="The check catalogue: id, category, tier, default severity, what each check "
                "covers and does not, known false positives and the AWS actions it needs.",
    input_schema=_obj(category=S(32))))
def list_checks(platform, category: str = "") -> dict:
    return {"checks": [c for c in scan.check_catalogue() if not category or c["category"] == category]}


@capability(Manifest(
    id="security.doctor", title="Check scanner permissions", kind="job", permission=READ,
    hosted=False,
    description="Probe what the current AWS identity can read (one cheap call per collector "
                "and region, no writes) and show each check as runnable, partial or blocked, "
                "with the easiest ways to get missing access.",
    input_schema=_obj(profile=S(16), regions=S(512))))
def doctor(platform, profile: str = "quick", regions: str = "") -> dict:
    env = platform.aws_env("doctor")
    rs = _regions(regions) or env.enabled_regions()
    return doctor_mod.run(env, rs, profiles.load(profile))


@capability(Manifest(
    id="security.generate_policy", title="Generate the scanner IAM policy", kind="view",
    permission=READ, hosted=False,
    description="The least-privilege IAM policy for the selected profile's checks, with "
                "explicit denies on data reads (S3 objects, secrets, parameters, KMS decrypt).",
    input_schema=_obj(profile=S(16))))
def generate_policy(platform, profile: str = "quick", tier: int = 0) -> dict:
    # `tier` is CLI-only (`security policy --tier`); the manifest is unchanged.
    return doctor_mod.generate_policy(_with_tier(profiles.load(profile), tier))
