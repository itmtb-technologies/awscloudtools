"""One scan, end to end, through the platform object: identical in every
deployment except for what the platform answers. Every run writes a run log, the
snapshot and the report under one run_id (R10.5), and diffs against the previous run
in the same store (R8.3)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .. import __version__
from ..core import diff, publish
from ..core.collect import Snapshot
from ..core.report import config_hash, exit_code, summarize
from ..core.collect import GLOBAL
from ..core.model import Gap
from ..core.platform.base import Principal, Refused
from ..core.runlog import RunLog
from . import graph, scan

LATEST = "runs/latest-security.json"
REPOS_KEY = "repo.secrets"


def _scan_repos(platform, repos: list[str], log) -> dict:
    """Local repos are a standalone input only: a hosted worker has no user disk to read."""
    if platform.name != "standalone":
        raise Refused("repository scanning runs only in the standalone variant", "NOT_HOSTED")
    from ..creds.repo_secrets import scan_repos
    out = getattr(platform, "output", "")
    exclude = [out] if out and not out.startswith("s3://") else []
    return scan_repos(repos, platform.secret_salt(), log, exclude=exclude)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _previous(store) -> dict | None:
    ptr = store.get(LATEST)
    if not ptr:
        return None
    raw = store.get(f"runs/{json.loads(ptr)['run_id']}/report.json")
    return json.loads(raw) if raw else None


def status_key(run_id: str) -> str:
    return f"runs/{run_id}/status.json"


def set_status(store, run_id: str, **fields) -> dict:
    """runs/<id>/status.json: queued -> running (with a stage) -> succeeded | failed. What
    `security.get_run_status` reads, so an agent can start a scan and poll (R11.4)."""
    raw = store.get(status_key(run_id))
    st = {**(json.loads(raw) if raw else {"run_id": run_id}), **fields, "updated_at": _now()}
    store.put(status_key(run_id), json.dumps(st, default=str).encode())
    return st


def run_scan(platform, profile: dict, regions: list[str] | None = None,
             snapshot_text: str | None = None, run_id: str | None = None,
             formats: list[str] | None = None, persist: bool = True,
             repos: list[str] | None = None) -> dict:
    run_id = run_id or scan.new_run_id()
    store = platform.store if persist else None
    if store:
        set_status(store, run_id, state="running", stage="starting", started_at=_now())
    try:
        report = _run_scan(platform, profile, regions, snapshot_text, run_id, formats, persist,
                           repos, (lambda s: set_status(store, run_id, stage=s)) if store else None)
    except Exception as e:
        if store:
            set_status(store, run_id, state="failed", ended_at=_now(),
                       error=f"{type(e).__name__}: {str(e)[:300]}")
        raise
    if store:
        set_status(store, run_id, state="succeeded", stage="done", ended_at=report["run"]["ended_at"],
                   summary=report["summary"], exit_code=report["run"]["exit_code"],
                   paths=len(report["paths"]))
    return report


def _run_scan(platform, profile, regions, snapshot_text, run_id, formats, persist, repos,
              stage=None) -> dict:
    stage = stage or (lambda s: None)
    log = RunLog(run_id, platform.log_sinks(run_id))
    started = _now()
    checks = scan.select(profile.get("include", ["*"]), profile.get("exclude", []),
                         profile.get("max_tier", 0), profile.get("mvp_only", False))
    env = None
    if snapshot_text:
        snap = Snapshot.from_json(snapshot_text)        # R3.6: no AWS call at all,
        regions = snap.regions                          # not even sts:GetCallerIdentity
        principal = Principal(id=f"offline (snapshot by {snap.meta.get('caller', 'unknown')})",
                              initiator=getattr(platform, "initiator", "cli"))
    else:
        principal = platform.principal()
        env = platform.aws_env(run_id, log)
        env.max_tier = profile.get("max_tier", 0)      # the guard's tier-1 reads need this
        if env.max_tier:                               # tier-1 hits are salted as collected
            env.secret_salt = platform.secret_salt()
        if not regions:
            want = profile.get("regions", "all-enabled")
            regions = env.enabled_regions() if want == "all-enabled" else list(want)
    log.emit("run.start", tool="security", tool_version=__version__,
             caller=principal.id, tenant=principal.tenant, initiator=principal.initiator,
             regions=regions, profile=profile.get("profile"), config_hash=config_hash(profile),
             max_tier=profile.get("max_tier", 0), checks=len(checks),
             source="snapshot" if snapshot_text else "aws")
    blocked: dict[str, list] = {}
    if env is not None and profile.get("preflight", True):
        # R4.5: a fast doctor pass; a check whose inputs are denied everywhere is skipped
        # and reported as a gap naming the permission, instead of running to an empty result.
        stage("preflight")
        from . import doctor
        d = doctor.run(env, regions, profile)
        blocked = {m["check"]: m["missing_actions"] for m in d["matrix"] if m["status"] == "blocked"}
        log.emit("preflight.done", runnable=d["summary"]["runnable"], partial=d["summary"]["partial"],
                 blocked=sorted(blocked), duration_ms=d["duration_ms"])
        checks = [c for c in checks if c.spec.id not in blocked]
    if env is not None:
        stage("collecting")
        snap = scan.collect_snapshot(env, regions, checks, log=log)
        repos = repos or profile.get("repos") or []
        if repos:
            snap.data[REPOS_KEY] = {GLOBAL: _scan_repos(platform, repos, log)}
    stage("evaluating")
    results, rows = scan.evaluate(snap, profile, log=log, skip=set(blocked))
    report = scan.build_report(snap, results, rows, profile, {
        "run_id": run_id, "tool_version": __version__, "started_at": started, "ended_at": "",
        "platform": platform.name, "initiator": principal.initiator, "caller": principal.id,
        "tenant": principal.tenant, "profile": profile.get("profile")})
    report["gaps"] += [Gap(cid, "the whole check", "blocked: no permission in any region "
                           "(preflight); run `cloudtools security doctor`", sorted(needs)).to_dict()
                       for cid, needs in sorted(blocked.items())]
    stage("analysing")
    stats = graph.analyse(report, profile)
    log.emit("graph.done", **stats)
    previous = _previous(platform.store) if profile.get("baseline", "previous") == "previous" else None
    report["run"].update(diff.apply(report, previous))
    report["summary"] = summarize(report["findings"], report["accepted"], report["gaps"])
    report["summary"]["resolved"] = len(report.get("resolved", []))
    report["summary"]["diff"]["resolved"] = report["summary"]["resolved"]   # kept apart from findings
    report["summary"]["not_rechecked"] = len(report.get("not_rechecked", []))
    report["run"]["ended_at"] = _now()
    code = exit_code(report["summary"], profile.get("fail_on", "high"))
    report["run"]["exit_code"] = code
    outputs = {}
    stage("publishing")
    if persist:
        outputs = write_outputs(platform.store, report, snap,
                                formats or (profile.get("output") or {}).get("formats", ["json", "html"]))
        platform.store.put(LATEST, json.dumps({"run_id": run_id}).encode())
    log.emit("run.end", by_severity=report["summary"]["by_severity"],
             diff=report["summary"]["diff"], resolved=report["summary"]["resolved"],
             gaps=report["summary"]["gaps"], paths=len(report["paths"]),
             outputs=outputs, exit_code=code)
    report["run"]["outputs"] = outputs
    report["run"]["log_events"] = len(log.events)
    return report


def write_outputs(store, report: dict, snap: Snapshot, formats: list[str]) -> dict:
    base = f"runs/{report['run']['run_id']}"
    out = {"snapshot": store.put(f"{base}/snapshot.json", snap.to_json().encode()),
           "json": store.put(f"{base}/report.json", publish.to_json(report))}
    if "html" in formats:
        out["html"] = store.put(f"{base}/report.html", publish.to_html(report), "text/html")
    if "sarif" in formats:
        out["sarif"] = store.put(f"{base}/report.sarif", publish.to_sarif(report, scan.check_catalogue()),
                                 "application/sarif+json")
    if "csv" in formats:
        out["csv"] = store.put(f"{base}/findings.csv", publish.to_csv(report), "text/csv")
    return out


def load_report(store, run_id: str | None = None) -> dict:
    if not run_id or run_id == "latest":
        ptr = store.get(LATEST)
        if not ptr:
            raise LookupError("no previous security scan in this output location")
        run_id = json.loads(ptr)["run_id"]
    raw = store.get(f"runs/{run_id}/report.json")
    if not raw:
        raise LookupError(f"no report for run {run_id}")
    return json.loads(raw)
