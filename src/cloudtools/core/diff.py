"""Diff against the previous run (R8.3): every finding is new, unchanged, regressed or
resolved. Ids are deterministic (R6.1), so matching is exact."""
from __future__ import annotations

from .model import SEVERITIES


def apply(report: dict, previous: dict | None) -> dict:
    """Mark report findings in place; add `resolved` (findings gone since `previous`).
    Returns the baseline description written into the report."""
    if not previous:
        for f in report["findings"] + report["accepted"]:
            f["diff"] = "new"
        report["resolved"] = report["not_rechecked"] = []
        return {"baseline": None}
    prev = {f["id"]: f for f in previous.get("findings", [])}
    prev_accepted = {f["id"] for f in previous.get("accepted", [])}
    prev_resolved = {f["id"] for f in previous.get("resolved", [])}
    for f in report["findings"]:
        p = prev.get(f["id"])
        if p is None:
            f["diff"] = "regressed" if f["id"] in prev_resolved | prev_accepted else "new"
        elif SEVERITIES.index(f["severity"]["base"]) > SEVERITIES.index(p["severity"]["base"]):
            f["diff"] = "regressed"
        else:
            f["diff"] = "unchanged"
    for f in report["accepted"]:
        f["diff"] = "unchanged" if f["id"] in prev_accepted else "new"
    now = {f["id"] for f in report["findings"]} | {f["id"] for f in report["accepted"]}
    # Not checked is not fixed: a missing finding counts as resolved only if its check ran
    # this time, completely (no gap, no error) and with its input (stats.evaluated).
    full = {r["id"] for r in report.get("checks", [])
            if r.get("status") == "ran" and (r.get("stats") or {}).get("evaluated", True)}
    # ...and only if its region was scanned this time. Global resources have no region.
    scanned = set(report.get("run", {}).get("regions") or [])

    def rechecked(p: dict) -> bool:
        region = (p.get("resource") or {}).get("region") or ""
        return p["check_id"] in full and (not region or not scanned or region in scanned)

    gone = [p for fid, p in sorted(prev.items()) if fid not in now]
    report["resolved"] = [{**p, "diff": "resolved"} for p in gone if rechecked(p)]
    report["not_rechecked"] = [{**p, "diff": "not_rechecked"} for p in gone if not rechecked(p)]
    return {"baseline": previous.get("run", {}).get("run_id")}
