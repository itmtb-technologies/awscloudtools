"""Score a scan of the scanner lab against its ground truth (tests/lab/expected.yaml).

    python tools/lab_score.py --report reports/lab/runs/<id>/report.json \
        --outputs reports/lab/outputs.json [--context reports/lab/lab-context.json]

`outputs.json` is the stack's outputs as {OutputKey: value} (up.sh writes it).
Exit 0 only when every in-tier required finding is present and no twin has a finding.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _matches(resource: dict, value: str) -> bool:
    rid, name = str(resource.get("id", "")), str(resource.get("name", ""))
    return value in (rid, name) or rid.endswith((":" + value, "/" + value))


def owner(resource: dict, outputs: dict) -> str | None:
    """The output key of the lab resource a finding is about, or None."""
    for key, value in outputs.items():
        if value and _matches(resource, value):
            return key
    return None


def referenced(expected: dict) -> set[str]:
    """Every output key expected.yaml names."""
    keys = set(expected.get("twins", [])) | set(expected.get("allowed_on_twins", {}))
    for req in expected.get("required", []):
        keys.update(req["resource"] if isinstance(req["resource"], list) else [req["resource"]])
    return keys


def score(report: dict, outputs: dict, expected: dict, context: dict | None = None) -> dict:
    context = context or {}
    max_tier = int(report.get("run", {}).get("max_tier") or 0)
    by_owner: dict[str, list[dict]] = {}
    outside = 0
    for f in report.get("findings", []):
        if f.get("status") == "resolved":
            continue
        key = owner(f["resource"], outputs)
        if key is None:
            outside += 1
        else:
            by_owner.setdefault(key, []).append(f)

    found, missed, skipped, used = [], [], [], set()
    for req in expected.get("required", []):
        keys = req["resource"] if isinstance(req["resource"], list) else [req["resource"]]
        label = f"{req['check']} on {'/'.join(keys)}"
        if int(req.get("tier", 0)) > max_tier:
            skipped.append(f"{label} (tier {req['tier']} > scan tier {max_tier})")
            continue
        if req.get("unless") and context.get(req["unless"]):
            skipped.append(f"{label} (account has {req['unless']})")
            continue
        hits = [f for k in keys for f in by_owner.get(k, []) if f["check_id"] == req["check"]]
        (found if hits else missed).append(label)
        used.update(f["id"] for f in hits)

    allowed = expected.get("allowed_on_twins", {})
    false_hits, extra = [], []
    for key, fs in sorted(by_owner.items()):
        for f in fs:
            if f["id"] in used:
                continue
            line = f"{f['check_id']} on {key}"
            if key in expected.get("twins", []):
                if f["check_id"] not in allowed.get(key, []):
                    false_hits.append(line)
            else:
                extra.append(line)

    scored = len(found) + len(missed)
    return {
        "scan_tier": max_tier,
        "recall": f"{len(found)}/{scored}",
        "found": found, "missed": missed, "skipped": skipped,
        "false_hits": false_hits, "extra_for_review": sorted(set(extra)),
        "outside_lab": outside,
        "missing_outputs": sorted(referenced(expected) - set(outputs)),
        "pass": not missed and not false_hits and scored > 0,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", required=True)
    ap.add_argument("--outputs", required=True)
    ap.add_argument("--context")
    ap.add_argument("--expected", default=str(ROOT / "tests/lab/expected.yaml"))
    a = ap.parse_args(argv)
    read = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
    result = score(read(a.report), read(a.outputs),
                   yaml.safe_load(Path(a.expected).read_text(encoding="utf-8")),
                   read(a.context) if a.context else None)
    print(json.dumps(result, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
