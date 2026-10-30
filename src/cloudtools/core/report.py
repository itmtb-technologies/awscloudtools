"""The report: the stable machine contract every front door returns (JSON, a hosted job
result, agent operations). Frozen 2026-10-27 as REPORT_SCHEMA "1"; the web module and the agent
operations are built against it. A breaking change bumps the version."""
from __future__ import annotations

import hashlib
from collections import Counter

from .model import SEVERITIES, canonical

REPORT_SCHEMA = "1"

_SEV = {"enum": list(SEVERITIES)}
# One finding, closed: a new field is a schema change, made here and in docs/REPORT_SCHEMA.md.
FINDING = {
    "type": "object", "additionalProperties": False,
    "required": ["id", "check_id", "resource", "title", "severity", "confidence", "status",
                 "diff", "evidence", "gaps", "on_paths", "remediation"],
    "properties": {
        "id": {"type": "string", "pattern": "^fd-[0-9a-f]{16}$"},
        "check_id": {"type": "string"},
        "resource": {"type": "object", "required": ["id"]},
        "title": {"type": "string"},
        "severity": {"type": "object", "required": ["base", "contextual"],
                     "properties": {"base": _SEV, "contextual": _SEV}},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "status": {"enum": ["open", "resolved", "accepted"]},
        "accepted_reason": {"type": "string"},
        "diff": {"enum": ["new", "unchanged", "regressed", "resolved", "not_rechecked"]},
        "evidence": {"type": "array", "items": {"type": "object", "required": ["source"]}},
        "gaps": {"type": "array"},
        "on_paths": {"type": "array", "items": {"type": "string"}},
        "remediation": {"type": "object", "required": ["summary"]},
        "qualifiers": {"type": "object"},
        "references": {"type": "array"},
        "cve": {"oneOf": [{"type": "null"}, {
            "type": "object", "additionalProperties": False,
            "required": ["id", "package", "installed_version", "fixed_version", "cvss", "source"],
            "properties": {"id": {"type": "string", "pattern": "^[A-Z][A-Z0-9]*-[A-Za-z0-9.:_-]+$"},
                           "package": {"type": "string"},
                           "installed_version": {"type": "string"},
                           "fixed_version": {"type": ["string", "null"]},
                           "cvss": {"type": ["number", "null"], "minimum": 0, "maximum": 10},
                           "source": {"enum": ["inspector", "osv", "ssm-patch", "ecr"]},
                           # several CVEs in one package (cve.inspector): every id, `id` the worst
                           "ids": {"type": "array", "minItems": 2,
                                   "items": {"type": "string",
                                             "pattern": "^[A-Z][A-Z0-9]*-[A-Za-z0-9.:_-]+$"}}}}]},
        "secret": {"oneOf": [{"type": "null"}, {
            "type": "object", "additionalProperties": False,
            "required": ["detector", "fingerprint", "preview", "location"],
            "properties": {"detector": {"type": "string"},
                           # R5.1: a salted fingerprint only; a raw value cannot validate
                           "fingerprint": {"type": "string", "pattern": "^sha256:[0-9a-f]{12}$"},
                           "preview": {"type": "string", "maxLength": 12},
                           "location": {"type": "string"}}}]},
    },
}

# The report: required keys are what consumers may rely on; findings are closed (FINDING).
SCHEMA = {
    "type": "object",
    "required": ["schema_version", "tool", "run", "summary", "findings", "accepted",
                 "gaps", "facts", "nodes", "paths", "chokepoints", "checks"],
    "properties": {
        "schema_version": {"const": REPORT_SCHEMA},
        "tool": {"type": "string"},
        "run": {"type": "object", "required": [
            "run_id", "tool_version", "started_at", "ended_at", "platform", "initiator",
            "caller", "account", "regions", "profile", "config_hash", "max_tier"]},
        "summary": {"type": "object", "required": [
            "by_severity", "open", "accepted", "gaps", "diff", "highest_new"]},
        "findings": {"type": "array", "items": FINDING},
        "accepted": {"type": "array", "items": FINDING},
        "gaps": {"type": "array", "items": {"type": "object",
                                            "required": ["check_id", "what", "why", "needs"]}},
        "facts": {"type": "array", "items": {"type": "object", "required": [
            "id", "from", "type", "to", "status", "confidence", "evidence", "emitted_by"]}},
        "nodes": {"type": "array"},
        "paths": {"type": "array"},
        "chokepoints": {"type": "array"},
        "checks": {"type": "array", "items": {"type": "object", "required": [
            "id", "status", "findings", "gaps", "duration_ms"]}},
    },
}


def config_hash(resolved_config: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(resolved_config).encode()).hexdigest()[:16]


def summarize(findings: list[dict], accepted: list[dict], gaps: list[dict]) -> dict:
    sev = Counter(f["severity"]["contextual"] for f in findings)
    diff = Counter(f.get("diff") or "new" for f in findings)
    new_or_regressed = [f["severity"]["contextual"] for f in findings
                        if f.get("diff") in ("new", "regressed", "", None)]
    highest = max(new_or_regressed, key=SEVERITIES.index) if new_or_regressed else None
    return {"by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
            "open": len(findings), "accepted": len(accepted), "gaps": len(gaps),
            "diff": {k: diff.get(k, 0) for k in ("new", "unchanged", "regressed", "resolved")},
            "highest_new": highest}


# R2.3: exit codes reflect the highest NEW severity, so CI can fail a build.
EXIT_CODES = {None: 0, "info": 0, "low": 0, "medium": 2, "high": 3, "critical": 4}


def exit_code(summary: dict, fail_on: str = "high") -> int:
    h = summary.get("highest_new")
    if h is None or SEVERITIES.index(h) < SEVERITIES.index(fail_on):
        return 0
    return EXIT_CODES[h]


def validate(report: dict) -> list[str]:
    import jsonschema
    v = jsonschema.Draft202012Validator(SCHEMA)
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in v.iter_errors(report)]
