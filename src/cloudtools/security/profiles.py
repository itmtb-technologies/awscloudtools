"""Run profiles (requirements §Configuration). A profile is YAML validated against a
schema; CLI flags override it; with none, `quick` runs. Each check's settings are
validated against that check's own config keys (R9.2)."""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

from .checks import CHECKS
from ..core.model import SEVERITIES

BUILTIN = {
    "quick": {"profile": "quick", "max_tier": 0, "mvp_only": True, "regions": "all-enabled",
              "include": ["*"], "exclude": [], "graph": {"enabled": True, "max_depth": 6},
              "output": {"formats": ["json", "html"]}, "baseline": "previous",
              "fail_on": "high"},
    "full": {"profile": "full", "max_tier": 0, "mvp_only": False, "regions": "all-enabled",
             "include": ["*"], "exclude": [], "graph": {"enabled": True, "max_depth": 6},
             "output": {"formats": ["json", "html", "sarif", "csv"]}, "baseline": "previous",
             "fail_on": "high"},
    "ci": {"profile": "ci", "max_tier": 0, "mvp_only": True, "regions": "all-enabled",
           "include": ["*"], "exclude": [], "graph": {"enabled": True, "max_depth": 6},
           "output": {"formats": ["json", "sarif"]}, "baseline": "previous", "fail_on": "high"},
}

KEYS = {"profile", "max_tier", "mvp_only", "accounts", "regions", "include", "exclude",
        "checks", "settings", "severity_overrides", "crown_jewels", "graph", "output",
        "baseline", "fail_on", "assume_compromised", "repos", "preflight"}


class ProfileError(ValueError):
    pass


def load(name_or_path: str | None) -> dict:
    if not name_or_path:
        name_or_path = "quick"
    if name_or_path in BUILTIN:
        return copy.deepcopy(BUILTIN[name_or_path])
    p = Path(name_or_path)
    if not p.exists():
        raise ProfileError(f"no built-in profile or file named {name_or_path!r} "
                           f"(built-ins: {', '.join(BUILTIN)})")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    base = copy.deepcopy(BUILTIN["full" if raw.get("mvp_only") is False else "quick"])
    checks = raw.pop("checks", None) or {}
    base.update(raw)
    if checks:
        base["include"] = checks.get("include", base["include"])
        base["exclude"] = checks.get("exclude", base["exclude"])
    base.setdefault("profile", p.stem)
    return validate(base)


def validate(profile: dict) -> dict:
    problems = [f"unknown profile key {k!r}" for k in profile if k not in KEYS]
    if profile.get("max_tier", 0) not in (0, 1, 2, 3):
        problems.append("max_tier must be 0-3")
    if profile.get("fail_on", "high") not in SEVERITIES:
        problems.append(f"fail_on must be one of {SEVERITIES}")
    for cid, s in (profile.get("settings") or {}).items():
        if cid not in CHECKS:
            problems.append(f"settings for unknown check {cid!r}")
            continue
        allowed = set(CHECKS[cid].spec.config)
        for k in s or {}:
            if k not in allowed:
                problems.append(f"{cid}: unknown setting {k!r} (allowed: {sorted(allowed) or 'none'})")
    for cid, sev in (profile.get("severity_overrides") or {}).items():
        if cid not in CHECKS:
            problems.append(f"severity override for unknown check {cid!r}")
        if sev not in SEVERITIES:
            problems.append(f"{cid}: severity {sev!r} is not one of {SEVERITIES}")
    if profile.get("max_tier", 0) > 2:
        problems.append("max_tier 3 (data sampling) is not in this release; tiers 0-2 are")
    if problems:
        raise ProfileError("; ".join(problems))
    return profile
