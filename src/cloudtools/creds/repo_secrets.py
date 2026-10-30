"""Secrets in local git repos: full history plus the working tree, through gitleaks.

Ported from credscan `collectors/repo_secrets.py` (2026-09-17). Standalone only: it
reads local paths, which a hosted scan has none of.

No secret value is kept (R5.1). gitleaks will only write its report to a file, so the
report goes to a mode-0600 temp file that is parsed and deleted before `_gitleaks`
returns; each value is reduced to a salted fingerprint in memory. The one exception is
an AWS access key id (`AKIA…`): it is an identifier, not a secret, and keeping its
fingerprint under the fixed `KEY_ID_SALT` is what lets `cred.inventory` match it to a
live IAM key.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..core.model import fingerprint

KEY_ID_SALT = "aws-access-key-id:"      # shared with collectors.access_keys; not a secret
MAX_LOCATIONS = 20
TIMEOUT_S = 600


def key_id_fp(key_id: str) -> str:
    return fingerprint(key_id, KEY_ID_SALT)


def _cred_type(rule: str) -> str:
    r = rule.lower()
    for frag, kind in (("private-key", "ssh_key"), ("aws-access", "aws_access_key_id"),
                       ("jwt", "token"), ("oauth", "token"), ("password", "password")):
        if frag in r:
            return kind
    return "api_key"


def _gitleaks(mode: str, path: str) -> list[dict]:
    fd, report = tempfile.mkstemp(suffix=".json")
    try:
        os.close(fd)
        os.chmod(report, 0o600)
        proc = subprocess.run(["gitleaks", mode, "--no-banner", "--log-level", "error",
                               "--report-format", "json", "--report-path", report, path],
                              capture_output=True, text=True, timeout=TIMEOUT_S)
        if proc.returncode not in (0, 1):          # 1 = leaks found, which is the point
            raise RuntimeError(f"gitleaks {mode} rc={proc.returncode}: {proc.stderr[-300:]}")
        text = Path(report).read_text(encoding="utf-8", errors="replace").strip()
        return json.loads(text) if text else []
    finally:
        if os.path.exists(report):
            os.remove(report)


def scan_repo(path: str, salt: str, exclude: tuple = ()) -> dict:
    """One repo -> {repo, path, secrets: [...]}; one entry per (rule, value)."""
    path = os.path.abspath(os.path.expanduser(path))
    agg: dict[tuple, dict] = {}
    for mode in ("git", "dir"):
        for hit in _gitleaks(mode, path):
            value = hit.get("Secret") or hit.get("Match") or ""
            if not value or _excluded(path, hit.get("File", ""), exclude):
                continue
            rule = hit.get("RuleID", "unknown")
            kind = _cred_type(rule)
            is_key_id = kind == "aws_access_key_id"
            fp = key_id_fp(value) if is_key_id else fingerprint(value, salt)
            commit = (hit.get("Commit") or "")[:7]
            loc = f"{hit.get('File', '?')}:{hit.get('StartLine', 0)}" + (f"@{commit}" if commit else "")
            a = agg.setdefault((rule, fp), {
                "rule": rule, "kind": kind, "fingerprint": fp,
                "hint": value[-4:] if is_key_id else "", "locations": set(),
                "in_worktree": False, "first_seen": None})
            a["locations"].add(loc)
            a["in_worktree"] |= mode == "dir"
            d = hit.get("Date") or None
            if d and (a["first_seen"] is None or d < a["first_seen"]):
                a["first_seen"] = d
    out = []
    for key in sorted(agg):
        a = agg[key]
        locs = sorted(a["locations"])          # sort before capping: gitleaks order varies
        out.append({**a, "locations": locs[:MAX_LOCATIONS], "locations_total": len(locs)})
    return {"repo": os.path.basename(path), "path": path, "secrets": out}


def _excluded(repo: str, file: str, exclude) -> bool:
    """The scanner's own output holds what it found; scanning it would report it again."""
    full = os.path.realpath(file if os.path.isabs(file) else os.path.join(repo, file))
    return any(full == e or full.startswith(e + os.sep) for e in exclude)


def scan_repos(paths: list[str], salt: str, log=None, workers: int = 4,
               exclude: list[str] | None = None) -> dict:
    """Several repos; one failing repo is an error entry, never an aborted sweep."""
    if shutil.which("gitleaks") is None:
        return {"repos": [], "errors": [{"path": p, "why": "gitleaks not on PATH"} for p in paths]}
    repos, errors = [], []
    skip = tuple(os.path.realpath(os.path.expanduser(e)) for e in exclude or [])

    def one(p):
        if not os.path.isdir(os.path.join(os.path.expanduser(p), ".git")):
            return None, {"path": p, "why": "not a git repository"}
        try:
            return scan_repo(p, salt, skip), None
        except Exception as e:                  # noqa: BLE001 (fail in its own lane)
            return None, {"path": p, "why": f"{type(e).__name__}: {str(e)[:200]}"}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(one, p): p for p in paths}
        for fut in as_completed(futs):          # log each repo as it finishes, not in order
            p, (res, err) = futs[fut], fut.result()
            if err:
                errors.append(err)
            else:
                repos.append(res)
            if log:
                log.emit("repo.scan", path=p, secrets=len(res["secrets"]) if res else 0,
                         error=err["why"] if err else None)
    return {"repos": sorted(repos, key=lambda r: r["path"]),
            "errors": sorted(errors, key=lambda e: e["path"])}
