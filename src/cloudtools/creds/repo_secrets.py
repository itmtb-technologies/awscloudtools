"""Secrets in local git repos: full history plus the working tree, through gitleaks.

Ported from credscan `collectors/repo_secrets.py` (2026-09-17). Standalone only: it
reads local paths, which a hosted scan has none of.

No secret value is kept (R5.1). gitleaks reports on stdout (`--report-path -`), so no file
ever holds a value (0.1.4 used a temp file, left behind if the process was killed: CT-15);
each value is reduced to a salted fingerprint in memory.

The scanned repo has no say in what is reported (CT-14, review 2026-10-30): gitleaks would
otherwise obey a `.gitleaks.toml`, a `.gitleaksignore` and `gitleaks:allow` comments found
in it, and on 0.1.4 a committed allowlist turned 1 hit into 0. So: gitleaks' own default
rules through `--config`, the ignore path pointed at an empty directory, inline allows
ignored, and history read from a mirror clone (in `git` mode gitleaks reads a
`.gitleaksignore` from the working tree whatever `--gitleaks-ignore-path` says). What the
repo tried to suppress is reported instead (`suppressions`). The one exception is
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
DEFAULT_CONFIG = "[extend]\nuseDefault = true\n"     # gitleaks' rules, nothing from the repo
SUPPRESSION_FILES = (".gitleaks.toml", ".gitleaksignore")
# git run on a repo we didn't make: no fsmonitor command, no hooks.
SAFE_GIT = ("git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null")


def key_id_fp(key_id: str) -> str:
    return fingerprint(key_id, KEY_ID_SALT)


def _cred_type(rule: str) -> str:
    r = rule.lower()
    for frag, kind in (("private-key", "ssh_key"), ("aws-access", "aws_access_key_id"),
                       ("jwt", "token"), ("oauth", "token"), ("password", "password")):
        if frag in r:
            return kind
    return "api_key"


def _gitleaks(mode: str, target: str, work: str) -> list[dict]:
    """One gitleaks pass. `work` holds our config and an empty ignore directory; the report
    comes back on stdout."""
    cfg, empty = os.path.join(work, "gitleaks.toml"), os.path.join(work, "no-ignores")
    if not os.path.exists(cfg):
        Path(cfg).write_text(DEFAULT_CONFIG, encoding="utf-8")
        os.mkdir(empty)
    proc = subprocess.run(["gitleaks", mode, "--no-banner", "--log-level", "error",
                           "--config", cfg, "--gitleaks-ignore-path", empty,
                           "--ignore-gitleaks-allow",
                           "--report-format", "json", "--report-path", "-", target],
                          capture_output=True, text=True, timeout=TIMEOUT_S)
    if proc.returncode not in (0, 1):              # 1 = leaks found, which is the point
        raise RuntimeError(f"gitleaks {mode} rc={proc.returncode}: {proc.stderr[-300:]}")
    text = proc.stdout.strip()
    return json.loads(text) if text else []


def _mirror(path: str, work: str) -> str:
    """Every ref of the repo, with no working tree, in our own directory."""
    dest = os.path.join(work, "mirror.git")
    subprocess.run([*SAFE_GIT, "clone", "--mirror", "--quiet", "--", path, dest],
                   check=True, capture_output=True, text=True, timeout=TIMEOUT_S)
    return dest


def _suppressions(path: str) -> dict:
    files = [f for f in SUPPRESSION_FILES if os.path.exists(os.path.join(path, f))]
    proc = subprocess.run([*SAFE_GIT, "grep", "-I", "-c", "-F", "gitleaks:allow"], cwd=path,
                          capture_output=True, text=True, timeout=TIMEOUT_S)
    allows = sum(int(line.rsplit(":", 1)[1]) for line in proc.stdout.splitlines()
                 if line.rsplit(":", 1)[-1].isdigit())
    return {"files": files, "inline_allows": allows}


def scan_repo(path: str, salt: str, exclude: tuple = ()) -> dict:
    """One repo -> {repo, path, secrets: [...]}; one entry per (rule, value)."""
    path = os.path.abspath(os.path.expanduser(path))
    agg: dict[tuple, dict] = {}
    with tempfile.TemporaryDirectory(prefix="cloudtools-gitleaks-") as work:
        hits = [("git", h) for h in _gitleaks("git", _mirror(path, work), work)]
        hits += [("dir", h) for h in _gitleaks("dir", path, work)]
    for mode, hit in hits:
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
    return {"repo": os.path.basename(path), "path": path, "secrets": out,
            "suppressions": _suppressions(path)}


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
