"""The credential tool's capabilities. A view over a stored security run: the IAM access
keys the scan saw, and where any of them was found in a repo. Ids are shown as their
last four characters only; no secret is ever part of a run (R5.1)."""
from __future__ import annotations

import json

from ..core.capability import UNTRUSTED_NOTE, Manifest, capability
from ..security import runner

CRED_READ = "security:credentials:read"


@capability(Manifest(
    id="cred.inventory", title="List AWS access keys and leaks", kind="view", permission=CRED_READ,
    description="The IAM access keys from a stored scan (user, last four characters, status, "
                "age, last use) and, when repos were scanned, which keys were found in which "
                "repo. Never returns a secret. run_id defaults to the latest. " + UNTRUSTED_NOTE,
    input_schema={"type": "object", "additionalProperties": False,
                  "properties": {"run_id": {"type": "string", "maxLength": 64},
                                 "leaked_only": {"type": "boolean"}}}))
def inventory(platform, run_id: str = "latest", leaked_only: bool = False) -> dict:
    rep = runner.load_report(platform.store, run_id)
    rid = rep["run"]["run_id"]
    raw = platform.store.get(f"runs/{rid}/snapshot.json")
    data = json.loads(raw)["data"] if raw else {}
    keys = data.get("iam.access_keys", {}).get("global", [])
    repos = data.get("repo.secrets", {}).get("global")
    leaks = {}
    for f in rep["findings"] + rep.get("accepted", []):
        if f["check_id"] == "cred.inventory":
            leaks[f["qualifiers"]["key"]] = {"finding_id": f["id"], "title": f["title"],
                                             "severity": f["severity"]["contextual"]}
    rows = [{"user": k["user"], "key": f"…{k['hint']}", "status": k["status"],
             "created": k["created"], "last_used": k["last_used"],
             "leak": leaks.get(k["key_fp"])} for k in keys]
    if leaked_only:
        rows = [r for r in rows if r["leak"]]
    return {"run_id": rid, "keys": rows, "total": len(rows),
            "repos_scanned": len(repos["repos"]) if repos else 0,
            "notice": "SENSITIVE: describes credentials of an AWS account."}


@capability(Manifest(
    id="cred.accounts", title="List accounts and stored secrets", kind="view", permission=CRED_READ,
    description="Everyone and everything that can sign in, from a stored scan: IAM users and keys, "
                "Identity Center users, database master users, ElastiCache, MQ and SFTP users, "
                "EC2 key pairs, Cognito pool sizes (never their end users), and secret/parameter "
                "names (never values). source filters by one source, e.g. rds. " + UNTRUSTED_NOTE,
    input_schema={"type": "object", "additionalProperties": False,
                  "properties": {"run_id": {"type": "string", "maxLength": 64},
                                 "source": {"type": "string", "maxLength": 32}}}))
def accounts(platform, run_id: str = "latest", source: str = "") -> dict:
    rep = runner.load_report(platform.store, run_id)
    rid = rep["run"]["run_id"]
    raw = platform.store.get(f"runs/{rid}/snapshot.json")
    data = json.loads(raw)["data"] if raw else {}

    def each(key):
        for region, items in sorted((data.get(key) or {}).items()):
            for it in items or []:
                yield region, it

    rows = []
    for _, k in each("iam.access_keys"):
        rows.append({"source": "iam", "where": "account", "who": k["user"], "kind": "access key",
                     "detail": f"…{k['hint']} {k['status']}", "last_used": k["last_used"]})
    for r, inst in each("identitycenter.users"):
        rows += [{"source": "identitycenter", "where": r, "who": u["user_name"], "kind": "workforce user",
                  "detail": u["display_name"], "last_used": None} for u in inst["users"]]
    for r, d in each("rds.db_users"):
        rows.append({"source": "rds", "where": f"{r}/{d['id']}", "who": d["master_user"],
                     "kind": f"{d['engine']} master user",
                     "detail": "password managed" if d["managed"] else
                               "IAM auth" if d["iam_auth"] else "static password", "last_used": None})
    for r, c in each("redshift.clusters"):
        rows.append({"source": "redshift", "where": f"{r}/{c['id']}", "who": c["master_user"],
                     "kind": "master user", "detail": "password managed" if c["managed"] else "static password",
                     "last_used": None})
    for r, u in each("elasticache.users"):
        rows.append({"source": "elasticache", "where": r, "who": u["user_name"], "kind": f"{u['engine']} user",
                     "detail": f"{u['auth']} · {u['access']}", "last_used": None})
    for r, b in each("mq.users"):
        rows += [{"source": "mq", "where": f"{r}/{b['broker']}", "who": n, "kind": "broker user",
                  "detail": "", "last_used": None} for n in b["users"]]
    for r, s in each("transfer.users"):
        rows += [{"source": "transfer", "where": f"{r}/{s['server']}", "who": u["user_name"],
                  "kind": "SFTP user", "detail": f"{u['ssh_keys']} SSH key(s)", "last_used": None}
                 for u in s["users"]]
    for r, p in each("cognito.pools"):
        rows.append({"source": "cognito", "where": f"{r}/{p['name']}", "who": f"{p['estimated_users']} end users",
                     "kind": "user pool (counted, not listed)", "detail": f"MFA {p['mfa']}", "last_used": None})
    for r, k in each("ec2.key_pairs"):
        rows.append({"source": "ec2", "where": r, "who": k["name"], "kind": "SSH key pair",
                     "detail": k["type"], "last_used": None})
    for r, s in each("secretsmanager.secrets"):
        rows.append({"source": "secretsmanager", "where": r, "who": s["name"], "kind": "secret (name only)",
                     "detail": "rotation on" if s["rotation"] else "rotation off",
                     "last_used": s["last_accessed"]})
    for r, p in each("ssm.parameters"):
        rows.append({"source": "ssm", "where": r, "who": p["name"], "kind": f"parameter {p['type']} (name only)",
                     "detail": p["last_modified_by"], "last_used": None})
    if source:
        rows = [x for x in rows if x["source"] == source]
    by = {}
    for x in rows:
        by[x["source"]] = by.get(x["source"], 0) + 1
    return {"run_id": rid, "total": len(rows), "by_source": by, "rows": rows,
            "not_listable": "OS accounts on hosts, users inside databases and OpenSearch internal "
                            "users need a host command or a database login; not collected.",
            "notice": "SENSITIVE: describes who can access an AWS account."}
