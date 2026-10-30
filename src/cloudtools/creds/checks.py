"""Credential checks (ported from credscan; requirements §Secrets).

`cred.inventory` joins the two halves credscan kept in separate databases: an AWS key id
found in a repo, and the same id live in IAM. A match makes the leak an entry point in
the attack graph: `leaked_credential --authenticates_as--> iam_user`.

That edge is `possible`, never confirmed. gitleaks' AWS rule matches the key *id*; the
secret half is assumed to sit next to it, which is how keys leak, but was not seen.

Repos are only scanned when the caller names them (`--repo`), so with no
`repo.secrets` input these checks report nothing rather than a gap: nothing was asked.
"""
from __future__ import annotations

from ..core.model import CheckResult, Gap, Node
from ..security.checks import CheckSpec, check

REPO_KEY = "repo.secrets"
KEY_ONLY = "only the key id was matched; the secret is assumed to have leaked with it"


def report_leaked_key(ctx, res: CheckResult, k: dict, fp: str, places: list[str], ev: list,
                      attrs: dict, cleanup: str, conditions=(KEY_ONLY,), confidence: float = 0.8,
                      secret: dict | None = None) -> None:
    """One AWS key id found somewhere it shouldn't be (`places`) that matches IAM key `k`.
    Active: a high finding on the user, a `leaked_credential` entry point and a possible
    `authenticates_as` edge to the user. Inactive: low, no edge. Shared by the repo scan
    (`cred.inventory`) and tier 1 (`sec.leaked-aws-key`); the node id `leak:<fp>` is the
    same for both, so one key leaked twice is one entry point."""
    where = ", ".join(places)
    ev = list(ev) + [("iam:ListAccessKeys", k["user_arn"], f"key …{k['hint']} {k['status']}")]
    user = {"id": k["user_arn"], "name": k["user"], "type": "iam_user"}
    if k["status"] != "Active":
        res.findings.append(ctx.finding(
            user, f"Inactive key …{k['hint']} of {k['user']} is in {where}", ev,
            {"summary": "Delete the inactive key; it can be re-activated by anyone with IAM write."},
            severity="low", qualifiers={"key": fp}, secret=secret))
        return
    leak = f"leak:{fp}"
    res.nodes.append(Node(leak, "leaked_credential", ctx.account, "",
                          f"key …{k['hint']} in {where}", labels=["entry_point"], attrs=attrs))
    res.facts.append(ctx.fact(leak, "authenticates_as", k["user_arn"], ev, {"key": fp},
                              list(conditions), confidence))
    res.findings.append(ctx.finding(
        user, f"Active key …{k['hint']} of {k['user']} is in {where}", ev,
        {"summary": f"Deactivate and replace the key now, then {cleanup}.",
         "cli": f"aws iam update-access-key --user-name {k['user']} --access-key-id <id ending "
                f"{k['hint']}> --status Inactive"},
        qualifiers={"key": fp}, secret=secret))


def _repos(ctx) -> dict | None:
    return ctx.glob(REPO_KEY)


@check(CheckSpec(
    "cred.inventory", "Leaked AWS access key still exists in IAM", "secrets", "high",
    ("iam.access_keys",),
    covers="AWS access key ids found by gitleaks in the repos given with --repo (history "
           "and working tree), matched to this account's IAM keys.",
    does_not_cover="Keys of other accounts (counted, not reported); secrets outside the "
                   "given repos; whether the secret half really leaked.",
    false_positives="A key id committed without its secret. Still rotate: you can't prove "
                    "the secret never travelled with it."))
def inventory(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    repos = _repos(ctx)
    keys = ctx.glob("iam.access_keys")
    if repos is None or keys is None:
        res.stats = {"repos_scanned": 0, "evaluated": False}   # not asked: not a pass either
        return res
    by_fp = {k["key_fp"]: k for k in keys}
    seen: dict[str, dict] = {}
    other = 0
    for repo in repos["repos"]:
        for s in repo["secrets"]:
            if s["kind"] != "aws_access_key_id":
                continue
            k = by_fp.get(s["fingerprint"])
            if not k:
                other += 1
                continue
            hit = seen.setdefault(s["fingerprint"], {"key": k, "where": []})
            hit["where"] += [(repo["repo"], loc, s["in_worktree"]) for loc in s["locations"]]
    for fp, hit in sorted(seen.items()):
        k, where = hit["key"], hit["where"]
        ev = [("gitleaks", f"{r}:{loc}", f"key id …{k['hint']}") for r, loc, _ in where[:5]]
        report_leaked_key(ctx, res, k, fp, sorted({w[0] for w in where}), ev,
                          {"in_worktree": any(w[2] for w in where)},
                          "remove it from the repo history (deleting the file is not enough)")
    res.stats = {"repos_scanned": len(repos["repos"]), "matched": len(seen), "other_accounts": other}
    return res


@check(CheckSpec(
    "cred.repo-secrets", "Secrets committed to a repository", "secrets", "medium", (),
    covers="Every gitleaks hit in the repos given with --repo, one finding per repo; "
           "fingerprints and locations only.",
    does_not_cover="Whether each secret is still valid. CI secret stores, images, "
                   "Terraform state.",
    false_positives="Test fixtures and example values: accept the risk per repo."))
def repo_secrets(ctx) -> CheckResult:
    res = CheckResult()
    repos = _repos(ctx)
    if repos is None:
        res.stats = {"evaluated": False}
        return res
    res.gaps += [Gap("cred.repo-secrets", f"repo {e['path']}", e["why"]) for e in repos["errors"]]
    for repo in repos["repos"]:
        found = [s for s in repo["secrets"] if s["kind"] != "aws_access_key_id"]
        if not found:
            continue
        live = sum(s["in_worktree"] for s in found)
        ev = [(s["rule"], f"{repo['repo']}:{s['locations'][0]}", s["fingerprint"]) for s in found[:10]]
        res.findings.append(ctx.finding(
            {"id": f"repo:{repo['path']}", "name": repo["repo"], "type": "repository"},
            f"{len(found)} secret{'s' if len(found) != 1 else ''} in {repo['repo']} "
            f"({live} in the working tree)", ev,
            {"summary": "Rotate each secret at its issuer, then remove it from history. Rotation "
                        "is the fix; deleting the line is not."},
            severity="medium" if live else "low"))
    return res


# ------------------------------------------------- who has access, beyond IAM
ACCOUNT_SOURCES = ("iam.access_keys", "identitycenter.users", "rds.db_users", "redshift.clusters",
                   "elasticache.users", "mq.users", "transfer.users", "cognito.pools",
                   "ec2.key_pairs", "secretsmanager.secrets", "ssm.parameters")


def _when(s):
    from datetime import datetime
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


@check(CheckSpec(
    "cred.accounts", "Accounts and stored secrets, everywhere AWS can list them", "secrets",
    "info", ACCOUNT_SOURCES,
    covers="Inventory only, no findings: IAM keys, Identity Center users, database master "
           "users, ElastiCache, MQ and SFTP users, EC2 key pairs, Cognito pool sizes, and "
           "secret/parameter names. Read with the cred.accounts view.",
    does_not_cover="OS accounts on hosts, users created inside a database, OpenSearch "
                   "internal users (need a host command or a database login). Cognito end "
                   "users are counted, never listed."))
def accounts(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    count = lambda key, f=len: sum(f(v) for v in ctx.per_region(key).values())  # noqa: E731
    res.stats = {
        "identity_center_users": count("identitycenter.users", lambda v: sum(len(i["users"]) for i in v)),
        "database_master_users": count("rds.db_users") + count("redshift.clusters"),
        "elasticache_users": count("elasticache.users"),
        "mq_users": count("mq.users", lambda v: sum(len(b["users"]) for b in v)),
        "sftp_users": count("transfer.users", lambda v: sum(len(s["users"]) for s in v)),
        "cognito_end_users": count("cognito.pools", lambda v: sum(p["estimated_users"] for p in v)),
        "ec2_key_pairs": count("ec2.key_pairs"),
        "secrets": count("secretsmanager.secrets"), "parameters": count("ssm.parameters"),
    }
    return res


@check(CheckSpec(
    "cred.secret-not-rotated", "Stored secret never rotated", "secrets", "medium",
    ("secretsmanager.secrets",), config={"max_days": 180},
    covers="Secrets Manager secrets with rotation off whose value last changed more than "
           "max_days ago (or never). From names and dates; the value is never read.",
    false_positives="Secrets that a person rotates by hand on a schedule: accept by tag."))
def secret_not_rotated(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    max_days = int(ctx.config.get("max_days", 180))
    for region, items in ctx.per_region("secretsmanager.secrets").items():
        for s in items:
            if s["rotation"] or s.get("owning_service"):   # service-owned secrets rotate themselves
                continue
            changed = _when(s["last_changed"]) or _when(s["created"])
            age = (ctx.now - changed).days if changed else None
            if age is not None and age <= max_days:
                continue
            res.findings.append(ctx.finding(
                {"id": s["arn"], "name": s["name"], "region": region, "type": "secret"},
                f"Secret {s['name']} has not changed in {age} days and rotation is off"
                if age is not None else f"Secret {s['name']} has rotation off",
                [("secretsmanager:ListSecrets", s["arn"],
                  f"RotationEnabled=false, LastChangedDate={s['last_changed']}")],
                {"summary": "Turn on rotation, or rotate it now and record who owns it."},
                tags=s.get("tags")))
    return res


@check(CheckSpec(
    "cred.db-static-master-password", "Database master password nobody rotates", "secrets",
    "low", ("rds.db_users", "redshift.clusters"),
    covers="RDS/Aurora/DocumentDB/Neptune and Redshift whose master password is not managed "
           "by Secrets Manager (RDS: also no IAM database login).",
    false_positives="A password rotated by your own tooling: accept by tag."))
def db_static_master(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, dbs in ctx.per_region("rds.db_users").items():
        for d in dbs:
            if d["managed"] or d["iam_auth"]:
                continue
            res.findings.append(ctx.finding(
                {"id": d["arn"] or d["id"], "name": d["id"], "region": region, "type": f"rds_{d['kind']}"},
                f"{d['id']} master user {d['master_user']!r} has a static password",
                [(f"rds:DescribeDB{'Clusters' if d['kind'] == 'cluster' else 'Instances'}",
                  d["arn"] or d["id"], "no MasterUserSecret, IAM auth off")],
                {"summary": "Let Secrets Manager manage the master password "
                            "(--manage-master-user-password), or enable IAM database auth."},
                tags=d.get("tags")))
    for region, cs in ctx.per_region("redshift.clusters").items():
        for c in cs:
            if c["managed"]:
                continue
            res.findings.append(ctx.finding(
                {"id": c["id"], "name": c["id"], "region": region, "type": "redshift_cluster"},
                f"Redshift {c['id']} master user {c['master_user']!r} has a static password",
                [("redshift:DescribeClusters", c["id"], "no MasterPasswordSecretArn")],
                {"summary": "Let Secrets Manager manage the admin password (--manage-master-password)."}))
    return res
