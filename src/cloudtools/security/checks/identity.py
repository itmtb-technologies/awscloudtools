"""iam.*: identity (requirements check catalogue, MVP).

Effective permissions here are identity policies only (inline, attached managed, group).
Permission boundaries and SCPs are NOT evaluated, so every permission fact is
`possible` with that stated as its condition (R7.1-R7.3). Precise evaluation is the
graph phase's job (PMapper / Access Analyzer, R7.2)."""
from __future__ import annotations

from datetime import datetime

from ...core.model import ADMIN, CheckResult, Node
from ..policy import (NOT_EVALUATED, account_of, allows, is_full_admin, trust_principals)
from . import CheckSpec, check

AUTH = "iam.authorization_details"
CRED = "iam.credential_report"
ADMIN_POLICY_ARNS = {"arn:aws:iam::aws:policy/AdministratorAccess"}

# Known privilege-escalation combinations (Rhino Security Labs catalogue, abridged).
ESCALATIONS = {
    "passrole+ec2": ["iam:PassRole", "ec2:RunInstances"],
    "passrole+lambda": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    "passrole+cloudformation": ["iam:PassRole", "cloudformation:CreateStack"],
    "passrole+glue": ["iam:PassRole", "glue:CreateDevEndpoint"],
    "create-policy-version": ["iam:CreatePolicyVersion"],
    "set-default-policy-version": ["iam:SetDefaultPolicyVersion"],
    "attach-user-policy": ["iam:AttachUserPolicy"],
    "attach-role-policy": ["iam:AttachRolePolicy"],
    "put-user-policy": ["iam:PutUserPolicy"],
    "put-role-policy": ["iam:PutRolePolicy"],
    "create-access-key": ["iam:CreateAccessKey"],
    "update-login-profile": ["iam:UpdateLoginProfile"],
    "update-assume-role-policy": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
    "lambda-update-code": ["lambda:UpdateFunctionCode"],
}


def _date(s: str):
    if not s or s in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _policy_docs(auth: dict, principal: dict, kind: str) -> list[tuple[str, dict]]:
    """(source name, document) for every identity policy reaching a principal."""
    managed = {p["Arn"]: p for p in auth.get("Policies", [])}
    groups = {g["GroupName"]: g for g in auth.get("GroupDetailList", [])}

    def default_doc(arn):
        p = managed.get(arn)
        if not p:
            return None
        for v in p.get("PolicyVersionList", []):
            if v.get("IsDefaultVersion"):
                return v.get("Document")
        return None

    def from_entity(e, inline_key):
        out = [(f"inline:{x['PolicyName']}", x["PolicyDocument"]) for x in e.get(inline_key, [])]
        for a in e.get("AttachedManagedPolicies", []):
            d = default_doc(a["PolicyArn"])
            out.append((a["PolicyArn"], d if d is not None else {"__aws_managed__": a["PolicyArn"]}))
        return out

    inline_key = {"user": "UserPolicyList", "role": "RolePolicyList", "group": "GroupPolicyList"}[kind]
    docs = from_entity(principal, inline_key)
    for gname in principal.get("GroupList", []) if kind == "user" else []:
        if gname in groups:
            docs += from_entity(groups[gname], "GroupPolicyList")
    return docs


def _principals(auth: dict):
    for u in auth.get("UserDetailList", []):
        yield "user", "iam_user", u, u["Arn"], u["UserName"]
    for r in auth.get("RoleDetailList", []):
        if "/aws-service-role/" in r.get("Path", ""):
            continue                           # service-linked: AWS-owned, out of scope
        yield "role", "iam_role", r, r["Arn"], r["RoleName"]


def _allows_any(docs, action) -> str | None:
    for src, d in docs:
        if "__aws_managed__" in d:
            continue                          # AWS-managed body not collected; see admin check
        if allows(d, action):
            return src
    return None


# ---------------------------------------------------------------- credential report checks
def _root(rows):
    return next((r for r in rows if r.get("user") == "<root_account>"), None)


def _live_rows(ctx):
    """Credential-report rows for users that still exist. AWS serves a cached report for
    up to 4 hours, so a user deleted since it was built still has a row (the lab's
    post-teardown scan, 2026-10-29). The user list from this scan decides; without it
    every row is kept and the miss is already a gap."""
    rows = ctx.glob(CRED) or []
    auth = ctx.glob(AUTH)
    if auth is None:
        return rows
    users = {u.get("Arn") for u in auth.get("UserDetailList", [])}
    return [r for r in rows if r.get("user") == "<root_account>" or r.get("arn") in users]


@check(CheckSpec(
    "iam.root-access-keys", "Root account has access keys", "identity", "critical",
    ("iam.account_summary",), references=("CIS 1.4",),
    covers="AccountAccessKeysPresent in the IAM account summary."))
def root_keys(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    s = ctx.glob("iam.account_summary")
    if s and s.get("AccountAccessKeysPresent", 0):
        res.findings.append(ctx.finding(
            {"id": f"arn:aws:iam::{ctx.account}:root", "name": "root", "type": "account"},
            "The root user has access keys",
            [("iam:GetAccountSummary", ctx.account, "AccountAccessKeysPresent=1")],
            {"summary": "Delete the root user's access keys; use IAM roles instead."}))
    return res


@check(CheckSpec(
    "iam.root-mfa", "Root account has no MFA", "identity", "critical", ("iam.account_summary",),
    references=("CIS 1.5",), covers="AccountMFAEnabled in the IAM account summary.",
    does_not_cover="Whether the MFA is hardware (CIS 1.6)."))
def root_mfa(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    s = ctx.glob("iam.account_summary")
    if s is not None and not s.get("AccountMFAEnabled", 0):
        res.findings.append(ctx.finding(
            {"id": f"arn:aws:iam::{ctx.account}:root", "name": "root", "type": "account"},
            "The root user has no MFA",
            [("iam:GetAccountSummary", ctx.account, "AccountMFAEnabled=0")],
            {"summary": "Enable MFA (preferably hardware) on the root user."}))
    return res


@check(CheckSpec(
    "iam.user-no-mfa", "Console user without MFA", "identity", "high", (CRED, AUTH),
    references=("CIS 1.10",), covers="IAM users with a console password and no MFA device."))
def user_no_mfa(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for r in _live_rows(ctx):
        if r["user"] != "<root_account>" and r.get("password_enabled") == "true" \
                and r.get("mfa_active") != "true":
            res.findings.append(ctx.finding(
                {"id": r["arn"], "name": r["user"], "type": "iam_user"},
                f"{r['user']} can sign in to the console without MFA",
                [("iam:GetCredentialReport", r["arn"], "password_enabled=true, mfa_active=false")],
                {"summary": "Require MFA for console users (or move them to IAM Identity Center)."}))
    return res


def _keys(row):
    for n in ("1", "2"):
        if row.get(f"access_key_{n}_active") == "true":
            yield n, _date(row.get(f"access_key_{n}_last_rotated")), \
                _date(row.get(f"access_key_{n}_last_used_date"))


@check(CheckSpec(
    "iam.access-key-age", "Access key older than the allowed age", "identity", "medium",
    (CRED, AUTH), config={"max_days": 90}, references=("CIS 1.14",),
    covers="Active access keys not rotated within max_days."))
def key_age(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    max_days = int(ctx.config.get("max_days", 90))
    for r in _live_rows(ctx):
        for n, rotated, _used in _keys(r):
            if rotated and (ctx.now - rotated).days > max_days:
                age = (ctx.now - rotated).days
                res.findings.append(ctx.finding(
                    {"id": r["arn"], "name": r["user"], "type": "iam_user"},
                    f"{r['user']} access key {n} is {age} days old",
                    [("iam:GetCredentialReport", r["arn"], f"access_key_{n}_last_rotated {rotated.date()}")],
                    {"summary": "Rotate the key, or replace it with a role."},
                    qualifiers={"key": n}))
    return res


@check(CheckSpec(
    "iam.unused-user-live-keys", "Unused user still has an active access key", "identity",
    "medium", (CRED, AUTH), config={"unused_days": 90}, references=("CIS 1.12",),
    covers="Active keys never used, or unused for unused_days, on keys older than that."))
def unused_keys(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    days = int(ctx.config.get("unused_days", 90))
    for r in _live_rows(ctx):
        for n, rotated, used in _keys(r):
            last = used or rotated
            if last and (ctx.now - last).days > days:
                res.findings.append(ctx.finding(
                    {"id": r["arn"], "name": r["user"], "type": "iam_user"},
                    f"{r['user']} key {n} unused for {(ctx.now - last).days} days but still active",
                    [("iam:GetCredentialReport", r["arn"],
                      f"last used {used.date() if used else 'never'}")],
                    {"summary": "Deactivate, then delete, the unused key.",
                     "cli": f"aws iam update-access-key --user-name {r['user']} "
                            "--access-key-id <id> --status Inactive"},
                    qualifiers={"key": n}))
    return res


# ---------------------------------------------------------------- policy checks
@check(CheckSpec(
    "iam.admin-principals", "Principal with full administrator access", "identity", "high",
    (AUTH,), references=("CIS 1.16",),
    covers="Users and roles with AdministratorAccess or an Allow *:* policy, directly or "
           "through a group. Emits can_escalate_to admin_equivalent facts.",
    false_positives="Break-glass roles: tag them scanner:accepted-risk."))
def admin_principals(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    auth = ctx.glob(AUTH)
    if auth is None:
        return res
    res.nodes.append(Node(ADMIN, "admin_equivalent", ctx.account, labels=["crown_jewel"]))
    for kind, ntype, p, arn, name in _principals(auth):
        docs = _policy_docs(auth, p, kind)
        src = next((s for s, d in docs if s in ADMIN_POLICY_ARNS
                    or ("__aws_managed__" not in d and is_full_admin(d))), None)
        if not src:
            continue
        tags = {t["Key"]: t["Value"] for t in p.get("Tags", [])}
        ev = [("iam:GetAccountAuthorizationDetails", arn, f"{src} grants *:*")]
        res.nodes.append(Node(arn, ntype, ctx.account, name=name, tags=tags))
        res.facts.append(ctx.fact(arn, "can_escalate_to", ADMIN, ev, {"via": "admin policy"},
                                  [NOT_EVALUATED], 0.9))
        res.findings.append(ctx.finding(
            {"id": arn, "name": name, "type": ntype}, f"{name} has full administrator access",
            ev, {"summary": "Replace with a least-privilege policy; keep admin for break-glass only."},
            tags=tags))
    return res


@check(CheckSpec(
    "iam.privilege-escalation", "Principal can escalate its own privileges", "identity",
    "high", (AUTH,), config={"patterns": sorted(ESCALATIONS)},
    covers="Known escalation combinations (PassRole + compute, policy-version, attach/put "
           "policy, CreateAccessKey, UpdateLoginProfile, UpdateFunctionCode).",
    does_not_cover="Resource scoping of each permission: a PassRole limited to one harmless "
                   "role is still flagged, as `possible`.",
    false_positives="Deployment roles that legitimately pass roles."))
def privesc(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    auth = ctx.glob(AUTH)
    if auth is None:
        return res
    wanted = {k: v for k, v in ESCALATIONS.items() if k in ctx.config.get("patterns", ESCALATIONS)}
    for kind, ntype, p, arn, name in _principals(auth):
        docs = _policy_docs(auth, p, kind)
        if any(s in ADMIN_POLICY_ARNS or ("__aws_managed__" not in d and is_full_admin(d))
               for s, d in docs):
            continue                            # already admin: iam.admin-principals covers it
        hits = {}
        for pat, actions in wanted.items():
            srcs = [_allows_any(docs, a) for a in actions]
            if all(srcs):
                hits[pat] = sorted(set(srcs))
        if not hits:
            continue
        tags = {t["Key"]: t["Value"] for t in p.get("Tags", [])}
        ev = [("iam:GetAccountAuthorizationDetails", arn, f"{pat} via {', '.join(s)}")
              for pat, s in sorted(hits.items())]
        res.nodes.append(Node(arn, ntype, ctx.account, name=name, tags=tags))
        res.facts.append(ctx.fact(arn, "can_escalate_to", ADMIN, ev,
                                  {"via": sorted(hits)},
                                  [NOT_EVALUATED, "resource scoping not evaluated"], 0.7))
        res.findings.append(ctx.finding(
            {"id": arn, "name": name, "type": ntype},
            f"{name} can escalate privileges ({', '.join(sorted(hits))})", ev,
            {"summary": "Scope iam:PassRole and IAM write actions to specific resources, or "
                        "add a permissions boundary."}, tags=tags, confidence=0.7))
    return res


@check(CheckSpec(
    "iam.trust-without-external-id", "Role trusts another account without ExternalId",
    "identity", "medium", (AUTH,),
    covers="Roles assumable by a principal in another AWS account with no sts:ExternalId "
           "condition (confused-deputy risk for third-party access). Emits can_assume facts "
           "for every trust relationship.",
    false_positives="Trusts between your own accounts (list them in config.own_accounts)."))
def trust(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    auth = ctx.glob(AUTH)
    if auth is None:
        return res
    own = set(ctx.config.get("own_accounts", [])) | {ctx.account}
    for r in auth.get("RoleDetailList", []):
        if "/aws-service-role/" in r.get("Path", ""):
            continue
        for tp in trust_principals(r.get("AssumeRolePolicyDocument")):
            if tp["kind"] != "aws":
                continue
            acct = account_of(tp["value"]) if tp["value"] != "*" else "*"
            src = tp["value"] if acct == ctx.account else f"external:{acct}"
            ev = [("iam:GetAccountAuthorizationDetails", r["Arn"], f"trusts {tp['value']}")]
            if acct != ctx.account:
                res.nodes.append(Node(src, "external_principal", acct, labels=["entry_point"]))
            res.facts.append(ctx.fact(src, "can_assume", r["Arn"], ev,
                                      {"external_id": tp["external_id"]},
                                      tp["conditions"] + ([NOT_EVALUATED] if acct == ctx.account else []),
                                      0.9))
            if acct not in own and not tp["external_id"]:
                res.findings.append(ctx.finding(
                    {"id": r["Arn"], "name": r["RoleName"], "type": "iam_role"},
                    f"{r['RoleName']} can be assumed from account {acct} without an ExternalId",
                    ev, {"summary": "Add an sts:ExternalId condition, or restrict the trusted "
                                    "principal to a specific role."},
                    severity="critical" if acct == "*" else None,
                    qualifiers={"trusted": tp["value"]},
                    tags={t["Key"]: t["Value"] for t in r.get("Tags", [])}))
    return res
