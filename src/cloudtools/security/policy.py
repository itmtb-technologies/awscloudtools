"""Small IAM policy reader for the MVP checks.

This is NOT an IAM evaluator (R7.2 says build on Access Analyzer / PMapper for that,
later). It answers narrow questions: does an Allow statement grant this action, is a
resource policy open to everyone. Anything it does not evaluate (permission boundaries,
SCPs, session policies, most conditions) is reported as a condition so the facts built
on it are `possible`, never `confirmed` (R6.3, R7.3).
"""
from __future__ import annotations

import fnmatch
from urllib.parse import unquote

NOT_EVALUATED = "permission boundaries, SCPs and session policies not evaluated"
# Conditions that genuinely restrict an otherwise-public principal.
RESTRICTING_KEYS = ("aws:sourcearn", "aws:sourceaccount", "aws:sourceowner",
                    "aws:principalorgid", "aws:principalaccount", "aws:principalarn",
                    "aws:sourcevpce", "aws:sourcevpc", "aws:sourceip", "aws:userid",
                    "aws:principalorgpaths", "kms:calleraccount", "kms:viaservice",
                    "sns:endpoint")


def doc(policy) -> dict:
    if isinstance(policy, str):
        import json
        return json.loads(unquote(policy))
    return policy or {}


def statements(policy) -> list[dict]:
    s = doc(policy).get("Statement", [])
    return [s] if isinstance(s, dict) else list(s)


def _as_list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def _match(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def allows(policy, action: str) -> bool:
    """True if some Allow statement grants `action` (on any resource), ignoring
    conditions, and no Deny statement in the SAME document denies it outright."""
    granted = False
    for st in statements(policy):
        acts, nacts = _as_list(st.get("Action")), _as_list(st.get("NotAction"))
        hit = (any(_match(a, action) for a in acts) if acts
               else bool(nacts) and not any(_match(a, action) for a in nacts))
        if not hit:
            continue
        if st.get("Effect") == "Deny" and not st.get("Condition"):
            return False
        if st.get("Effect") == "Allow":
            granted = True
    return granted


def is_full_admin(policy) -> bool:
    for st in statements(policy):
        if st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        if "*" in _as_list(st.get("Action")) and "*" in _as_list(st.get("Resource")):
            return True
    return False


def _principal_is_everyone(p) -> bool:
    if p == "*":
        return True
    if isinstance(p, dict):
        return "*" in _as_list(p.get("AWS")) or "*" in _as_list(p.get("CanonicalUser"))
    return False


def _restricted(cond: dict | None) -> bool:
    for _op, kv in (cond or {}).items():
        for k in (kv or {}):
            if k.lower() in RESTRICTING_KEYS:
                return True
    return False


def public_statements(policy) -> list[dict]:
    """Allow statements open to any principal with no restricting condition."""
    return [st for st in statements(policy)
            if st.get("Effect") == "Allow" and _principal_is_everyone(st.get("Principal"))
            and not _restricted(st.get("Condition"))]


def trust_principals(trust_policy) -> list[dict]:
    """[{kind: aws|service|federated, value, external_id: bool, conditions: [...]}] for
    every Allow sts:AssumeRole* statement in a role's trust policy."""
    out = []
    for st in statements(trust_policy):
        if st.get("Effect") != "Allow":
            continue
        acts = [a.lower() for a in _as_list(st.get("Action"))]
        if not any(a.startswith("sts:assumerole") or a == "sts:*" or a == "*" for a in acts):
            continue
        cond = st.get("Condition") or {}
        ext = any(k.lower() == "sts:externalid" for kv in cond.values() for k in (kv or {}))
        p = st.get("Principal")
        p = {"AWS": p} if isinstance(p, str) else (p or {})
        for kind in ("AWS", "Service", "Federated"):
            for v in _as_list(p.get(kind)):
                out.append({"kind": kind.lower(), "value": v, "external_id": ext,
                            "conditions": sorted(f"{op}:{k}" for op, kv in cond.items()
                                                 for k in (kv or {}))})
    return out


def account_of(principal_arn: str) -> str:
    if principal_arn.isdigit():
        return principal_arn
    parts = principal_arn.split(":")
    return parts[4] if len(parts) > 4 else ""
