"""`doctor`: what the current identity can actually do, and how to get the rest
(requirements §The doctor command). Probing is the source of truth (policy simulation
misses SCPs and session policies). It makes no write call and one cheap read per
collector per region (R4.4).

Also the least-privilege policy generator (R4.1, R4.2) and the "ask your admin"
message (§doctor step 5.4)."""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from ..core.aws import TIER1_ACTIONS, is_access_denied
from ..core.collect import COLLECTORS, GLOBAL
from . import scan  # noqa: F401 (registers collectors and checks)
from .checks import select

# One cheap read per collector: (service, operation, kwargs). Global ones run once.
PROBES = {
    "iam.access_keys": ("iam", "list_users", {"MaxItems": 1}),
    "identitycenter.users": ("sso-admin", "list_instances", {"MaxResults": 1}),
    "rds.db_users": ("rds", "describe_db_clusters", {"MaxRecords": 20}),
    "redshift.clusters": ("redshift", "describe_clusters", {"MaxRecords": 20}),
    "elasticache.users": ("elasticache", "describe_users", {"MaxRecords": 20}),
    "mq.users": ("mq", "list_brokers", {"MaxResults": 5}),      # MQ rejects fewer than 5
    "transfer.users": ("transfer", "list_servers", {"MaxResults": 1}),
    "cognito.pools": ("cognito-idp", "list_user_pools", {"MaxResults": 1}),
    "ec2.key_pairs": ("ec2", "describe_key_pairs", {}),
    "secretsmanager.secrets": ("secretsmanager", "list_secrets", {"MaxResults": 1}),
    "ssm.parameters": ("ssm", "describe_parameters", {"MaxResults": 1}),
    "ec2.security_groups": ("ec2", "describe_security_groups", {"MaxResults": 5}),
    "ec2.network_acls": ("ec2", "describe_network_acls", {"MaxResults": 5}),
    "ec2.route_tables": ("ec2", "describe_route_tables", {"MaxResults": 5}),
    "ec2.vpcs": ("ec2", "describe_flow_logs", {"MaxResults": 5}),
    "ec2.instances": ("ec2", "describe_instances", {"MaxResults": 5}),
    "ec2.volumes": ("ec2", "get_ebs_encryption_by_default", {}),
    "ec2.public_snapshots": ("ec2", "describe_snapshots", {"OwnerIds": ["self"], "MaxResults": 5}),
    "ec2.public_images": ("ec2", "describe_images", {"Owners": ["self"]}),
    "ssm.managed_instances": ("ssm", "describe_instance_information", {"MaxResults": 5}),
    "elbv2.load_balancers": ("elbv2", "describe_load_balancers", {"PageSize": 1}),
    "lambda.functions": ("lambda", "list_functions", {"MaxItems": 1}),
    "eks.clusters": ("eks", "list_clusters", {"maxResults": 1}),
    "ecr.repositories": ("ecr", "describe_repositories", {"maxResults": 1}),
    "rds.instances": ("rds", "describe_db_instances", {"MaxRecords": 20}),
    "sqs.queues": ("sqs", "list_queues", {"MaxResults": 1}),
    "sns.topics": ("sns", "list_topics", {}),
    "kms.keys": ("kms", "list_keys", {"Limit": 1}),
    "guardduty.detectors": ("guardduty", "list_detectors", {"MaxResults": 1}),
    "config.recorders": ("config", "describe_configuration_recorder_status", {}),
    "iam.credential_report": ("iam", "get_credential_report", {}),
    "iam.account_summary": ("iam", "get_account_summary", {}),
    "iam.authorization_details": ("iam", "get_account_authorization_details", {"MaxItems": 1}),
    "s3.buckets": ("s3", "list_buckets", {}),
    "cloudtrail.trails": ("cloudtrail", "describe_trails", {}),
}
# Native services whose findings later tiers ingest (R5.3). Detection only.
SERVICES = {
    "guardduty": ("guardduty", "list_detectors", {}),
    "securityhub": ("securityhub", "describe_hub", {}),
    "inspector2": ("inspector2", "batch_get_account_status", {}),
    "macie": ("macie2", "get_macie_session", {}),
    "access-analyzer": ("accessanalyzer", "list_analyzers", {}),
}
MANAGED = ["arn:aws:iam::aws:policy/SecurityAudit", "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"]
DATA_DENY = ["s3:GetObject", "secretsmanager:GetSecretValue", "ssm:GetParameter",
             "ssm:GetParameters", "ssm:GetParametersByPath", "kms:Decrypt", "lambda:GetFunction"]


# Whether each service is switched on: "on", "off", or "not allowed" (really denied).
# The call succeeding only proves permission; a live account showed "ok" for an unsubscribed
# Security Hub and "denied" for Macie, which answers AccessDenied when it is merely off.
_ON = {
    "guardduty": lambda r: bool(r.get("DetectorIds")),
    "securityhub": lambda r: bool(r.get("HubArn")),
    "inspector2": lambda r: any((a.get("state") or {}).get("status") == "ENABLED"
                                for a in r.get("accounts", [])),
    "macie": lambda r: r.get("status") == "ENABLED",
    "access-analyzer": lambda r: any(a.get("status") == "ACTIVE" for a in r.get("analyzers", [])),
}
_OFF_WHEN = {"securityhub": ("InvalidAccessException", "not subscribed"),
             "macie": ("AccessDeniedException", "not enabled")}


def probe_for(key: str) -> tuple:
    """The cheap probe for a collector: PROBES here, or `PROBES` in the collector's own
    module, looked up at run time. A module that registers collectors declares its probes
    next to them; importing order can't lose them (doctor imports scan before PROBES)."""
    if key in PROBES:
        return PROBES[key]
    mod = sys.modules.get(COLLECTORS[key].fn.__module__)
    probe = getattr(mod, "PROBES", {}).get(key)
    if probe is None:
        raise KeyError(f"no doctor probe for collector {key!r}: add it to PROBES in "
                       f"{COLLECTORS[key].fn.__module__}")
    return probe


def service_state(name: str, client) -> str:
    _, op, kw = SERVICES[name]
    try:
        return "on" if _ON[name](getattr(client, op)(**kw)) else "off"
    except ClientError as e:
        err = e.response.get("Error", {})
        off = _OFF_WHEN.get(name)
        if off and err.get("Code") == off[0] and off[1] in (err.get("Message") or "").lower():
            return "off"
        return "not allowed" if is_access_denied(e) else f"error:{err.get('Code', '')}"
    except Exception as e:                                   # endpoint missing, etc.
        return f"error:{type(e).__name__}"


def _probe(env, region, svc, op, kw):
    try:
        getattr(env.client(svc, None if region == GLOBAL else region), op)(**kw)
        return "ok"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if is_access_denied(e):
            return "denied"
        # "the report is not there yet" still proves the permission exists.
        if code in ("ReportNotPresent", "ReportExpired", "ReportInProgress",
                    "NoSuchConfigurationRecorderException", "ResourceNotFoundException",
                    "InvalidAccessException", "BadRequestException"):
            return "ok"
        return f"error:{code}"
    except Exception as e:                       # endpoint not in region, etc.
        return f"error:{type(e).__name__}"


def run(env, regions: list[str], profile: dict, workers: int = 16) -> dict:
    t0 = time.monotonic()
    scope = env.resolve_scope()
    checks = select(profile.get("include", ["*"]), profile.get("exclude", []),
                    profile.get("max_tier", 0), profile.get("mvp_only", False))
    keys = sorted({k for c in checks for k in c.spec.collectors})
    tasks = []
    for k in keys:
        svc, op, kw = probe_for(k)
        rs = [GLOBAL] if COLLECTORS[k].scope == GLOBAL else regions
        tasks += [(k, r, svc, op, kw) for r in rs]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [(k, r, pool.submit(_probe, env, r, svc, op, kw)) for k, r, svc, op, kw in tasks]
        probe = {}
        for k, r, f in futs:
            probe.setdefault(k, {})[r] = f.result()
    with ThreadPoolExecutor(max_workers=len(SERVICES)) as pool:
        svc_res = {name: pool.submit(lambda n, s: service_state(n, env.client(s[0], env.region)),
                                     name, spec) for name, spec in SERVICES.items()}
        services = {n: f.result() for n, f in svc_res.items()}
    matrix = []
    for c in checks:
        states = [s for k in c.spec.collectors for s in probe[k].values()]
        denied = sorted({a for k in c.spec.collectors if "denied" in probe[k].values()
                         for a in COLLECTORS[k].actions})
        status = ("runnable" if all(s == "ok" for s in states)
                  else "blocked" if all(s == "denied" for s in states) else "partial")
        matrix.append({"check": c.spec.id, "status": status, "missing_actions": denied,
                       "regions_denied": sorted({r for k in c.spec.collectors
                                                 for r, s in probe[k].items() if s != "ok"})})
    missing = sorted({a for m in matrix for a in m["missing_actions"]})
    return {
        "caller": scope.caller_arn, "account": scope.account_id, "regions": regions,
        "duration_ms": int((time.monotonic() - t0) * 1000),
        "summary": {s: sum(1 for m in matrix if m["status"] == s)
                    for s in ("runnable", "partial", "blocked")},
        "matrix": matrix, "probes": probe, "services": services,
        "missing_actions": missing, "fixes": fixes(missing, profile),
    }


def generate_policy(profile: dict) -> dict:
    """Least-privilege policy for the selected checks (R4.1) with explicit data-read
    denies (R4.2). Tier 2b is never generated here (R4.3). At tier >= 1 the tier-1
    content reads the selected checks need are allowed and their denies dropped; nothing
    else is (GetObject, GetSecretValue, GetParameter*, Decrypt stay denied)."""
    tier = profile.get("max_tier", 0)
    checks = select(profile.get("include", ["*"]), profile.get("exclude", []),
                    tier, profile.get("mvp_only", False))
    actions = sorted({a for c in checks for a in c.spec.required_actions()})
    opened = set(TIER1_ACTIONS) & set(actions) if tier >= 1 else set()
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "CloudtoolsReadOnly", "Effect": "Allow", "Action": actions, "Resource": "*"},
        {"Sid": "CloudtoolsNeverReadsData", "Effect": "Deny",
         "Action": [a for a in DATA_DENY if a not in opened], "Resource": "*"}]}


def ask_admin_message(missing: list[str]) -> str:
    why = {}
    for k, spec in COLLECTORS.items():
        for a in spec.actions:
            why.setdefault(a, set()).add(k)
    lines = ["Hi, I'd like to run a read-only AWS security scan (cloudtools). It needs these",
             "permissions, all read-only. It cannot read object, secret or parameter contents,",
             "and it changes nothing:", ""]
    lines += [f"  - {a}: used by {', '.join(sorted(why.get(a, {'scanner'})))}" for a in missing]
    lines += ["", "Easiest option: attach the AWS managed policies SecurityAudit and ViewOnlyAccess.",
              "A least-privilege policy is attached as cloudtools-policy.json. Thank you!"]
    return "\n".join(lines)


def fixes(missing: list[str], profile: dict) -> list[dict]:
    if not missing:
        return []
    return [
        {"option": 1, "how": "Attach the AWS managed policies", "policies": MANAGED},
        {"option": 2, "how": "Attach the generated least-privilege policy",
         "policy": generate_policy(profile)},
        {"option": 3, "how": "Send this message to your AWS admin",
         "message": ask_admin_message(missing)},
    ]


def to_text(d: dict) -> str:
    s = d["summary"]
    lines = [f"Caller {d['caller']} · account {d['account']} · {len(d['regions'])} region(s) · "
             f"{d['duration_ms'] / 1000:.1f}s",
             f"Checks: {s['runnable']} runnable · {s['partial']} partial · {s['blocked']} blocked", ""]
    for m in d["matrix"]:
        if m["status"] != "runnable":
            lines.append(f"  {m['status']:>8}  {m['check']}  needs {', '.join(m['missing_actions']) or '(see regions: ' + ', '.join(m['regions_denied']) + ')'}")
    lines.append("\nAWS security services (on/off): "
                 + ", ".join(f"{k} {v}" for k, v in d["services"].items()))
    if d["fixes"]:
        lines.append("\nWays to get the missing access, easiest first:")
        for f in d["fixes"]:
            lines.append(f"  {f['option']}. {f['how']}")
        lines.append("Write the policy and admin message with: cloudtools security policy --write ./policy")
    else:
        lines.append("\nEverything the selected checks need is readable.")
    return "\n".join(lines)


def policy_json(profile: dict) -> str:
    return json.dumps(generate_policy(profile), indent=2)
