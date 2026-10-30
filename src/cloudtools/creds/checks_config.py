"""Tier 1 checks: secrets found in AWS configuration (collectors in `config_secrets.py`).

`sec.config-secrets`: one finding per hit, carrying the `secret` block (detector,
salted fingerprint, masked preview, location) and never a value.

`sec.leaked-aws-key`: an AWS key id in configuration that matches a live IAM key of this
account becomes a `leaked_credential` entry point with `authenticates_as` → the user,
exactly as a key found in a repo does (`checks.report_leaked_key`). Anyone who can read
that configuration (the function's, the instance's, the stack's readers) holds the key.

Both are tier 1: `select()` leaves them out unless the profile's max_tier >= 1, so their
collectors, their doctor probes and their policy actions are absent at tier 0.
"""
from __future__ import annotations

from ..core.model import CheckResult, Gap
from ..security.checks import CheckSpec, check
from .checks import report_leaked_key
from .config_secrets import SOURCES

LABEL = {"ec2_instance": "instance", "lambda_function": "function", "ecs_task_definition": "task definition",
         "cloudformation_stack": "stack", "codebuild_project": "CodeBuild project",
         "ssm_parameter": "parameter"}
WHERE = {"ec2_instance": "user data", "lambda_function": "configuration or code",
         "ecs_task_definition": "container environment", "cloudformation_stack": "template or parameters",
         "codebuild_project": "environment", "ssm_parameter": "plain String value"}
# Detectors whose shape is the evidence; the entropy guess is one level lower.
GUESS = {"generic-secret-entropy"}


def _hits(ctx):
    """(region, collector key, hit) for every hit, in a stable order."""
    for key in SOURCES:
        for region, payload in sorted(ctx.per_region(key).items()):
            for h in (payload or {}).get("hits", []):
                yield region, key, h


def _skipped_gaps(ctx) -> list[Gap]:
    out = []
    for key in SOURCES:
        for region, payload in sorted(ctx.per_region(key).items()):
            for s in (payload or {}).get("skipped", []):
                r = s["resource"]
                out.append(ctx.gap(f"{LABEL.get(r['type'], r['type'])} {r['name']}", s["why"],
                                   [r["api"]], region))
    return out


def _secret(h: dict) -> dict:
    return {"detector": h["detector"], "fingerprint": h["fingerprint"], "preview": h["preview"],
            "location": h["location"]}


def _scanned(ctx) -> dict:
    return {key: sum((p or {}).get("items", 0) for p in ctx.per_region(key).values()) for key in SOURCES}


@check(CheckSpec(
    "sec.config-secrets", "Secret in plain AWS configuration", "secrets", "high", SOURCES, tier=1,
    mvp=True,                     # the tier is the opt-in; quick at --tier 1 must run it
    covers="EC2 user data; Lambda environment variables and deployment code (zip, up to 50 MiB); "
           "ECS task definition environments (latest active revision); CloudFormation templates and "
           "stack parameters; CodeBuild PLAINTEXT environment variables; SSM String/StringList "
           "parameter values, every version. gitleaks-derived rules plus an entropy check on values "
           "whose name says secret.",
    does_not_cover="Secrets Manager values and SecureString parameters (never read, by design); "
                   "Lambda layers and container-image functions; older ECS revisions; launch templates; "
                   "whether a secret is still valid.",
    false_positives="Test or sample values and high-entropy non-secrets named like secrets (the "
                    "entropy detector, reported one level lower). Accept by tag."))
def config_secrets(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps() + _skipped_gaps(ctx))
    n = 0
    for region, key, h in _hits(ctx):
        if h["kind"] == "aws_access_key_id":     # an identifier; sec.leaked-aws-key joins it to IAM
            continue
        n += 1
        r = h["resource"]
        label = LABEL.get(r["type"], r["type"])
        res.findings.append(ctx.finding(
            {"id": r["id"], "name": r["name"], "type": r["type"], "region": region},
            f"{h['detector']} in the {WHERE.get(r['type'], 'configuration')} of {label} {r['name']}",
            [(r["api"], r["id"], f"{h['detector']} at {h['location']} ({h['fingerprint']})")],
            {"summary": "Rotate the secret at its issuer first: everyone who can read this "
                        f"{label}'s configuration has had it. Then store it in Secrets Manager or "
                        "an SSM SecureString and reference it instead of the value."},
            severity="medium" if h["detector"] in GUESS else None,
            qualifiers={"location": h["location"], "fp": h["fingerprint"]},
            secret=_secret(h)))
    res.stats = {"scanned": _scanned(ctx), "secrets": n}
    return res


@check(CheckSpec(
    "sec.leaked-aws-key", "Live AWS access key in plain AWS configuration", "secrets", "high",
    SOURCES + ("iam.access_keys",), tier=1, mvp=True,
    covers="AWS access key ids in the tier-1 configuration sources that match this account's IAM "
           "keys. An active one is an attack-graph entry point that signs in as its user.",
    does_not_cover="Keys of other accounts (counted, not reported); whether the secret half sits "
                   "beside the id (assumed when not seen, and stated).",
    false_positives="A key id written without its secret. Still rotate: whoever wrote the id "
                    "likely had the secret too."))
def leaked_aws_key(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    keys = ctx.glob("iam.access_keys")
    if keys is None:
        res.stats = {"evaluated": False}
        return res
    by_fp = {k["key_fp"]: k for k in keys}
    secret_beside: set[str] = set()      # resources where an AWS secret access key was also seen
    seen: dict[str, dict] = {}
    other = 0
    for region, key, h in _hits(ctx):
        if h["kind"] == "aws_secret_access_key":
            secret_beside.add(h["resource"]["id"])
        if h["kind"] != "aws_access_key_id":
            continue
        k = by_fp.get(h["fingerprint"])
        if not k:
            other += 1
            continue
        seen.setdefault(h["fingerprint"], {"key": k, "hits": []})["hits"].append((region, h))
    for fp, hit in sorted(seen.items()):
        k, hits = hit["key"], hit["hits"]
        places = sorted({f"{LABEL.get(h['resource']['type'], '')} {h['resource']['name']}" for _, h in hits})
        ev = [(h["resource"]["api"], h["resource"]["id"], f"key id …{k['hint']} at {h['location']}")
              for _, h in hits[:5]]
        with_secret = any(h["resource"]["id"] in secret_beside for _, h in hits)
        cond = (["a secret access key was found beside the id; it was not verified against IAM"]
                if with_secret else None)
        report_leaked_key(ctx, res, k, fp, places, ev,
                          {"source": "aws-config", "locations": sorted(h["location"] for _, h in hits)[:20]},
                          "remove it from that configuration and use the resource's IAM role instead "
                          "of a key", **({"conditions": cond, "confidence": 0.9} if cond else {}),
                          secret={"detector": hits[0][1]["detector"], "fingerprint": fp,
                                  "preview": hits[0][1]["preview"], "location": hits[0][1]["location"]})
    res.stats = {"matched": len(seen), "other_accounts": other}
    return res
