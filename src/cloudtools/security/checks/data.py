"""data.*: exposed data, configuration only (requirements check catalogue, MVP tier 0).
No object, secret or parameter content is ever read (R4.2)."""
from __future__ import annotations

from ...core.model import INTERNET, CheckResult, Node
from ..policy import public_statements
from . import CheckSpec, check


def _public_fact(ctx, arn, ev, conds=()):
    return ctx.fact(INTERNET, "is_public", arn, ev, conditions=conds, confidence=0.95)


@check(CheckSpec(
    "data.s3-public-bucket", "S3 bucket readable or writable by anyone", "data", "high",
    ("s3.buckets",), references=("CIS 2.1.4", "AWS FSBP S3.2"),
    covers="Buckets public through their policy or ACL that Block Public Access does not "
           "neutralise (bucket and account level).",
    false_positives="Static website buckets: tag scanner:accepted-risk."))
def s3_public(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    p = ctx.glob("s3.buckets")
    if p is None:
        return res
    acct = p["account_bpa"] or {}
    if p["account_bpa_denied"]:
        res.gaps.append(ctx.gap("account Block Public Access", p["account_bpa_denied"],
                                ["s3:GetAccountPublicAccessBlock"]))
    for b in p["buckets"]:
        bpa = {k: (acct.get(k) or (b["bpa"] or {}).get(k)) for k in
               ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
        for what, why in (("policy", b["policy_denied"]), ("ACL", b["acl_denied"]),
                          ("Block Public Access", b["bpa_denied"])):
            if why:
                res.gaps.append(ctx.gap(f"{what} of bucket {b['name']}", why,
                                        ["s3:GetBucketPolicy", "s3:GetBucketAcl",
                                         "s3:GetBucketPublicAccessBlock"]))
        ev = []
        if (b["policy_is_public"] or public_statements(b["policy"])) and not bpa["RestrictPublicBuckets"]:
            ev.append(("s3:GetBucketPolicyStatus", b["arn"], "policy grants access to everyone"))
        if b["public_acl_grants"] and not bpa["IgnorePublicAcls"]:
            ev.append(("s3:GetBucketAcl", b["arn"], f"AllUsers/AuthenticatedUsers: "
                                                     f"{','.join(b['public_acl_grants'])}"))
        if not ev:
            continue
        res.nodes.append(Node(b["arn"], "s3_bucket", ctx.account, b["region"], b["name"], b["tags"]))
        res.facts.append(_public_fact(ctx, b["arn"], ev))
        writes = any(g in ("WRITE", "FULL_CONTROL") for g in b["public_acl_grants"])
        res.findings.append(ctx.finding(
            {"id": b["arn"], "name": b["name"], "region": b["region"], "type": "s3_bucket"},
            f"Bucket {b['name']} is public{' and writable' if writes else ''}", ev,
            {"summary": "Turn on Block Public Access for the bucket (and the account); serve "
                        "public content through CloudFront with origin access control.",
             "cli": f"aws s3api put-public-access-block --bucket {b['name']} "
                    "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"},
            severity="critical" if writes else None, tags=b["tags"]))
    return res


@check(CheckSpec(
    "data.s3-account-bpa-off", "Account-level S3 Block Public Access is not fully on",
    "data", "medium", ("s3.buckets",), references=("CIS 2.1.4",),
    covers="The account-wide S3 Block Public Access settings."))
def s3_account_bpa(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    p = ctx.glob("s3.buckets")
    if p is None or p["account_bpa_denied"]:
        return res
    a = p["account_bpa"] or {}
    off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                       "RestrictPublicBuckets") if not a.get(k)]
    if off:
        res.findings.append(ctx.finding(
            {"id": f"arn:aws:s3:::account/{ctx.account}", "name": "S3 account settings", "type": "account"},
            f"Account S3 Block Public Access is off for {', '.join(off)}",
            [("s3:GetAccountPublicAccessBlock", ctx.account, f"off: {off}")],
            {"summary": "Turn on all four account-level Block Public Access settings."}))
    return res


@check(CheckSpec(
    "data.ebs-snapshot-public", "EBS snapshot is public", "data", "critical",
    ("ec2.public_snapshots",), references=("AWS FSBP EC2.1",),
    covers="Snapshots you own that any AWS account can restore."))
def ebs_public(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, snaps in ctx.per_region("ec2.public_snapshots").items():
        for s in snaps:
            ev = [("ec2:DescribeSnapshots", s["id"], "RestorableBy all")]
            res.nodes.append(Node(s["id"], "snapshot", ctx.account, region, s["id"], s["tags"]))
            res.facts.append(_public_fact(ctx, s["id"], ev))
            res.findings.append(ctx.finding(
                {"id": s["id"], "name": s["id"], "region": region, "type": "snapshot"},
                f"EBS snapshot {s['id']} can be restored by anyone", ev,
                {"summary": "Remove the public createVolumePermission.",
                 "cli": f"aws ec2 modify-snapshot-attribute --region {region} --snapshot-id "
                        f"{s['id']} --attribute createVolumePermission --operation-type remove "
                        "--group-names all"}, tags=s["tags"]))
    return res


@check(CheckSpec(
    "data.rds-snapshot-public", "RDS snapshot is public", "data", "critical",
    ("rds.instances",), references=("AWS FSBP RDS.1",),
    covers="Manual DB snapshots shared with 'all'."))
def rds_snap_public(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, payload in ctx.per_region("rds.instances").items():
        for s in payload["public_snapshots"]:
            if s["denied"]:
                res.gaps.append(ctx.gap(f"sharing of DB snapshot {s['id']}", s["denied"],
                                        ["rds:DescribeDBSnapshotAttributes"], region))
                continue
            ev = [("rds:DescribeDBSnapshotAttributes", s["id"], "restore: all")]
            res.facts.append(_public_fact(ctx, s["arn"] or s["id"], ev))
            res.findings.append(ctx.finding(
                {"id": s["arn"] or s["id"], "name": s["id"], "region": region, "type": "snapshot"},
                f"DB snapshot {s['id']} is public", ev,
                {"summary": "Remove 'all' from the snapshot's restore attribute."}))
    return res


@check(CheckSpec(
    "data.ami-public", "AMI is public", "data", "high", ("ec2.public_images",),
    covers="AMIs you own that are public."))
def ami_public(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, imgs in ctx.per_region("ec2.public_images").items():
        for i in imgs:
            ev = [("ec2:DescribeImages", i["id"], "is-public=true")]
            res.facts.append(_public_fact(ctx, i["id"], ev))
            res.findings.append(ctx.finding(
                {"id": i["id"], "name": i["name"], "region": region, "type": "ami"},
                f"AMI {i['name'] or i['id']} is public", ev,
                {"summary": "Make the AMI private unless publishing it is intended."},
                tags=i["tags"]))
    return res


def _policy_check(ctx, key: str, rtype: str, ntype: str, label: str, action_hint: str):
    res = CheckResult(gaps=ctx.gaps())
    for region, items in ctx.per_region(key).items():
        for it in items:
            arn = it["arn"]
            if it.get("policy_denied"):
                res.gaps.append(ctx.gap(f"policy of {arn}", it["policy_denied"], [action_hint], region))
                continue
            pub = public_statements(it.get("policy"))
            if not pub:
                continue
            acts = sorted({a for st in pub for a in (st.get("Action") if isinstance(
                st.get("Action"), list) else [st.get("Action")]) if a})
            ev = [(action_hint, arn, f"Principal * allows {acts}")]
            res.nodes.append(Node(arn, ntype, ctx.account, region, arn.split(":")[-1]))
            res.facts.append(_public_fact(ctx, arn, ev))
            res.findings.append(ctx.finding(
                {"id": arn, "name": arn.split(":")[-1], "region": region, "type": rtype},
                f"{label} {arn.split(':')[-1]} policy allows anyone: {', '.join(acts)}", ev,
                {"summary": f"Restrict the {label.lower()} policy to named principals or add "
                            "an aws:SourceArn / aws:PrincipalOrgID condition."},
                qualifiers={"actions": acts}))
    return res


@check(CheckSpec(
    "data.sqs-policy-public", "SQS queue policy allows anyone", "data", "high", ("sqs.queues",),
    covers="Queue policies with Principal * and no restricting condition."))
def sqs_public(ctx):
    return _policy_check(ctx, "sqs.queues", "sqs_queue", "sqs_queue", "Queue", "sqs:GetQueueAttributes")


@check(CheckSpec(
    "data.sns-policy-public", "SNS topic policy allows anyone", "data", "high", ("sns.topics",),
    covers="Topic policies with Principal * and no restricting condition."))
def sns_public(ctx):
    return _policy_check(ctx, "sns.topics", "sns_topic", "sns_topic", "Topic", "sns:GetTopicAttributes")


@check(CheckSpec(
    "data.kms-policy-public", "KMS key policy allows anyone", "data", "critical", ("kms.keys",),
    covers="Customer-managed key policies with Principal * and no restricting condition."))
def kms_public(ctx):
    return _policy_check(ctx, "kms.keys", "kms_key", "kms_key", "Key", "kms:GetKeyPolicy")


@check(CheckSpec(
    "data.ecr-policy-public", "ECR repository policy allows anyone", "data", "high",
    ("ecr.repositories",), covers="Repository policies with Principal * (public pulls or pushes)."))
def ecr_public(ctx):
    return _policy_check(ctx, "ecr.repositories", "ecr_repository", "ecr_repository",
                         "Repository", "ecr:GetRepositoryPolicy")


@check(CheckSpec(
    "data.ebs-unencrypted", "EBS volume is not encrypted", "data", "low", ("ec2.volumes",),
    references=("CIS 2.2.1",),
    covers="Unencrypted volumes, and regions where encryption by default is off."))
def ebs_unencrypted(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, p in ctx.per_region("ec2.volumes").items():
        if p["encryption_by_default_denied"]:
            res.gaps.append(ctx.gap(f"EBS encryption-by-default in {region}",
                                    p["encryption_by_default_denied"],
                                    ["ec2:GetEbsEncryptionByDefault"], region))
        elif p["encryption_by_default"] is False:
            res.findings.append(ctx.finding(
                {"id": f"ebs-default/{region}", "name": f"EBS default encryption {region}",
                 "region": region, "type": "account"},
                f"EBS encryption by default is off in {region}",
                [("ec2:GetEbsEncryptionByDefault", region, "false")],
                {"summary": "Turn on EBS encryption by default.",
                 "cli": f"aws ec2 enable-ebs-encryption-by-default --region {region}"}))
        for v in p["volumes"]:
            if not v["encrypted"]:
                res.findings.append(ctx.finding(
                    {"id": v["id"], "name": v["tags"].get("Name", v["id"]), "region": region,
                     "type": "ebs_volume"},
                    f"Volume {v['id']} is not encrypted",
                    [("ec2:DescribeVolumes", v["id"], "Encrypted=false")],
                    {"summary": "Snapshot, copy encrypted, and replace the volume."},
                    tags=v["tags"]))
    return res


@check(CheckSpec(
    "data.rds-unencrypted", "RDS storage is not encrypted", "data", "medium",
    ("rds.instances",), references=("CIS 2.3.1",), covers="DB instances without storage encryption."))
def rds_unencrypted(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, payload in ctx.per_region("rds.instances").items():
        for d in payload["instances"]:
            if not d["encrypted"]:
                res.findings.append(ctx.finding(
                    {"id": d["arn"] or d["id"], "name": d["id"], "region": region, "type": "rds_instance"},
                    f"RDS {d['id']} storage is not encrypted",
                    [("rds:DescribeDBInstances", d["id"], "StorageEncrypted=false")],
                    {"summary": "Restore from an encrypted snapshot copy."}, tags=d["tags"]))
    return res
