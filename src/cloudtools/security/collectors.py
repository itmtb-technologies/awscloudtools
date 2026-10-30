"""Security collectors. Each returns a NORMALISED payload (only the fields checks use),
so snapshots stay small, deterministic and reviewable. They are the only code here that
calls AWS, through AwsEnv's read-only clients.

Per-item calls (bucket policy, queue policy, …) swallow AccessDenied/NoSuch* into a
per-item `_denied` marker instead of failing the whole collector: a check reports those
items as gaps, never as passes.
"""
from __future__ import annotations

import csv
import io
import json
import re
import time

from botocore.exceptions import ClientError

from ..core.aws import is_access_denied
from ..core.collect import GLOBAL, collector


def _pages(client, op: str, key: str, **kw) -> list:
    out: list = []
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kw):
            out += page.get(key, [])
    else:
        out = getattr(client, op)(**kw).get(key, [])
    return out


def _tags(tag_list) -> dict:
    return {t["Key"]: t["Value"] for t in (tag_list or []) if "Key" in t}


def _try(fn, missing=("NoSuch", "NotFound", "Nonexistent")):
    """Call fn; return (value, None) or (None, reason). Missing config is not denial."""
    try:
        return fn(), None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if any(m in code for m in missing):
            return None, None
        return None, ("denied" if is_access_denied(e) else code or "error")


def _policy(text) -> dict | None:
    if not text:
        return None
    return json.loads(text) if isinstance(text, str) else text


# ---------------------------------------------------------------- EC2 / VPC (regional)
@collector("ec2.security_groups", ["ec2:DescribeSecurityGroups"])
def security_groups(env, region):
    out = []
    for g in _pages(env.client("ec2", region), "describe_security_groups", "SecurityGroups"):
        rules = []
        for p in g.get("IpPermissions", []):
            rules.append({
                "proto": p.get("IpProtocol"), "from": p.get("FromPort"), "to": p.get("ToPort"),
                "cidrs": sorted(r["CidrIp"] for r in p.get("IpRanges", [])),
                "ipv6": sorted(r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])),
                "sg_refs": sorted(r["GroupId"] for r in p.get("UserIdGroupPairs", [])
                                  if "GroupId" in r)})
        out.append({"id": g["GroupId"], "name": g.get("GroupName", ""),
                    "vpc": g.get("VpcId", ""), "tags": _tags(g.get("Tags")), "ingress": rules})
    return sorted(out, key=lambda x: x["id"])


@collector("ec2.network_acls", ["ec2:DescribeNetworkAcls"])
def network_acls(env, region):
    out = []
    for a in _pages(env.client("ec2", region), "describe_network_acls", "NetworkAcls"):
        out.append({"id": a["NetworkAclId"], "vpc": a.get("VpcId", ""),
                    "subnets": sorted(x["SubnetId"] for x in a.get("Associations", [])),
                    "entries": sorted(({
                        "egress": e.get("Egress", False), "rule": e.get("RuleNumber"),
                        "proto": str(e.get("Protocol")), "action": e.get("RuleAction"),
                        "cidr": e.get("CidrBlock") or e.get("Ipv6CidrBlock", ""),
                        "from": (e.get("PortRange") or {}).get("From"),
                        "to": (e.get("PortRange") or {}).get("To")}
                        for e in a.get("Entries", [])), key=lambda e: (e["egress"], e["rule"]))})
    return sorted(out, key=lambda x: x["id"])


@collector("ec2.route_tables", ["ec2:DescribeRouteTables"])
def route_tables(env, region):
    out = []
    for t in _pages(env.client("ec2", region), "describe_route_tables", "RouteTables"):
        to_igw = any((r.get("GatewayId") or "").startswith("igw-")
                     and (r.get("DestinationCidrBlock") == "0.0.0.0/0"
                          or r.get("DestinationIpv6CidrBlock") == "::/0")
                     for r in t.get("Routes", []))
        assoc = t.get("Associations", [])
        out.append({"id": t["RouteTableId"], "vpc": t.get("VpcId", ""),
                    "main": any(a.get("Main") for a in assoc),
                    "subnets": sorted(a["SubnetId"] for a in assoc if a.get("SubnetId")),
                    "default_to_igw": to_igw})
    return sorted(out, key=lambda x: x["id"])


@collector("ec2.vpcs", ["ec2:DescribeVpcs", "ec2:DescribeSubnets", "ec2:DescribeFlowLogs"])
def vpcs(env, region):
    ec2 = env.client("ec2", region)
    flows = {f["ResourceId"] for f in _pages(ec2, "describe_flow_logs", "FlowLogs")
             if f.get("FlowLogStatus", "ACTIVE") == "ACTIVE"}
    subnets = [{"id": s["SubnetId"], "vpc": s["VpcId"],
                "public_ip_on_launch": s.get("MapPublicIpOnLaunch", False)}
               for s in _pages(ec2, "describe_subnets", "Subnets")]
    return {"vpcs": sorted(({"id": v["VpcId"], "default": v.get("IsDefault", False),
                             "flow_logs": v["VpcId"] in flows, "tags": _tags(v.get("Tags"))}
                            for v in _pages(ec2, "describe_vpcs", "Vpcs")),
                           key=lambda v: v["id"]),
            "subnets": sorted(subnets, key=lambda s: s["id"])}


@collector("ec2.instances", ["ec2:DescribeInstances"])
def instances(env, region):
    out = []
    for r in _pages(env.client("ec2", region), "describe_instances", "Reservations"):
        for i in r.get("Instances", []):
            state = (i.get("State") or {}).get("Name")
            if state == "terminated":
                continue
            md = i.get("MetadataOptions") or {}
            out.append({
                "id": i["InstanceId"], "state": state, "tags": _tags(i.get("Tags")),
                "name": _tags(i.get("Tags")).get("Name", i["InstanceId"]),
                "public_ip": i.get("PublicIpAddress", ""),
                "subnet": i.get("SubnetId", ""), "vpc": i.get("VpcId", ""),
                # Instance-level groups plus every ENI's groups: a secondary interface can
                # carry a different (open) group than the primary.
                "sgs": sorted({g["GroupId"] for g in i.get("SecurityGroups", [])}
                              | {g["GroupId"] for ni in i.get("NetworkInterfaces", [])
                                 for g in ni.get("Groups", [])}),
                # HttpTokens "optional" = IMDSv1 allowed; endpoint disabled = no IMDS.
                "imds_v1": md.get("HttpTokens", "optional") == "optional"
                and md.get("HttpEndpoint", "enabled") == "enabled",
                "profile_arn": (i.get("IamInstanceProfile") or {}).get("Arn", ""),
                "image_id": i.get("ImageId", ""), "key_name": i.get("KeyName", ""),
                "launch_time": str(i.get("LaunchTime", ""))})
    return sorted(out, key=lambda x: x["id"])


@collector("ec2.volumes", ["ec2:DescribeVolumes", "ec2:GetEbsEncryptionByDefault"])
def volumes(env, region):
    ec2 = env.client("ec2", region)
    default, why = _try(lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"])
    return {"encryption_by_default": default, "encryption_by_default_denied": why,
            "volumes": sorted(({"id": v["VolumeId"], "encrypted": v.get("Encrypted", False),
                                "state": v.get("State"), "tags": _tags(v.get("Tags"))}
                               for v in _pages(ec2, "describe_volumes", "Volumes")),
                              key=lambda v: v["id"])}


@collector("ec2.public_snapshots", ["ec2:DescribeSnapshots"])
def public_snapshots(env, region):
    snaps = _pages(env.client("ec2", region), "describe_snapshots", "Snapshots",
                   OwnerIds=["self"], RestorableByUserIds=["all"])
    return sorted(({"id": s["SnapshotId"], "volume": s.get("VolumeId", ""),
                    "tags": _tags(s.get("Tags"))} for s in snaps), key=lambda s: s["id"])


@collector("ec2.public_images", ["ec2:DescribeImages"])
def public_images(env, region):
    imgs = env.client("ec2", region).describe_images(
        Owners=["self"], Filters=[{"Name": "is-public", "Values": ["true"]}])["Images"]
    return sorted(({"id": i["ImageId"], "name": i.get("Name", ""),
                    "tags": _tags(i.get("Tags"))} for i in imgs), key=lambda i: i["id"])


@collector("ssm.managed_instances", ["ssm:DescribeInstanceInformation"])
def ssm_managed(env, region):
    info = _pages(env.client("ssm", region), "describe_instance_information",
                  "InstanceInformationList")
    return sorted(i["InstanceId"] for i in info if i.get("PingStatus") == "Online")


# ---------------------------------------------------------------- load balancers
@collector("elbv2.load_balancers", ["elasticloadbalancing:DescribeLoadBalancers",
                                    "elasticloadbalancing:DescribeListeners",
                                    "elasticloadbalancing:DescribeTargetGroups",
                                    "elasticloadbalancing:DescribeTargetHealth"])
def load_balancers(env, region):
    elb = env.client("elbv2", region)
    out = []
    for lb in _pages(elb, "describe_load_balancers", "LoadBalancers"):
        arn = lb["LoadBalancerArn"]
        listeners = [{"port": li.get("Port"), "protocol": li.get("Protocol"),
                      "ssl_policy": li.get("SslPolicy", "")}
                     for li in _pages(elb, "describe_listeners", "Listeners",
                                      LoadBalancerArn=arn)]
        targets = []
        for tg in _pages(elb, "describe_target_groups", "TargetGroups", LoadBalancerArn=arn):
            health, _ = _try(lambda: elb.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"])
            targets += [{"id": h["Target"]["Id"], "port": h["Target"].get("Port", tg.get("Port"))}
                        for h in (health or [])]
        out.append({"arn": arn, "name": lb.get("LoadBalancerName", ""),
                    "scheme": lb.get("Scheme"), "type": lb.get("Type"),
                    "sgs": sorted(lb.get("SecurityGroups", [])),
                    "listeners": sorted(listeners, key=lambda x: x["port"] or 0),
                    "targets": sorted(targets, key=lambda t: (t["id"], t["port"] or 0))})
    return sorted(out, key=lambda x: x["arn"])


# ---------------------------------------------------------------- compute services
@collector("lambda.functions", ["lambda:ListFunctions", "lambda:ListFunctionUrlConfigs"])
def lambda_functions(env, region):
    lam = env.client("lambda", region)
    out = []
    for f in _pages(lam, "list_functions", "Functions"):
        urls, why = _try(lambda: lam.list_function_url_configs(
            FunctionName=f["FunctionName"])["FunctionUrlConfigs"])
        out.append({"name": f["FunctionName"], "arn": f["FunctionArn"],
                    "runtime": f.get("Runtime", ""), "role": f.get("Role", ""),
                    "url_auth": sorted(u.get("AuthType") for u in (urls or [])),
                    "url_denied": why})
    return sorted(out, key=lambda x: x["arn"])


@collector("eks.clusters", ["eks:ListClusters", "eks:DescribeCluster"])
def eks_clusters(env, region):
    eks = env.client("eks", region)
    out = []
    for name in _pages(eks, "list_clusters", "clusters"):
        c, why = _try(lambda: eks.describe_cluster(name=name)["cluster"])
        vpc = (c or {}).get("resourcesVpcConfig", {})
        out.append({"name": name, "arn": (c or {}).get("arn", name), "denied": why,
                    "endpoint_public": vpc.get("endpointPublicAccess"),
                    "public_cidrs": sorted(vpc.get("publicAccessCidrs", []))})
    return sorted(out, key=lambda x: x["name"])


@collector("ecr.repositories", ["ecr:DescribeRepositories", "ecr:GetRepositoryPolicy"])
def ecr_repositories(env, region):
    ecr = env.client("ecr", region)
    out = []
    for r in _pages(ecr, "describe_repositories", "repositories"):
        pol, why = _try(lambda: ecr.get_repository_policy(
            repositoryName=r["repositoryName"])["policyText"],
            missing=("NotFound",))
        out.append({"name": r["repositoryName"], "arn": r["repositoryArn"],
                    "policy": _policy(pol), "policy_denied": why,
                    "scan_on_push": (r.get("imageScanningConfiguration") or {}).get("scanOnPush")})
    return sorted(out, key=lambda x: x["arn"])


@collector("rds.instances", ["rds:DescribeDBInstances", "rds:DescribeDBSnapshots",
                             "rds:DescribeDBSnapshotAttributes"])
def rds(env, region):
    r = env.client("rds", region)
    dbs = [{"id": d["DBInstanceIdentifier"], "arn": d.get("DBInstanceArn", ""),
            "engine": d.get("Engine"), "version": d.get("EngineVersion"),
            "public": d.get("PubliclyAccessible", False),
            "encrypted": d.get("StorageEncrypted", False),
            "auto_minor_upgrade": d.get("AutoMinorVersionUpgrade", True),
            "sgs": sorted(g["VpcSecurityGroupId"] for g in d.get("VpcSecurityGroups", [])),
            "tags": _tags(d.get("TagList"))}
           for d in _pages(r, "describe_db_instances", "DBInstances")]
    public_snaps = []
    for s in _pages(r, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        attrs, why = _try(lambda: r.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=s["DBSnapshotIdentifier"])
            ["DBSnapshotAttributesResult"]["DBSnapshotAttributes"])
        restore = [a for a in (attrs or []) if a.get("AttributeName") == "restore"]
        if why or any("all" in a.get("AttributeValues", []) for a in restore):
            public_snaps.append({"id": s["DBSnapshotIdentifier"],
                                 "arn": s.get("DBSnapshotArn", ""), "denied": why})
    return {"instances": sorted(dbs, key=lambda d: d["id"]),
            "public_snapshots": sorted(public_snaps, key=lambda s: s["id"])}


# ---------------------------------------------------------------- resource policies
@collector("sqs.queues", ["sqs:ListQueues", "sqs:GetQueueAttributes"])
def sqs_queues(env, region):
    sqs = env.client("sqs", region)
    out = []
    for url in _pages(sqs, "list_queues", "QueueUrls"):
        attrs, why = _try(lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["Policy", "QueueArn"])["Attributes"])
        out.append({"url": url, "arn": (attrs or {}).get("QueueArn", url),
                    "policy": _policy((attrs or {}).get("Policy")), "policy_denied": why})
    return sorted(out, key=lambda x: x["arn"])


@collector("sns.topics", ["sns:ListTopics", "sns:GetTopicAttributes"])
def sns_topics(env, region):
    sns = env.client("sns", region)
    out = []
    for t in _pages(sns, "list_topics", "Topics"):
        attrs, why = _try(lambda: sns.get_topic_attributes(TopicArn=t["TopicArn"])["Attributes"])
        out.append({"arn": t["TopicArn"], "policy": _policy((attrs or {}).get("Policy")),
                    "policy_denied": why})
    return sorted(out, key=lambda x: x["arn"])


@collector("kms.keys", ["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy",
                        "kms:GetKeyRotationStatus"])
def kms_keys(env, region):
    kms = env.client("kms", region)
    out = []
    for k in _pages(kms, "list_keys", "Keys"):
        meta, why = _try(lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"])
        if meta and (meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled"):
            continue
        pol, pwhy = _try(lambda: kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"])
        rot, _ = _try(lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"])
        out.append({"id": k["KeyId"], "arn": k["KeyArn"], "policy": _policy(pol),
                    "policy_denied": why or pwhy, "rotation": rot})
    return sorted(out, key=lambda x: x["arn"])


# ---------------------------------------------------------------- detection (regional)
@collector("guardduty.detectors", ["guardduty:ListDetectors", "guardduty:GetDetector"])
def guardduty(env, region):
    gd = env.client("guardduty", region)
    out = []
    for d in _pages(gd, "list_detectors", "DetectorIds"):
        det, why = _try(lambda: gd.get_detector(DetectorId=d))
        out.append({"id": d, "status": (det or {}).get("Status"), "denied": why})
    return out


@collector("config.recorders", ["config:DescribeConfigurationRecorderStatus"])
def config_recorders(env, region):
    st = env.client("config", region).describe_configuration_recorder_status()
    return [{"name": r["name"], "recording": r.get("recording", False)}
            for r in st.get("ConfigurationRecordersStatus", [])]


# ---------------------------------------------------------------- global (once per account)
@collector("iam.credential_report", ["iam:GenerateCredentialReport", "iam:GetCredentialReport"],
           scope=GLOBAL, early=True)
def credential_report(env, region):
    """R3.9: requested first; AWS builds it asynchronously. The CSV holds no secrets
    (key ids are not in it), only ages, last-use and MFA flags."""
    iam = env.client("iam")
    for _ in range(20):
        if iam.generate_credential_report().get("State") == "COMPLETE":
            break
        time.sleep(1.5)
    raw = iam.get_credential_report()["Content"]
    text = raw.decode() if isinstance(raw, bytes) else raw
    return sorted(csv.DictReader(io.StringIO(text)), key=lambda r: r.get("arn", ""))


@collector("iam.account_summary", ["iam:GetAccountSummary"], scope=GLOBAL)
def account_summary(env, region):
    return env.client("iam").get_account_summary()["SummaryMap"]


@collector("iam.authorization_details", ["iam:GetAccountAuthorizationDetails"], scope=GLOBAL)
def authorization_details(env, region):
    """Users, groups, roles and managed policies with their documents, in one paginated
    call. Kept nearly raw: the identity checks and the graph both read it."""
    iam = env.client("iam")
    out = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for k in out:
            out[k] += page.get(k, [])
    for k in out:
        out[k] = json.loads(json.dumps(out[k], default=str))   # datetimes -> str
        for p in out[k]:
            p["Tags"] = [_key_id_tag(t) for t in p.get("Tags", [])]
    return out


_KEY_ID = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")


def _key_id_tag(t: dict) -> dict:
    """The IAM console stores a key's description as a user tag keyed by the key id. Keep
    the description, not the id: verbatim it put key ids in every report (2026-10-27)."""
    if _KEY_ID.match(t.get("Key", "")):
        return {"Key": f"access-key-description:…{t['Key'][-4:]}", "Value": t.get("Value", "")}
    return t


@collector("s3.buckets", ["s3:ListAllMyBuckets", "s3:GetBucketLocation",
                          "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicy",
                          "s3:GetBucketPolicyStatus", "s3:GetBucketAcl",
                          "s3:GetEncryptionConfiguration", "s3:GetBucketTagging",
                          "s3:GetAccountPublicAccessBlock"], scope=GLOBAL)
def s3_buckets(env, region):
    s3 = env.client("s3")
    acct = env.resolve_scope().account_id
    account_bpa, abpa_why = _try(lambda: env.client("s3control").get_public_access_block(
        AccountId=acct)["PublicAccessBlockConfiguration"])
    out = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        loc, _ = _try(lambda: s3.get_bucket_location(Bucket=name)["LocationConstraint"])
        bpa, bpa_why = _try(lambda: s3.get_public_access_block(Bucket=name)
                            ["PublicAccessBlockConfiguration"])
        pol, pol_why = _try(lambda: s3.get_bucket_policy(Bucket=name)["Policy"])
        status, _ = _try(lambda: s3.get_bucket_policy_status(Bucket=name)
                         ["PolicyStatus"]["IsPublic"])
        acl, acl_why = _try(lambda: s3.get_bucket_acl(Bucket=name)["Grants"])
        tags, _ = _try(lambda: s3.get_bucket_tagging(Bucket=name)["TagSet"])
        public_grants = sorted({g["Permission"] for g in (acl or [])
                                if (g.get("Grantee") or {}).get("URI", "").endswith(
                                    ("/global/AllUsers", "/global/AuthenticatedUsers"))})
        out.append({"name": name, "arn": f"arn:aws:s3:::{name}",
                    "region": loc or "us-east-1", "bpa": bpa, "bpa_denied": bpa_why,
                    "policy": _policy(pol), "policy_denied": pol_why,
                    "policy_is_public": status, "public_acl_grants": public_grants,
                    "acl_denied": acl_why, "tags": _tags(tags)})
    return {"account_bpa": account_bpa, "account_bpa_denied": abpa_why,
            "buckets": sorted(out, key=lambda x: x["name"])}


@collector("cloudtrail.trails", ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
                                 "cloudtrail:GetEventSelectors"], scope=GLOBAL)
def trails(env, region):
    ct = env.client("cloudtrail")
    out = []
    for t in ct.describe_trails(includeShadowTrails=True).get("trailList", []):
        home = t.get("HomeRegion") or env.region
        st, why = _try(lambda: env.client("cloudtrail", home).get_trail_status(
            Name=t["TrailARN"]))
        out.append({"arn": t["TrailARN"], "name": t.get("Name"), "home": home,
                    "multi_region": t.get("IsMultiRegionTrail", False),
                    "org": t.get("IsOrganizationTrail", False),
                    "logging": (st or {}).get("IsLogging"), "status_denied": why,
                    "validation": t.get("LogFileValidationEnabled", False),
                    "kms": bool(t.get("KmsKeyId"))})
    # A multi-region trail shows up once per region with includeShadowTrails.
    uniq = {t["arn"]: t for t in out}
    return sorted(uniq.values(), key=lambda t: t["arn"])
