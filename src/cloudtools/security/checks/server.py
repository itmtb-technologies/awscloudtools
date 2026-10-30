"""srv.*: servers and workloads (requirements check catalogue, MVP)."""
from __future__ import annotations

from ...core.model import CheckResult, Node
from . import CheckSpec, check

# Runtimes past AWS end of support as of 2026-10 (config so a profile can extend it).
DEPRECATED_RUNTIMES = sorted({
    "python2.7", "python3.6", "python3.7", "python3.8", "nodejs", "nodejs4.3",
    "nodejs6.10", "nodejs8.10", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x",
    "ruby2.5", "ruby2.7", "java8", "go1.x", "dotnetcore1.0", "dotnetcore2.0",
    "dotnetcore2.1", "dotnetcore3.1", "dotnet5.0", "dotnet6", "provided"})


def _profile_roles(ctx) -> dict[str, str]:
    """instance-profile ARN -> role ARN, from iam.authorization_details (if collected)."""
    auth = ctx.glob("iam.authorization_details") or {}
    out = {}
    for r in auth.get("RoleDetailList", []):
        for ip in r.get("InstanceProfileList", []):
            out[ip["Arn"]] = r["Arn"]
    return out


@check(CheckSpec(
    "srv.workload-identities", "Workloads and the roles they run as", "server", "info",
    ("ec2.instances", "lambda.functions", "iam.authorization_details"), mvp=True,
    covers="Facts only: which IAM role each instance and Lambda function runs as. "
           "No findings; the attack graph needs these links."))
def workload_identities(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    roles = _profile_roles(ctx)
    for region, insts in ctx.per_region("ec2.instances").items():
        for i in insts:
            role = roles.get(i["profile_arn"])
            if i["profile_arn"] and role:
                res.facts.append(ctx.fact(i["id"], "runs_as", role, [
                    ("ec2:DescribeInstances", i["id"], f"profile {i['profile_arn']}"),
                    ("iam:GetAccountAuthorizationDetails", role, "profile -> role")]))
            elif i["profile_arn"]:
                res.gaps.append(ctx.gap(f"role behind {i['profile_arn']}",
                                        "instance profile not found in IAM details",
                                        ["iam:GetAccountAuthorizationDetails"], region))
    for region, fns in ctx.per_region("lambda.functions").items():
        for f in fns:
            if f["role"]:
                res.facts.append(ctx.fact(f["arn"], "runs_as", f["role"], [
                    ("lambda:ListFunctions", f["arn"], "execution role")]))
    return res


@check(CheckSpec(
    "srv.imdsv1-enabled", "Instance allows IMDSv1", "server", "medium", ("ec2.instances",),
    references=("AWS FSBP EC2.8",),
    covers="Running instances whose metadata service accepts IMDSv1 (HttpTokens optional).",
    false_positives="Instances with no role gain little from IMDSv2; still recommended."))
def imdsv1(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    roles = _profile_roles(ctx)
    for region, insts in ctx.per_region("ec2.instances").items():
        for i in insts:
            if i["state"] != "running" or not i["imds_v1"]:
                continue
            ev = [("ec2:DescribeInstances", i["id"], "MetadataOptions.HttpTokens=optional")]
            role = roles.get(i["profile_arn"])
            if role:
                # IMDSv1 lets anything that can make the instance send a GET (SSRF behind an
                # exposed service) read the role's credentials. Heuristic, so `possible`.
                res.facts.append(ctx.fact(i["id"], "exposes_credentials", role, ev,
                                          {"via": "imdsv1"},
                                          ["requires a request-forgery path on the instance"], 0.6))
            res.nodes.append(Node(i["id"], "ec2_instance", ctx.account, region, i["name"],
                                  i["tags"], attrs={"imds_v1": True}))
            res.findings.append(ctx.finding(
                {"id": i["id"], "name": i["name"], "region": region, "type": "ec2_instance"},
                f"{i['name']} accepts IMDSv1", ev,
                {"summary": "Require IMDSv2 (HttpTokens=required).",
                 "cli": f"aws ec2 modify-instance-metadata-options --region {region} "
                        f"--instance-id {i['id']} --http-tokens required --http-endpoint enabled"},
                severity="high" if role else "medium", tags=i["tags"]))
    return res


@check(CheckSpec(
    "srv.public-ip", "Instance has a public IP address", "server", "low", ("ec2.instances",),
    covers="Running instances with a public IPv4 address."))
def public_ip(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, insts in ctx.per_region("ec2.instances").items():
        for i in insts:
            if i["state"] == "running" and i["public_ip"]:
                res.findings.append(ctx.finding(
                    {"id": i["id"], "name": i["name"], "region": region, "type": "ec2_instance"},
                    f"{i['name']} has public IP {i['public_ip']}",
                    [("ec2:DescribeInstances", i["id"], f"PublicIpAddress {i['public_ip']}")],
                    {"summary": "Put the instance in a private subnet behind a load balancer "
                                "or use SSM for access."}, tags=i["tags"]))
    return res


@check(CheckSpec(
    "srv.not-ssm-managed", "Instance not managed by SSM", "server", "low",
    ("ec2.instances", "ssm.managed_instances"), references=("AWS FSBP SSM.1",),
    covers="Running instances with no online SSM agent (no patching or session access).",
    false_positives="Instances where SSM is blocked by design (no endpoint, no NAT)."))
def not_ssm(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    managed = ctx.per_region("ssm.managed_instances")
    for region, insts in ctx.per_region("ec2.instances").items():
        if region not in managed:
            continue                     # unseen: the per-collector gap already says so
        for i in insts:
            if i["state"] == "running" and i["id"] not in managed[region]:
                res.findings.append(ctx.finding(
                    {"id": i["id"], "name": i["name"], "region": region, "type": "ec2_instance"},
                    f"{i['name']} has no online SSM agent",
                    [("ssm:DescribeInstanceInformation", i["id"], "not in managed list")],
                    {"summary": "Install the SSM agent and attach AmazonSSMManagedInstanceCore."},
                    tags=i["tags"]))
    return res


@check(CheckSpec(
    "srv.lambda-deprecated-runtime", "Lambda function on a deprecated runtime", "server",
    "medium", ("lambda.functions",), config={"deprecated": DEPRECATED_RUNTIMES},
    covers="Functions whose runtime no longer receives security patches.",
    does_not_cover="Container-image functions (no runtime field)."))
def lambda_runtime(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    bad = set(ctx.config.get("deprecated", DEPRECATED_RUNTIMES))
    for region, fns in ctx.per_region("lambda.functions").items():
        for f in fns:
            if f["runtime"] in bad:
                res.findings.append(ctx.finding(
                    {"id": f["arn"], "name": f["name"], "region": region, "type": "lambda_function"},
                    f"{f['name']} runs on {f['runtime']}",
                    [("lambda:ListFunctions", f["arn"], f"Runtime {f['runtime']}")],
                    {"summary": "Upgrade to a supported runtime."}))
    return res


@check(CheckSpec(
    "srv.eks-public-endpoint", "EKS API endpoint open to the internet", "server", "medium",
    ("eks.clusters",), references=("CIS EKS 5.4.2",),
    covers="Clusters with a public endpoint allowing 0.0.0.0/0."))
def eks_public(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, clusters in ctx.per_region("eks.clusters").items():
        for c in clusters:
            if c["denied"]:
                res.gaps.append(ctx.gap(f"EKS cluster {c['name']}", c["denied"],
                                        ["eks:DescribeCluster"], region))
            elif c["endpoint_public"] and (not c["public_cidrs"] or "0.0.0.0/0" in c["public_cidrs"]):
                res.findings.append(ctx.finding(
                    {"id": c["arn"], "name": c["name"], "region": region, "type": "eks_cluster"},
                    f"EKS cluster {c['name']} API is reachable from anywhere",
                    [("eks:DescribeCluster", c["arn"], "endpointPublicAccess, 0.0.0.0/0")],
                    {"summary": "Disable the public endpoint or restrict publicAccessCidrs."}))
    return res


@check(CheckSpec(
    "srv.rds-publicly-accessible", "RDS instance is publicly accessible", "server", "high",
    ("rds.instances",), references=("AWS FSBP RDS.2",),
    covers="DB instances with PubliclyAccessible=true (a public DNS name and IP)."))
def rds_public(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, payload in ctx.per_region("rds.instances").items():
        for d in payload["instances"]:
            if d["public"]:
                res.findings.append(ctx.finding(
                    {"id": d["arn"] or d["id"], "name": d["id"], "region": region,
                     "type": "rds_instance"},
                    f"RDS {d['id']} is publicly accessible",
                    [("rds:DescribeDBInstances", d["id"], "PubliclyAccessible=true")],
                    {"summary": "Set PubliclyAccessible=false and reach it from inside the VPC."},
                    tags=d["tags"]))
    return res


@check(CheckSpec(
    "srv.rds-auto-minor-upgrade-off", "RDS minor version upgrades are disabled", "server",
    "low", ("rds.instances",), references=("AWS FSBP RDS.13",),
    covers="DB instances that will not take engine security patches automatically.",
    does_not_cover="Whether the current version has known CVEs (tier 2)."))
def rds_upgrade(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, payload in ctx.per_region("rds.instances").items():
        for d in payload["instances"]:
            if not d["auto_minor_upgrade"]:
                res.findings.append(ctx.finding(
                    {"id": d["arn"] or d["id"], "name": d["id"], "region": region,
                     "type": "rds_instance"},
                    f"RDS {d['id']} ({d['engine']} {d['version']}) does not auto-apply minor upgrades",
                    [("rds:DescribeDBInstances", d["id"], "AutoMinorVersionUpgrade=false")],
                    {"summary": "Enable auto minor version upgrade."}, tags=d["tags"]))
    return res
