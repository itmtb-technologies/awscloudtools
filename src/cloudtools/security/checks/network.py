"""net.*: ports and network (requirements check catalogue, MVP)."""
from __future__ import annotations

from ...core.model import INTERNET, CheckResult, Node
from ..reach import instance_reach, nacl_allows_world, region_index, sg_world_ports
from . import CheckSpec, check

ADMIN_PORTS = [22, 3389, 3306, 5432, 6379, 27017, 9200, 1433, 5984, 11211]
SG_KEYS = ("ec2.security_groups", "ec2.network_acls", "ec2.route_tables", "ec2.instances")


def _sg_res(sg, region):
    return {"id": sg["id"], "name": sg["name"], "region": region, "type": "security_group"}


@check(CheckSpec(
    "net.open-admin-ports", "Admin ports open to the internet", "network", "high", SG_KEYS,
    config={"ports": ADMIN_PORTS, "allow_tag": "scanner:allow-public"},
    references=("CIS 5.2", "CIS 5.3"),
    covers="Security group rules allowing 0.0.0.0/0 or ::/0 to admin/database ports, and "
           "whether a running instance is reachable through route, NACL and public IP.",
    does_not_cover="Ports behind a load balancer (see net.public-lb-listeners); host firewalls.",
    false_positives="Bastions intentionally open: tag scanner:allow-public or accepted-risk."))
def open_admin_ports(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    ports = ctx.config.get("ports", ADMIN_PORTS)
    allow_tag = ctx.config.get("allow_tag", "scanner:allow-public")
    for region, sg_list in ctx.per_region("ec2.security_groups").items():
        sgs, nacl_by_subnet, rt_by_subnet, main_rt = region_index(ctx, region)
        insts = ctx.per_region("ec2.instances").get(region) or []
        for sg in sg_list:
            if allow_tag in sg["tags"]:
                continue
            for port, cidrs in sorted(sg_world_ports(sg, ports).items()):
                attached = [i for i in insts if sg["id"] in i["sgs"]]
                reached = []
                for i in attached:
                    r = instance_reach(i, port, sgs, nacl_by_subnet, rt_by_subnet, main_rt)
                    if r.status == "none":
                        continue
                    reached.append(i["id"])
                    res.nodes.append(Node(i["id"], "ec2_instance", ctx.account, region,
                                          i["name"], i["tags"], ["entry_point"]))
                    res.facts.append(ctx.fact(INTERNET, "reaches", i["id"], r.evidence,
                                              {"protocol": "tcp", "ports": [port]},
                                              r.conditions, 0.95 if r.status == "confirmed" else 0.6))
                sev = "high" if reached else "medium"
                res.findings.append(ctx.finding(
                    _sg_res(sg, region), f"tcp/{port} open to the internet on {sg['name'] or sg['id']}",
                    [("ec2:DescribeSecurityGroups", sg["id"], f"{','.join(cidrs)} -> tcp/{port}")]
                    + [("reachability", i, "instance reachable from internet") for i in reached],
                    {"summary": f"Restrict tcp/{port} to known ranges, or use SSM Session Manager.",
                     "cli": f"aws ec2 revoke-security-group-ingress --region {region} "
                            f"--group-id {sg['id']} --protocol tcp --port {port} --cidr 0.0.0.0/0"},
                    severity=sev, qualifiers={"port": port}, tags=sg["tags"]))
    return res


@check(CheckSpec(
    "net.sg-all-traffic-open", "Security group allows all traffic from the internet",
    "network", "high", ("ec2.security_groups",), references=("CIS 5.2",),
    covers="Ingress rules with protocol -1 (all) from 0.0.0.0/0 or ::/0."))
def sg_all_traffic(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, sgs in ctx.per_region("ec2.security_groups").items():
        for sg in sgs:
            for r in sg["ingress"]:
                if r["proto"] == "-1" and ("0.0.0.0/0" in r["cidrs"] or "::/0" in r["ipv6"]):
                    res.findings.append(ctx.finding(
                        _sg_res(sg, region), f"All traffic open to the internet on {sg['name'] or sg['id']}",
                        [("ec2:DescribeSecurityGroups", sg["id"], "world -> all protocols")],
                        {"summary": "Remove the all-traffic rule; allow only the ports the "
                                    "workload serves."}, tags=sg["tags"]))
                    break
    return res


@check(CheckSpec(
    "net.default-sg-has-rules", "Default security group allows traffic", "network", "low",
    ("ec2.security_groups",), references=("CIS 5.4",),
    covers="Default security groups with any ingress rule (CIS recommends none)."))
def default_sg(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, sgs in ctx.per_region("ec2.security_groups").items():
        for sg in sgs:
            if sg["name"] == "default" and any(r["cidrs"] or r["ipv6"] for r in sg["ingress"]):
                res.findings.append(ctx.finding(
                    _sg_res(sg, region), f"Default security group in {sg['vpc']} allows ingress",
                    [("ec2:DescribeSecurityGroups", sg["id"], "default group with CIDR ingress")],
                    {"summary": "Remove all rules from the default security group; use "
                                "purpose-built groups."}, tags=sg["tags"]))
    return res


@check(CheckSpec(
    "net.nacl-admin-ports-open", "Network ACL allows admin ports from the internet",
    "network", "low", ("ec2.network_acls",), config={"ports": [22, 3389]},
    references=("CIS 5.1",),
    covers="Inbound NACL rules (evaluated in rule order) allowing 22/3389 from the world.",
    false_positives="Most default NACLs allow all; the SG is the real control. Low by design."))
def nacl_admin(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, nacls in ctx.per_region("ec2.network_acls").items():
        for a in nacls:
            open_ports = [p for p in ctx.config.get("ports", [22, 3389]) if nacl_allows_world(a, p)]
            if open_ports and a["subnets"]:
                res.findings.append(ctx.finding(
                    {"id": a["id"], "region": region, "type": "network_acl"},
                    f"NACL {a['id']} allows {', '.join(map(str, open_ports))} from the internet",
                    [("ec2:DescribeNetworkAcls", a["id"], f"allow world -> {open_ports}")],
                    {"summary": "Deny admin ports from 0.0.0.0/0 at the NACL as defence in depth."},
                    qualifiers={"ports": open_ports}))
    return res


OLD_TLS = {"ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-2016-08",
           "ELBSecurityPolicy-TLS-1-0-2015-04", "ELBSecurityPolicy-TLS-1-1-2017-01",
           "ELBSecurityPolicy-FS-2018-06", "ELBSecurityPolicy-FS-1-1-2019-08"}


@check(CheckSpec(
    "net.public-lb-listeners", "Internet-facing load balancers and what they reach",
    "network", "info", ("elbv2.load_balancers",),
    covers="Internet-facing ALB/NLB listeners and their registered targets. Emits the "
           "reaches facts the attack graph uses; findings are informational."))
def public_lbs(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, lbs in ctx.per_region("elbv2.load_balancers").items():
        for lb in lbs:
            if lb["scheme"] != "internet-facing" or not lb["listeners"]:
                continue
            ports = sorted({li["port"] for li in lb["listeners"] if li["port"]})
            ev = [("elasticloadbalancing:DescribeListeners", lb["arn"], f"listeners {ports}")]
            res.nodes.append(Node(lb["arn"], "load_balancer", ctx.account, region, lb["name"],
                                  labels=["entry_point"]))
            res.facts.append(ctx.fact(INTERNET, "reaches", lb["arn"], ev,
                                      {"protocol": "tcp", "ports": ports}, confidence=0.95))
            for t in lb["targets"]:
                res.facts.append(ctx.fact(lb["arn"], "reaches", t["id"],
                                          [("elasticloadbalancing:DescribeTargetHealth", t["id"],
                                            f"target port {t['port']}")],
                                          {"protocol": "tcp", "ports": [t["port"]]}, confidence=0.9))
            res.findings.append(ctx.finding(
                {"id": lb["arn"], "name": lb["name"], "region": region, "type": "load_balancer"},
                f"Internet-facing load balancer {lb['name']} on {ports}", ev,
                {"summary": "Confirm this load balancer is meant to be public; put a WAF in front."}))
    return res


@check(CheckSpec(
    "net.lb-outdated-tls", "Load balancer listener uses an outdated TLS policy", "network",
    "medium", ("elbv2.load_balancers",), config={"outdated_policies": sorted(OLD_TLS)},
    covers="HTTPS/TLS listeners on policies allowing TLS 1.0/1.1."))
def lb_tls(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    old = set(ctx.config.get("outdated_policies", OLD_TLS))
    for region, lbs in ctx.per_region("elbv2.load_balancers").items():
        for lb in lbs:
            for li in lb["listeners"]:
                if li["protocol"] in ("HTTPS", "TLS") and li["ssl_policy"] in old:
                    res.findings.append(ctx.finding(
                        {"id": lb["arn"], "name": lb["name"], "region": region, "type": "load_balancer"},
                        f"{lb['name']}:{li['port']} uses {li['ssl_policy']}",
                        [("elasticloadbalancing:DescribeListeners", lb["arn"], li["ssl_policy"])],
                        {"summary": "Switch to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer."},
                        qualifiers={"port": li["port"]}))
    return res


@check(CheckSpec(
    "net.lambda-url-no-auth", "Lambda function URL without authentication", "network",
    "high", ("lambda.functions",),
    covers="Function URLs with AuthType NONE (anyone on the internet can invoke).",
    false_positives="Public webhooks that verify a signature in code: accept the risk by tag."))
def lambda_url(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, fns in ctx.per_region("lambda.functions").items():
        for f in fns:
            if f["url_denied"]:
                res.gaps.append(ctx.gap(f"function URL config of {f['name']}", f["url_denied"],
                                        ["lambda:ListFunctionUrlConfigs"], region))
            if "NONE" in f["url_auth"]:
                ev = [("lambda:ListFunctionUrlConfigs", f["arn"], "AuthType NONE")]
                res.nodes.append(Node(f["arn"], "lambda_function", ctx.account, region, f["name"],
                                      labels=["entry_point"]))
                res.facts.append(ctx.fact(INTERNET, "reaches", f["arn"], ev,
                                          {"protocol": "https", "ports": [443]}, confidence=0.95))
                if f["role"]:
                    # Code anyone can invoke without signing in is assumed to have a flaw
                    # sooner or later, which hands over its role. Unlike an instance that is
                    # merely reachable, so a `possible` edge rather than `runs_as`.
                    res.facts.append(ctx.fact(f["arn"], "exposes_credentials", f["role"], ev,
                                              {"via": "public-code"},
                                              ["assumes a flaw in code anyone can invoke"], 0.5))
                res.findings.append(ctx.finding(
                    {"id": f["arn"], "name": f["name"], "region": region, "type": "lambda_function"},
                    f"Function URL of {f['name']} needs no authentication", ev,
                    {"summary": "Set the function URL AuthType to AWS_IAM, or remove the URL."}))
    return res
