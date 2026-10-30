"""B3 tier-0 checks: the five MVP gaps of the requirements' catalogue (API Gateway auth,
outdated AMIs, RDS engine versions, open OpenSearch, activity in unused regions) and six
picked for the attack graph and CIS coverage. Inputs come from `collectors_extra.py`, plus
existing collectors where those already hold what is needed."""
from __future__ import annotations

from datetime import datetime

from ...core.model import INTERNET, CheckResult, Node
from ..collectors_extra import s3_bucket_of
from ..policy import is_full_admin, public_statements, statements
from . import CheckSpec, check
from .identity import ADMIN_POLICY_ARNS, _policy_docs
from .server import _profile_roles


def _when(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _bucket_public(b: dict, account_bpa: dict | None) -> list[tuple]:
    """Evidence that a bucket is public, as data.s3-public-bucket decides it ([] if not)."""
    bpa = {k: ((account_bpa or {}).get(k) or (b["bpa"] or {}).get(k))
           for k in ("IgnorePublicAcls", "RestrictPublicBuckets")}
    ev = []
    if (b["policy_is_public"] or public_statements(b["policy"])) and not bpa["RestrictPublicBuckets"]:
        ev.append(("s3:GetBucketPolicyStatus", b["arn"], "policy grants access to everyone"))
    if b["public_acl_grants"] and not bpa["IgnorePublicAcls"]:
        ev.append(("s3:GetBucketAcl", b["arn"], f"AllUsers: {','.join(b['public_acl_grants'])}"))
    return ev


# ---------------------------------------------------------------- 1. API Gateway
def _api_arn(region, a):
    return f"arn:aws:apigateway:{region}::/{'restapis' if a['kind'] == 'rest' else 'apis'}/{a['id']}"


@check(CheckSpec(
    "net.apigw-no-auth", "API Gateway route callable without authentication", "network",
    "high", ("apigw.apis", "lambda.functions"),
    covers="REST API methods with authorization NONE and no API key on a non-private "
           "endpoint, and HTTP API routes with no authorizer. Emits internet -> API -> "
           "integration Lambda, and (as for an auth-NONE function URL) the Lambda's role as "
           "a `possible` exposure.",
    does_not_cover="WebSocket APIs; authorization done inside the backend code; WAF rules; "
                   "integrations other than Lambda (HTTP proxies, AWS service integrations) "
                   "get the internet -> API edge only.",
    false_positives="Intentionally public endpoints (health checks, public read APIs, webhooks "
                    "that verify a signature in code): tag the API scanner:accepted-risk. A "
                    "REST resource policy that limits callers by IP makes the reach `possible`, "
                    "not absent."))
def apigw_no_auth(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, apis in ctx.per_region("apigw.apis").items():
        roles = {f["arn"]: f["role"] for f in ctx.per_region("lambda.functions").get(region) or []}
        for a in apis:
            if a["denied"]:
                res.gaps.append(ctx.gap(f"routes of API {a['name'] or a['id']}", a["denied"],
                                        ["apigateway:GET"], region))
            if not a["public"] or not a["open"]:
                continue
            arn = _api_arn(region, a)
            # A resource policy that does not openly allow everyone may limit callers (by IP,
            # VPC endpoint): not evaluated, so the reach is `possible`, never absent.
            conds = (["resource policy may restrict callers; not evaluated"]
                     if a["policy"] and not public_statements(a["policy"]) else [])
            routes = [o["route"] for o in a["open"]]
            ev = [("apigateway:GET", arn, f"no authorizer on {', '.join(routes[:10])}"
                   + (f" (+{len(routes) - 10} more)" if len(routes) > 10 else ""))]
            res.nodes.append(Node(arn, "api_gateway", ctx.account, region, a["name"], a["tags"],
                                  ["entry_point"]))
            res.facts.append(ctx.fact(INTERNET, "reaches", arn, ev, {"protocol": "https", "ports": [443]},
                                      conds, 0.95))
            for fn in sorted({o["target"] for o in a["open"] if o["target"]}):
                fev = [("apigateway:GET", arn, f"integration -> {fn}")]
                res.facts.append(ctx.fact(arn, "reaches", fn, fev, {"via": "integration"}, conds, 0.95))
                if roles.get(fn):
                    res.facts.append(ctx.fact(fn, "exposes_credentials", roles[fn], fev,
                                              {"via": "public-code"},
                                              ["assumes a flaw in code anyone can invoke"], 0.5))
            res.findings.append(ctx.finding(
                {"id": arn, "name": a["name"], "region": region, "type": "api_gateway"},
                f"API {a['name'] or a['id']} has {len(routes)} route(s) callable without "
                "authentication", ev,
                {"summary": "Add an authorizer (IAM, Cognito, JWT or Lambda) or require an API "
                            "key with a usage plan; make internal APIs PRIVATE."},
                tags=a["tags"]))
    return res


# ---------------------------------------------------------------- 2. AMI age
@check(CheckSpec(
    "srv.ami-outdated", "Instance runs from an old, deprecated or deregistered AMI", "server",
    "low", ("ec2.instances", "ec2.instance_images"), config={"max_age_days": 180},
    covers="Running instances whose image is older than max_age_days, past its deprecation "
           "time, or no longer returned by DescribeImages (deregistered).",
    does_not_cover="Whether the instance was patched after launch (see tier 2 and SSM patch "
                   "compliance); the age of the OS inside a custom image built from an old base.",
    false_positives="Golden images rebuilt in place under a new id are fine; an image its owner "
                    "stopped sharing looks deregistered. Long-lived, patched hosts: raise "
                    "max_age_days or accept the risk by tag."))
def ami_outdated(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    max_days = int(ctx.config.get("max_age_days", 180))
    for region, insts in ctx.per_region("ec2.instances").items():
        p = ctx.per_region("ec2.instance_images").get(region)
        if p is None:
            continue                                   # the per-collector gap says so
        if p["denied"]:
            res.gaps.append(ctx.gap(f"some AMIs in {region}", p["denied"], ["ec2:DescribeImages"], region))
        for i in insts:
            if i["state"] != "running" or i["image_id"] not in p["images"]:
                continue
            img = p["images"][i["image_id"]]
            res_ = {"id": i["id"], "name": i["name"], "region": region, "type": "ec2_instance"}
            if img is None:
                reason, detail, sev = "deregistered", "image no longer exists", "medium"
            elif _when(img["deprecation"]) and _when(img["deprecation"]) <= ctx.now:
                reason, detail, sev = "deprecated", f"deprecated {img['deprecation'][:10]}", "medium"
            elif _when(img["created"]) and (ctx.now - _when(img["created"])).days > max_days:
                reason, sev = "age", None
                detail = f"created {img['created'][:10]}, {(ctx.now - _when(img['created'])).days} days old"
            else:
                continue
            res.findings.append(ctx.finding(
                res_, f"{i['name']} runs from {reason} AMI {i['image_id']}",
                [("ec2:DescribeImages", i["image_id"], detail)],
                {"summary": "Rebuild the instance from a current, patched image (or an image "
                            "pipeline that does so on a schedule)."},
                severity=sev, qualifiers={"reason": reason}, tags=i["tags"]))
    return res


# ---------------------------------------------------------------- 3. RDS engine version
@check(CheckSpec(
    "srv.rds-engine-outdated", "RDS/Aurora engine version is behind or past standard support",
    "server", "low", ("rds.engine_versions",), references=("AWS FSBP RDS.35",),
    covers="DB instances and Aurora clusters for which AWS offers a newer minor version "
           "(DescribeDBEngineVersions ValidUpgradeTarget), and those whose major version is "
           "past the end of standard support (DescribeDBMajorEngineVersions), i.e. on paid "
           "extended support or due for a forced upgrade. No version list is kept here.",
    does_not_cover="Which CVEs the version has (tier 2); engines without lifecycle data "
                   "(commercial engines) get the minor-version part only.",
    false_positives="A newer minor version released in the last days, not yet scheduled. "
                    "Pinned versions for application compatibility: accept the risk by tag."))
def rds_engine_outdated(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, p in ctx.per_region("rds.engine_versions").items():
        if p.get("clusters_denied"):
            res.gaps.append(ctx.gap(f"Aurora clusters in {region}", p["clusters_denied"],
                                    ["rds:DescribeDBClusters"], region))
        for d in p["dbs"]:
            v = p["versions"].get(f"{d['engine']}|{d['version']}") or {}
            rid = {"id": d["arn"] or d["id"], "name": d["id"], "region": region,
                   "type": "rds_instance" if d["kind"] == "instance" else "rds_cluster"}
            if v.get("denied") or not v:
                res.gaps.append(ctx.gap(f"versions for {d['engine']} {d['version']}",
                                        v.get("denied") or "not returned",
                                        ["rds:DescribeDBEngineVersions"], region))
            elif v["upgrades"]:
                res.findings.append(ctx.finding(
                    rid, f"{d['id']} runs {d['engine']} {d['version']}; {v['upgrades'][-1]} is available",
                    [("rds:DescribeDBEngineVersions", f"{d['engine']} {d['version']}",
                      f"minor upgrades: {', '.join(v['upgrades'][-5:])}")],
                    {"summary": "Apply the latest minor version in the next maintenance window "
                                "(or turn on auto minor version upgrade)."},
                    qualifiers={"reason": "minor-behind"}, tags=d["tags"]))
            major = v.get("major")
            if not major:
                continue
            s = p["support"].get(f"{d['engine']}|{major}")
            if s is None or s.get("denied"):
                res.gaps.append(ctx.gap(f"support dates of {d['engine']} {major}",
                                        (s or {}).get("denied") or "not collected",
                                        ["rds:DescribeDBMajorEngineVersions"], region))
            elif _when(s["standard_end"]) and _when(s["standard_end"]) <= ctx.now:
                res.findings.append(ctx.finding(
                    rid, f"{d['id']} ({d['engine']} {major}) is past the end of standard support",
                    [("rds:DescribeDBMajorEngineVersions", f"{d['engine']} {major}",
                      f"standard support ended {s['standard_end'][:10]}"
                      + (f"; lifecycle {d['lifecycle']}" if d["lifecycle"] else ""))],
                    {"summary": "Upgrade to a supported major version; extended support is "
                                "charged per vCPU-hour and gets critical fixes only."},
                    severity="medium", qualifiers={"reason": "extended-support"}, tags=d["tags"]))
    return res


# ---------------------------------------------------------------- 4. OpenSearch
@check(CheckSpec(
    "data.opensearch-open", "OpenSearch domain open to anyone", "data", "high",
    ("opensearch.domains",), references=("AWS FSBP Opensearch.2",),
    covers="Domains with a public (non-VPC) endpoint whose access policy allows Principal * "
           "with no IP, VPC endpoint, account or org condition, unless fine-grained access "
           "control requires sign-in (anonymous auth off).",
    does_not_cover="Kibana/Dashboards Cognito settings; users inside the internal user "
                   "database; legacy Elasticsearch domains are covered only through the same "
                   "OpenSearch API.",
    false_positives="Conditions this reader does not know (custom keys) are treated as not "
                    "restricting, so such a policy is reported."))
def opensearch_open(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, doms in ctx.per_region("opensearch.domains").items():
        for d in doms:
            if d["denied"]:
                res.gaps.append(ctx.gap(f"OpenSearch domain {d['name']}", d["denied"],
                                        ["es:DescribeDomains"], region))
                continue
            pub = public_statements(d["policy"])
            if d["vpc"] or not pub or (d["fgac"] and not d["anonymous"]):
                continue
            ev = [("es:DescribeDomains", d["arn"], "public endpoint, access policy Principal * "
                   "without a restricting condition" + ("; anonymous auth on" if d["anonymous"] else ""))]
            res.nodes.append(Node(d["arn"], "opensearch_domain", ctx.account, region, d["name"]))
            res.facts.append(ctx.fact(INTERNET, "is_public", d["arn"], ev, confidence=0.95))
            res.findings.append(ctx.finding(
                {"id": d["arn"], "name": d["name"], "region": region, "type": "opensearch_domain"},
                f"OpenSearch domain {d['name']} is open to anyone", ev,
                {"summary": "Move the domain into a VPC, or restrict the access policy to named "
                            "principals or source IPs and turn on fine-grained access control."}))
    return res


# ---------------------------------------------------------------- 5. activity in unused regions
USAGE_KEYS = ("ec2.instances", "lambda.functions", "rds.instances", "elbv2.load_balancers",
              "ec2.vpcs")


def _region_in_use(ctx, region) -> bool | None:
    """True if any workload or non-default VPC is there, None if an input is unreadable."""
    seen = []
    for k in USAGE_KEYS:
        p = ctx.per_region(k).get(region)
        if p is None:
            return None
        if k == "rds.instances":
            seen.append(bool(p["instances"]))
        elif k == "ec2.vpcs":
            seen.append(any(not v["default"] for v in p["vpcs"]))
        else:
            seen.append(bool(p))
    return any(seen)


@check(CheckSpec(
    "log.activity-in-unused-regions", "Write activity in a region with no resources",
    "logging", "medium", ("cloudtrail.write_events",) + USAGE_KEYS,
    covers="Regions with no instances, functions, databases, load balancers or non-default "
           "VPCs where CloudTrail LookupEvents shows management write events by people or "
           "roles in the last 7 days (capped at 150 events a region). Reported as possibly "
           "unexpected, with counts and a sample.",
    does_not_cover="Resource types other than those listed (a region holding only an S3-less "
                   "SQS queue counts as unused); data events; global-service events (IAM, STS, "
                   "CloudFront, Route 53), which AWS logs in us-east-1.",
    false_positives="Short-lived experiments, infrastructure-as-code that creates then deletes, "
                    "and service-linked setup not marked as AWSService. Read the sample."))
def activity_unused_regions(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, w in ctx.per_region("cloudtrail.write_events").items():
        used = _region_in_use(ctx, region)
        if used is None:
            res.gaps.append(ctx.gap(f"whether {region} is in use", "an inventory input is missing",
                                    [], region))
            continue
        if used or not w["events"]:
            continue
        top = sorted(w["by_name"].items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        ev = [("cloudtrail:LookupEvents", region,
               f"{w['events']}{'+' if w['capped'] else ''} write event(s) in {w['window_days']} days: "
               + ", ".join(f"{k} x{n}" for k, n in top))]
        ev += [("cloudtrail:LookupEvents", s["name"], f"{s['time']} {s['source']} by {s['user'] or '?'}")
               for s in w["sample"]]
        res.findings.append(ctx.finding(
            {"id": f"region/{region}", "name": region, "region": region, "type": "account"},
            f"Possibly unexpected write activity in unused region {region}", ev,
            {"summary": "Confirm who made these calls. If the region is not used, deny it with an "
                        "SCP (aws:RequestedRegion) and look for resources left behind."},
            confidence=0.6))
    return res


# ---------------------------------------------------------------- 6. dangling DNS
@check(CheckSpec(
    "net.dangling-dns", "DNS record points at a resource that is not yours", "network", "high",
    ("route53.records", "cloudfront.distributions", "s3.buckets"),
    covers="CNAME and alias records in public Route 53 zones pointing at an S3 endpoint whose "
           "bucket no account holds (anyone can create it: subdomain takeover) or that another "
           "account holds, and at a CloudFront distribution not in this account. Emits "
           "internet -can_write-> the name.",
    does_not_cover="A/AAAA records to released Elastic IPs (telling an AWS IP from any other "
                   "needs AWS's published ranges, which a read-only API scan does not fetch); "
                   "DNS hosted outside Route 53; Elastic Beanstalk, Azure or Heroku targets.",
    false_positives="A bucket or distribution in another account of yours (S3 does not reveal "
                    "a bucket's owner): delete the finding's cause or accept the risk."))
def dangling_dns(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    p = ctx.glob("route53.records")
    if p is None:
        return res
    dists = ctx.glob("cloudfront.distributions")
    s3 = ctx.glob("s3.buckets")
    mine_cf = {d["domain"].rstrip(".").lower() for d in dists or []}
    mine_s3 = {b["name"] for b in (s3 or {}).get("buckets", [])}
    for r in p["records"]:
        name = r["name"].rstrip(".").lower()
        for target in r["values"] + ([r["alias"]] if r["alias"] else []):
            t = target.rstrip(".").lower()
            bucket = s3_bucket_of(name, t)
            if bucket:
                if s3 is None or bucket in mine_s3:
                    continue
                state = p["bucket_exists"].get(bucket)
                if state is None:
                    res.gaps.append(ctx.gap(f"bucket {bucket} behind {name}", "not checked",
                                            ["s3:ListAllMyBuckets"]))
                    continue
                kind, conf, sev = "s3", (0.9 if state == "missing" else 0.4), \
                    (None if state == "missing" else "medium")
                detail = f"{r['type']} -> {t}; bucket {bucket} " + (
                    "does not exist (anyone can create it)" if state == "missing"
                    else "exists in another account")
            elif t.endswith(".cloudfront.net"):
                if dists is None or t in mine_cf:
                    continue
                kind, conf, sev = "cloudfront", 0.3, "medium"
                detail = f"{r['type']} -> {t}; no distribution in this account has that domain"
            else:
                continue
            rec = f"dns:{name}"
            ev = [("route53:ListResourceRecordSets", f"{r['zone']}/{name}", detail)]
            res.nodes.append(Node(rec, "dns_record", ctx.account, name=name))
            res.facts.append(ctx.fact(INTERNET, "can_write", rec, ev, {"via": f"dangling-{kind}"},
                                      ["assumes an attacker can claim the target name"], conf))
            res.findings.append(ctx.finding(
                {"id": rec, "name": name, "type": "dns_record"},
                f"{name} points at {'a missing' if sev is None else 'a foreign'} {kind} target", ev,
                {"summary": "Delete the record, or recreate the resource it points to in this "
                            "account before anyone else does."},
                severity=sev, qualifiers={"target": kind, "value": t}))
    return res


# ---------------------------------------------------------------- 7. CloudFront origin
@check(CheckSpec(
    "data.cloudfront-origin-exposed", "CloudFront S3 origin readable around the distribution",
    "data", "medium", ("cloudfront.distributions", "s3.buckets"),
    covers="S3 origins (REST or website endpoint) whose bucket is public, or that use neither "
           "origin access control nor an origin access identity while the bucket policy "
           "allows Principal * (e.g. a Referer condition, which anyone can forge).",
    does_not_cover="Origins in other accounts (reported as gaps); custom (non-S3) origins; "
                   "signed URLs and geo restriction.",
    false_positives="Buckets meant to be public as well as served by CloudFront: accept the "
                    "risk by tag."))
def cloudfront_origin(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    dists, s3 = ctx.glob("cloudfront.distributions"), ctx.glob("s3.buckets")
    if dists is None or s3 is None:
        return res
    by_name = {b["name"]: b for b in s3["buckets"]}
    for d in dists:
        for o in d["origins"]:
            bucket = s3_bucket_of("", o["domain"])
            if not bucket:
                continue
            b = by_name.get(bucket)
            if b is None:
                res.gaps.append(ctx.gap(f"origin bucket {bucket} of {d['id']}",
                                        "bucket not in this account", ["s3:GetBucketPolicy"]))
                continue
            if b["policy_denied"]:
                res.gaps.append(ctx.gap(f"policy of origin bucket {bucket}", b["policy_denied"],
                                        ["s3:GetBucketPolicy"]))
            ev = _bucket_public(b, s3.get("account_bpa"))
            star = [st for st in statements(b["policy"]) if st.get("Effect") == "Allow"
                    and (st.get("Principal") == "*" or "*" in str((st.get("Principal") or {}).get("AWS", "")))]
            if not ev and not (o["oac"] or o["oai"]) and star:
                ev = [("s3:GetBucketPolicy", b["arn"], "Principal * with a condition, and the "
                       "origin has no OAC/OAI")]
            if not ev:
                continue
            res.findings.append(ctx.finding(
                {"id": b["arn"], "name": bucket, "region": b["region"], "type": "s3_bucket"},
                f"Origin bucket {bucket} of {d['id']} can be read without CloudFront",
                [("cloudfront:ListDistributions", d["arn"] or d["id"], f"origin {o['domain']}, "
                  f"OAC {'yes' if o['oac'] else 'no'}, OAI {'yes' if o['oai'] else 'no'}")] + ev,
                {"summary": "Use origin access control, make the bucket private, and allow only "
                            "the distribution (aws:SourceArn) in the bucket policy."},
                qualifiers={"distribution": d["id"]}, tags=b["tags"]))
    return res


# ---------------------------------------------------------------- 8. instance with admin role
@check(CheckSpec(
    "iam.instance-admin-role", "Running instance has an administrator role", "identity",
    "high", ("ec2.instances", "iam.authorization_details"),
    covers="Running instances whose instance profile's role has AdministratorAccess or an "
           "Allow *:* policy (the same test as iam.admin-principals). Emits instance -runs_as-> "
           "role, which the graph follows from hosts marked assume_compromised.",
    does_not_cover="Roles that are admin through escalation only (iam.privilege-escalation); "
                   "permission boundaries and SCPs (not evaluated).",
    false_positives="Short-lived build or bootstrap hosts that need admin: accept the risk by "
                    "tag. With no assume_compromised host and no other route to the role, the "
                    "graph lowers it to medium."))
def instance_admin_role(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    auth = ctx.glob("iam.authorization_details")
    if auth is None:
        return res
    admin_roles = {}
    for r in auth.get("RoleDetailList", []):
        src = next((s for s, d in _policy_docs(auth, r, "role") if s in ADMIN_POLICY_ARNS
                    or ("__aws_managed__" not in d and is_full_admin(d))), None)
        if src:
            admin_roles[r["Arn"]] = src
    roles = _profile_roles(ctx)
    for region, insts in ctx.per_region("ec2.instances").items():
        for i in insts:
            role = roles.get(i["profile_arn"])
            if i["state"] != "running" or role not in admin_roles:
                continue
            ev = [("ec2:DescribeInstances", i["id"], f"profile {i['profile_arn']}"),
                  ("iam:GetAccountAuthorizationDetails", role, f"{admin_roles[role]} grants *:*")]
            res.nodes.append(Node(i["id"], "ec2_instance", ctx.account, region, i["name"], i["tags"]))
            res.facts.append(ctx.fact(i["id"], "runs_as", role, ev, {"role": "admin"}))
            res.findings.append(ctx.finding(
                {"id": i["id"], "name": i["name"], "region": region, "type": "ec2_instance"},
                f"{i['name']} runs with administrator role {role.split('/')[-1]}", ev,
                {"summary": "Give the instance a role scoped to what it does; anyone who runs "
                            "code on it holds the whole account."}, tags=i["tags"]))
    return res


# ---------------------------------------------------------------- 9. Access Analyzer
EDGE_BY_TYPE = {"AWS::IAM::Role": "can_assume", "AWS::Lambda::Function": "can_execute_on"}
WRITE_VERBS = ("put", "delete", "create", "update", "write", "*", "sendmessage", "publish",
               "invoke")


def _aa_edge(f) -> str:
    if f["resource_type"] in EDGE_BY_TYPE:
        return EDGE_BY_TYPE[f["resource_type"]]
    acts = [a.split(":")[-1].lower() for a in f["action"]]
    return "can_write" if any(a.startswith(WRITE_VERBS) for a in acts) else "can_read"


def _aa_source(principal: dict) -> tuple[str, str]:
    """(node id, account) for the principal of an Access Analyzer finding."""
    aws = principal.get("AWS")
    if aws:
        acct = aws if aws.isdigit() else (aws.split(":")[4] if aws.count(":") >= 4 else aws)
        return f"external:{acct}", acct
    fed = principal.get("Federated")
    return (f"federated:{fed}", "") if fed else ("", "")


@check(CheckSpec(
    "iam.access-analyzer-external", "Resource shared outside the account (Access Analyzer)",
    "identity", "high", ("accessanalyzer.findings",),
    covers="Active external-access findings of IAM Access Analyzer (account or organization "
           "zone of trust), one finding each. Emits external principal -> resource "
           "(can_assume for roles, can_execute_on for functions, can_read/can_write by action) "
           "or internet -is_public-> resource. A region with no active analyzer is a gap.",
    does_not_cover="Unused-access findings; archived findings (your archive rules decide); "
                   "regions where the analyzer is off (gap); more than 500 findings a region.",
    false_positives="Intended third-party access: archive the finding in Access Analyzer with a "
                    "rule, and it leaves this report."))
def access_analyzer_external(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, p in ctx.per_region("accessanalyzer.findings").items():
        if not any(a["status"] == "ACTIVE" for a in p["analyzers"]):
            res.gaps.append(ctx.gap(f"Access Analyzer in {region}", "no active account or "
                                    "organization analyzer", ["access-analyzer:CreateAnalyzer "
                                                              "(an admin enables it)"], region))
            continue
        if p["capped"]:
            res.gaps.append(ctx.gap(f"Access Analyzer findings in {region} beyond 500", "capped",
                                    [], region))
        for f in p["findings"]:
            ev = [("access-analyzer:ListFindings", f["resource"],
                   f"{f['id']}: {', '.join(f['action'][:5]) or 'access'} to "
                   f"{'everyone' if f['is_public'] else json_principal(f['principal'])}")]
            conds = sorted(f"{k}" for k in f["condition"]) if f["condition"] else []
            if f["is_public"]:
                src, typ = INTERNET, "is_public"
            else:
                src, acct = _aa_source(f["principal"])
                typ = _aa_edge(f)
                if src:
                    res.nodes.append(Node(src, "external_principal", acct, labels=["entry_point"]))
            if src:
                res.facts.append(ctx.fact(src, typ, f["resource"], ev, {"via": "access-analyzer"},
                                          conds, 0.9))
            res.findings.append(ctx.finding(
                {"id": f["resource"], "name": f["resource"].split(":")[-1].split("/")[-1],
                 "region": region, "type": f["resource_type"]},
                f"{f['resource_type']} {f['resource'].split(':')[-1]} is accessible "
                f"{'publicly' if f['is_public'] else 'from outside the account'}", ev,
                {"summary": "Remove the external grant from the resource policy, or archive the "
                            "Access Analyzer finding if the access is intended."},
                severity="critical" if f["is_public"] else None, qualifiers={"aa_id": f["id"]}))
    return res


def json_principal(p: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(p.items()))


# ---------------------------------------------------------------- 10. KMS rotation
@check(CheckSpec(
    "log.kms-rotation-off", "Customer-managed KMS key rotation is off", "logging", "low",
    ("kms.key_rotation",), references=("CIS 3.6",),
    covers="Enabled customer-managed symmetric keys with AWS-generated key material whose "
           "automatic rotation is off.",
    does_not_cover="Asymmetric and HMAC keys, imported key material and custom key stores "
                   "(AWS cannot rotate them); AWS-managed keys (rotated by AWS).",
    false_positives="Keys rotated manually by alias swap: accept the risk on the key."))
def kms_rotation(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, keys in ctx.per_region("kms.key_rotation").items():
        for k in keys:
            if k["spec"] != "SYMMETRIC_DEFAULT" or k["origin"] != "AWS_KMS":
                continue
            if k["rotation_denied"] or k["rotation"] is None:
                res.gaps.append(ctx.gap(f"rotation status of {k['arn']}",
                                        k["rotation_denied"] or "not returned",
                                        ["kms:GetKeyRotationStatus"], region))
            elif k["rotation"] is False:
                res.findings.append(ctx.finding(
                    {"id": k["arn"], "name": k["id"], "region": region, "type": "kms_key"},
                    f"KMS key {k['id']} has automatic rotation off",
                    [("kms:GetKeyRotationStatus", k["arn"], "KeyRotationEnabled=false")],
                    {"summary": "Enable automatic key rotation.",
                     "cli": f"aws kms enable-key-rotation --region {region} --key-id {k['id']}"}))
    return res


# ---------------------------------------------------------------- 11. CloudTrail integrity
@check(CheckSpec(
    "log.cloudtrail-integrity", "CloudTrail logs can be altered or read by anyone", "logging",
    "medium", ("cloudtrail.trail_integrity", "s3.buckets"), references=("CIS 3.2", "CIS 3.3"),
    covers="Every trail (not only multi-region ones) without log file validation, and trails "
           "whose S3 bucket is public by policy or ACL.",
    does_not_cover="Buckets in another account, e.g. an organization's log archive (a gap); "
                   "object lock, MFA delete and bucket access logging.",
    false_positives="None known for validation. log.cloudtrail-not-multiregion also reports "
                    "validation off on multi-region trails (low); the two share the cause."))
def cloudtrail_integrity(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    trails, s3 = ctx.glob("cloudtrail.trail_integrity"), ctx.glob("s3.buckets")
    if trails is None:
        return res
    by_name = {b["name"]: b for b in (s3 or {}).get("buckets", [])}
    for t in trails:
        rid = {"id": t["arn"], "name": t["name"], "region": t["home"], "type": "cloudtrail_trail"}
        if not t["validation"]:
            res.findings.append(ctx.finding(
                rid, f"Trail {t['name']} has log file validation off",
                [("cloudtrail:DescribeTrails", t["arn"], "LogFileValidationEnabled=false")],
                {"summary": "Enable log file validation so tampering with delivered logs is "
                            "detectable.",
                 "cli": f"aws cloudtrail update-trail --name {t['arn']} --enable-log-file-validation"},
                qualifiers={"aspect": "validation"}))
        if s3 is None:
            continue
        b = by_name.get(t["bucket"])
        if b is None:
            res.gaps.append(ctx.gap(f"bucket {t['bucket']} of trail {t['name']}",
                                    "bucket not in this account", ["s3:GetBucketPolicy"]))
            continue
        ev = _bucket_public(b, s3.get("account_bpa"))
        if ev:
            res.findings.append(ctx.finding(
                rid, f"Trail {t['name']} delivers to public bucket {b['name']}", ev,
                {"summary": "Make the log bucket private (Block Public Access) and restrict its "
                            "policy to CloudTrail and your auditors."},
                severity="high", qualifiers={"aspect": "bucket-public"}))
    return res
