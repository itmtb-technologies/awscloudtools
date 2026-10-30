"""Collectors for the B3 tier-0 checks (`checks/extra.py`). Same rules as `collectors.py`:
normalised payloads, read-only clients, per-item denials kept as `*_denied` markers so a
check reports a gap instead of a pass.

Where an existing collector already reads a service but not the field a check needs
(`kms.keys` has no key spec or origin; `cloudtrail.trails` has no bucket), a new key here
reads it rather than changing that collector's payload.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from ..core.collect import GLOBAL, collector
from .collectors import _pages, _policy, _tags, _try

# One cheap read per collector; doctor.probe_for() finds them here at run time.
PROBES = {
    "apigw.apis": ("apigateway", "get_rest_apis", {"limit": 1}),
    "ec2.instance_images": ("ec2", "describe_images", {"Owners": ["self"], "MaxResults": 5}),
    "rds.engine_versions": ("rds", "describe_db_engine_versions",
                            {"Engine": "postgres", "MaxRecords": 20}),
    "opensearch.domains": ("opensearch", "list_domain_names", {}),
    "cloudtrail.write_events": ("cloudtrail", "lookup_events", {"MaxResults": 1}),
    "route53.records": ("route53", "list_hosted_zones", {"MaxItems": "1"}),
    "cloudfront.distributions": ("cloudfront", "list_distributions", {"MaxItems": "1"}),
    "accessanalyzer.findings": ("accessanalyzer", "list_analyzers", {"maxResults": 1}),
    "kms.key_rotation": ("kms", "list_keys", {"Limit": 1}),
    "cloudtrail.trail_integrity": ("cloudtrail", "describe_trails", {}),
}


def _iso(v) -> str | None:
    if v is None or v == "":
        return None
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


# ---------------------------------------------------------------- API Gateway (regional)
_LAMBDA_IN_URI = re.compile(r"(arn:aws[\w-]*:lambda:[\w-]+:\d{12}:function:[\w-]+)")


def _lambda_target(uri: str) -> str:
    """The unqualified function ARN inside an integration URI ('' if not a Lambda, or if a
    stage variable picks the function at run time)."""
    m = _LAMBDA_IN_URI.search(uri or "")
    return m.group(1) if m else ""


def _rest_policy(text):
    """GetRestApis returns the resource policy as JSON with its quotes escaped."""
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(text.replace('\\"', '"'))


@collector("apigw.apis", ["apigateway:GET"])
def apigw_apis(env, region):
    """REST and HTTP APIs with the routes anyone can call: REST methods with authorization
    NONE and no API key (OPTIONS and MOCK skipped: CORS preflight, no backend), and HTTP
    API routes with no authorizer. API Gateway's IAM action for every read is apigateway:GET."""
    out = []
    rest = env.client("apigateway", region)
    for a in _pages(rest, "get_rest_apis", "items"):
        types = (a.get("endpointConfiguration") or {}).get("types") or ["EDGE"]
        res, why = _try(lambda: _pages(rest, "get_resources", "items", restApiId=a["id"],
                                       embed=["methods"]))
        open_ = []
        for r in res or []:
            for verb, m in sorted((r.get("resourceMethods") or {}).items()):
                integ = m.get("methodIntegration") or {}
                if verb == "OPTIONS" or integ.get("type") == "MOCK":
                    continue
                if m.get("authorizationType", "NONE") == "NONE" and not m.get("apiKeyRequired"):
                    open_.append({"route": f"{verb} {r.get('path', '')}",
                                  "target": _lambda_target(integ.get("uri", ""))})
        out.append({"id": a["id"], "name": a.get("name", ""), "kind": "rest",
                    "endpoint": types[0], "public": "PRIVATE" not in types,
                    "policy": _rest_policy(a.get("policy")),
                    "denied": why, "tags": a.get("tags") or {},
                    "open": sorted(open_, key=lambda o: o["route"])})
    v2 = env.client("apigatewayv2", region)
    for a in _pages(v2, "get_apis", "Items"):
        if a.get("ProtocolType") != "HTTP":
            continue                                   # WebSocket: out of scope (documented)
        routes, why = _try(lambda: _pages(v2, "get_routes", "Items", ApiId=a["ApiId"]))
        integs, iwhy = _try(lambda: _pages(v2, "get_integrations", "Items", ApiId=a["ApiId"]))
        by_id = {i["IntegrationId"]: i.get("IntegrationUri", "") for i in integs or []}
        open_ = [{"route": r.get("RouteKey", ""),
                  "target": _lambda_target(by_id.get((r.get("Target") or "").split("/")[-1], ""))}
                 for r in routes or [] if r.get("AuthorizationType", "NONE") == "NONE"
                 and not r.get("ApiKeyRequired")]
        out.append({"id": a["ApiId"], "name": a.get("Name", ""), "kind": "http",
                    "endpoint": "HTTP", "public": True, "policy": None,
                    "denied": why or iwhy, "tags": a.get("Tags") or {},
                    "open": sorted(open_, key=lambda o: o["route"])})
    return sorted(out, key=lambda x: (x["kind"], x["id"]))


# ---------------------------------------------------------------- AMIs in use (regional)
@collector("ec2.instance_images", ["ec2:DescribeInstances", "ec2:DescribeImages"])
def instance_images(env, region):
    """The image of every non-terminated instance, including deprecated ones. An id AWS no
    longer returns is stored as None: deregistered (or unshared by its owner)."""
    ec2 = env.client("ec2", region)
    ids = sorted({i["ImageId"] for r in _pages(ec2, "describe_instances", "Reservations")
                  for i in r.get("Instances", []) if i.get("ImageId")
                  and (i.get("State") or {}).get("Name") != "terminated"})
    found, denied = {}, None
    for n in range(0, len(ids), 100):
        batch = ids[n:n + 100]
        try:
            imgs = ec2.describe_images(ImageIds=batch, IncludeDeprecated=True)["Images"]
        except ClientError as e:
            if "InvalidAMIID" not in e.response.get("Error", {}).get("Code", ""):
                raise
            imgs = []                                  # one gone id fails the batch: go one by one
            for i in batch:
                one, why = _try(lambda: ec2.describe_images(ImageIds=[i], IncludeDeprecated=True)
                                ["Images"], missing=("InvalidAMIID",))
                imgs += one or []
                denied = denied or why
        found.update({i["ImageId"]: i for i in imgs})
    return {"images": {i: ({"name": found[i].get("Name", ""), "created": found[i].get("CreationDate"),
                            "deprecation": found[i].get("DeprecationTime"),
                            "state": found[i].get("State"), "owner": found[i].get("OwnerId", "")}
                           if i in found else None) for i in ids},
            "denied": denied}


# ---------------------------------------------------------------- RDS versions (regional)
@collector("rds.engine_versions", ["rds:DescribeDBInstances", "rds:DescribeDBClusters",
                                   "rds:DescribeDBEngineVersions",
                                   "rds:DescribeDBMajorEngineVersions"])
def rds_engine_versions(env, region):
    """Each instance and cluster's engine version, the minor upgrades AWS offers from it, and
    when its major version leaves standard support. All from AWS, no version table here.
    Aurora members are reported once, as their cluster."""
    rds = env.client("rds", region)
    dbs = [{"kind": "instance", "id": d["DBInstanceIdentifier"], "arn": d.get("DBInstanceArn", ""),
            "engine": d.get("Engine", ""), "version": d.get("EngineVersion", ""),
            "lifecycle": d.get("EngineLifecycleSupport", ""), "tags": _tags(d.get("TagList"))}
           for d in _pages(rds, "describe_db_instances", "DBInstances")
           if not d.get("DBClusterIdentifier")]
    clusters, cwhy = _try(lambda: _pages(rds, "describe_db_clusters", "DBClusters"))
    dbs += [{"kind": "cluster", "id": c["DBClusterIdentifier"], "arn": c.get("DBClusterArn", ""),
             "engine": c.get("Engine", ""), "version": c.get("EngineVersion", ""),
             "lifecycle": c.get("EngineLifecycleSupport", ""), "tags": _tags(c.get("TagList"))}
            for c in clusters or []]
    versions, support = {}, {}
    for eng, ver in sorted({(d["engine"], d["version"]) for d in dbs}):
        ev, why = _try(lambda: rds.describe_db_engine_versions(Engine=eng, EngineVersion=ver)
                       ["DBEngineVersions"])
        ev = (ev or [{}])[0]
        versions[f"{eng}|{ver}"] = {
            "major": ev.get("MajorEngineVersion", ""), "denied": why,
            "upgrades": sorted(t["EngineVersion"] for t in ev.get("ValidUpgradeTarget", [])
                               if not t.get("IsMajorVersionUpgrade"))}
    for eng, major in sorted({(d["engine"], versions[f"{d['engine']}|{d['version']}"]["major"])
                              for d in dbs}):
        if not major:
            continue
        mv, why = _try(lambda: rds.describe_db_major_engine_versions(
            Engine=eng, MajorEngineVersion=major)["DBMajorEngineVersions"])
        ends = [lc.get("LifecycleSupportEndDate") for m in mv or []
                for lc in m.get("SupportedEngineLifecycles", [])
                if lc.get("LifecycleSupportName") == "open-source-rds-standard-support"]
        support[f"{eng}|{major}"] = {"standard_end": _iso(ends[0]) if ends else None, "denied": why}
    return {"dbs": sorted(dbs, key=lambda d: (d["kind"], d["id"])), "versions": versions,
            "support": support, "clusters_denied": cwhy}


# ---------------------------------------------------------------- OpenSearch (regional)
@collector("opensearch.domains", ["es:ListDomainNames", "es:DescribeDomains"])
def opensearch_domains(env, region):
    os_ = env.client("opensearch", region)
    names = [d["DomainName"] for d in os_.list_domain_names().get("DomainNames", [])]
    out = []
    for n in range(0, len(names), 5):                  # DescribeDomains takes 5 at a time
        batch = names[n:n + 5]
        got, why = _try(lambda: os_.describe_domains(DomainNames=batch)["DomainStatusList"])
        if why:
            out += [{"name": b, "arn": b, "denied": why, "vpc": None, "endpoint": "",
                     "policy": None, "fgac": None, "anonymous": None} for b in batch]
            continue
        for d in got or []:
            sec = d.get("AdvancedSecurityOptions") or {}
            out.append({"name": d["DomainName"], "arn": d.get("ARN", d["DomainName"]),
                        "vpc": bool(d.get("VPCOptions", {}).get("VPCId") or d.get("Endpoints")),
                        "endpoint": d.get("Endpoint", ""),
                        "policy": _policy(d.get("AccessPolicies")), "denied": None,
                        "fgac": bool(sec.get("Enabled")),
                        "anonymous": bool(sec.get("AnonymousAuthEnabled"))})
    return sorted(out, key=lambda x: x["name"])


# ---------------------------------------------------------------- CloudTrail activity (regional)
EVENT_WINDOW_DAYS = 7
EVENT_PAGES = 3                                        # 50 events a page; LookupEvents is 2 TPS
# Global services log to us-east-1 whatever the caller's region; not a sign of regional use.
GLOBAL_SOURCES = ("iam.", "sts.", "signin.", "cloudfront.", "route53.", "organizations.",
                  "health.", "support.", "account.", "billing", "ce.")


@collector("cloudtrail.write_events", ["cloudtrail:LookupEvents"])
def write_events(env, region):
    """Management write events of the last 7 days in this region, capped at 3 pages. Writes
    AWS services make on their own (userIdentity AWSService, or invokedBy) and global-service
    events are dropped. Counts and a 5-event sample, never request parameters."""
    ct = env.client("cloudtrail", region)
    end = datetime.now(timezone.utc)
    kw = {"LookupAttributes": [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
          "StartTime": end - timedelta(days=EVENT_WINDOW_DAYS), "EndTime": end, "MaxResults": 50}
    by_name, sample, n, capped = {}, [], 0, False
    for page in range(EVENT_PAGES):
        r = ct.lookup_events(**kw)
        for e in r.get("Events", []):
            try:
                body = json.loads(e.get("CloudTrailEvent") or "{}")
            except ValueError:
                body = {}
            who = body.get("userIdentity") or {}
            src = e.get("EventSource", "")
            if who.get("type") == "AWSService" or who.get("invokedBy") or src.startswith(GLOBAL_SOURCES):
                continue
            n += 1
            key = f"{src}:{e.get('EventName', '')}"
            by_name[key] = by_name.get(key, 0) + 1
            if len(sample) < 5:
                sample.append({"time": _iso(e.get("EventTime")), "name": e.get("EventName", ""),
                               "source": src, "user": e.get("Username", "")})
        if not r.get("NextToken"):
            break
        kw["NextToken"] = r["NextToken"]
        capped = page == EVENT_PAGES - 1
    return {"window_days": EVENT_WINDOW_DAYS, "events": n, "capped": capped,
            "by_name": dict(sorted(by_name.items())), "sample": sample}


# ---------------------------------------------------------------- Route 53 (global)
_S3_HOST = re.compile(r"^(?:(?P<bucket>.+?)\.)?s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$")


def s3_bucket_of(record_name: str, value: str) -> str:
    """The bucket a record serves from: the host prefix of an S3 endpoint, or for a bare
    S3 website endpoint (an alias) the record name itself. '' if not S3."""
    m = _S3_HOST.match((value or "").lower())
    if not m:
        return ""
    return m.group("bucket") or record_name.rstrip(".").lower()


@collector("route53.records", ["route53:ListHostedZones", "route53:ListResourceRecordSets"],
           scope=GLOBAL)
def route53_records(env, region):
    """CNAME/A/AAAA records of public zones, and whether each S3 bucket they name exists.
    HeadBucket answers 404 for a name no account holds (claimable) and 403/301 for one held
    elsewhere; it is asked only for names not in this account's bucket list. It needs no
    extra permission for either answer, so none is listed."""
    r53, s3 = env.client("route53"), env.client("s3")
    zones, records = [], []
    for z in _pages(r53, "list_hosted_zones", "HostedZones"):
        private = (z.get("Config") or {}).get("PrivateZone", False)
        zones.append({"id": z["Id"].split("/")[-1], "name": z["Name"], "private": private})
        if private:
            continue
        for rr in _pages(r53, "list_resource_record_sets", "ResourceRecordSets", HostedZoneId=z["Id"]):
            if rr.get("Type") not in ("CNAME", "A", "AAAA"):
                continue
            records.append({"zone": zones[-1]["id"], "name": rr["Name"], "type": rr["Type"],
                            "values": sorted(v["Value"] for v in rr.get("ResourceRecords", [])),
                            "alias": (rr.get("AliasTarget") or {}).get("DNSName", "")})
    mine = {b["Name"] for b in s3.list_buckets().get("Buckets", [])}
    names = {s3_bucket_of(r["name"], v) for r in records for v in r["values"] + [r["alias"]]} - {""}
    exists = {}
    for b in sorted(names - mine):
        try:
            s3.head_bucket(Bucket=b)
            exists[b] = "exists-elsewhere"
        except ClientError as e:
            code = str(e.response.get("Error", {}).get("Code", ""))
            exists[b] = "missing" if code in ("404", "NoSuchBucket", "NotFound") else "exists-elsewhere"
    return {"zones": sorted(zones, key=lambda z: z["id"]),
            "records": sorted(records, key=lambda r: (r["zone"], r["name"], r["type"])),
            "bucket_exists": exists}


# ---------------------------------------------------------------- CloudFront (global)
@collector("cloudfront.distributions", ["cloudfront:ListDistributions"], scope=GLOBAL)
def cloudfront_distributions(env, region):
    cf = env.client("cloudfront")
    out = []
    pages = cf.get_paginator("list_distributions").paginate()
    for page in pages:
        for d in (page.get("DistributionList") or {}).get("Items", []):
            origins = [{"id": o["Id"], "domain": o.get("DomainName", ""),
                        "oac": o.get("OriginAccessControlId", ""),
                        "oai": (o.get("S3OriginConfig") or {}).get("OriginAccessIdentity", "")}
                       for o in (d.get("Origins") or {}).get("Items", [])]
            out.append({"id": d["Id"], "arn": d.get("ARN", ""), "domain": d.get("DomainName", ""),
                        "aliases": sorted((d.get("Aliases") or {}).get("Items", [])),
                        "origins": sorted(origins, key=lambda o: o["id"])})
    return sorted(out, key=lambda x: x["id"])


# ---------------------------------------------------------------- Access Analyzer (regional)
FINDINGS_CAP = 500


@collector("accessanalyzer.findings", ["access-analyzer:ListAnalyzers",
                                       "access-analyzer:ListFindings"])
def access_analyzer(env, region):
    """Active external-access findings of every active account or organization analyzer
    (unused-access analyzers are skipped), capped at 500 a region."""
    aa = env.client("accessanalyzer", region)
    analyzers = [{"arn": a["arn"], "type": a.get("type", ""), "status": a.get("status", "")}
                 for a in _pages(aa, "list_analyzers", "analyzers")
                 if a.get("type") in ("ACCOUNT", "ORGANIZATION")]
    findings, capped = [], False
    for a in analyzers:
        if a["status"] != "ACTIVE":
            continue
        for f in _pages(aa, "list_findings", "findings", analyzerArn=a["arn"],
                        filter={"status": {"eq": ["ACTIVE"]}}):
            if len(findings) >= FINDINGS_CAP:
                capped = True
                break
            findings.append({"id": f["id"], "resource": f.get("resource", ""),
                             "resource_type": f.get("resourceType", ""),
                             "principal": f.get("principal") or {},
                             "action": sorted(f.get("action") or []),
                             "is_public": bool(f.get("isPublic")),
                             "condition": f.get("condition") or {},
                             "owner": f.get("resourceOwnerAccount", "")})
    return {"analyzers": analyzers, "findings": sorted(findings, key=lambda f: f["id"]),
            "capped": capped}


# ---------------------------------------------------------------- KMS rotation (regional)
@collector("kms.key_rotation", ["kms:ListKeys", "kms:DescribeKey", "kms:GetKeyRotationStatus"])
def kms_key_rotation(env, region):
    """Enabled customer-managed keys with their spec and origin, which `kms.keys` does not
    keep, so a check can tell 'rotation off' from 'rotation not possible'."""
    kms = env.client("kms", region)
    out = []
    for k in _pages(kms, "list_keys", "Keys"):
        meta, why = _try(lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"])
        if meta and (meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled"):
            continue
        meta = meta or {}
        spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec", "")
        rot, rwhy = None, why
        if spec == "SYMMETRIC_DEFAULT" and meta.get("Origin") == "AWS_KMS":
            rot, rwhy = _try(lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"])
        out.append({"id": k["KeyId"], "arn": k["KeyArn"], "spec": spec,
                    "origin": meta.get("Origin", ""), "rotation": rot, "rotation_denied": rwhy})
    return sorted(out, key=lambda x: x["arn"])


# ---------------------------------------------------------------- CloudTrail integrity (global)
@collector("cloudtrail.trail_integrity", ["cloudtrail:DescribeTrails"], scope=GLOBAL)
def trail_integrity(env, region):
    trails = env.client("cloudtrail").describe_trails(includeShadowTrails=True).get("trailList", [])
    uniq = {t["TrailARN"]: {"arn": t["TrailARN"], "name": t.get("Name", ""),
                            "home": t.get("HomeRegion") or env.region,
                            "bucket": t.get("S3BucketName", ""),
                            "validation": t.get("LogFileValidationEnabled", False)}
            for t in trails}
    return sorted(uniq.values(), key=lambda t: t["arn"])
