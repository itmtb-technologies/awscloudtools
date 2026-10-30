"""The B3 tier-0 checks (`security/checks/extra.py`): one positive and one negative recorded
snapshot per check, in the shapes `security/collectors_extra.py` stores, plus a graph test
for each check whose edge creates or extends an attack path (1, 6, 8, 9)."""
import pytest

import test_checks_table
from cloudtools.core.model import ADMIN, INTERNET, Evidence, Fact
from cloudtools.security import graph
from cloudtools.security.checks import CHECKS, CheckCtx
from test_checks_table import ACCT, R, inst, reg, snap

FN = "arn:aws:lambda:eu-west-1:1:function:f1"
ROLE = "arn:aws:iam::1:role/r"
ADMIN_ROLE = f"arn:aws:iam::{ACCT}:role/ec2-admin"
PROFILE_ARN = f"arn:aws:iam::{ACCT}:instance-profile/ec2-admin"


def run(check_id, s, **config):
    c = CHECKS[check_id]
    return c.fn(CheckCtx(s, c.spec, {**c.spec.config, **config}))


def fn():
    return {"name": "f1", "arn": FN, "runtime": "python3.12", "role": ROLE, "url_auth": [],
            "url_denied": None}


def api(kind="rest", endpoint="REGIONAL", open_=(("GET /pets", FN),), policy=None):
    return {"id": "a1", "name": "pets", "kind": kind, "endpoint": endpoint,
            "public": endpoint != "PRIVATE", "policy": policy, "denied": None, "tags": {},
            "open": [{"route": r, "target": t} for r, t in open_]}


def images(created="2026-09-01T00:00:00.000Z", deprecation=None, state="available", gone=False):
    img = None if gone else {"name": "al2023", "created": created, "deprecation": deprecation,
                             "state": state, "owner": "137112412989"}
    return {"images": {"ami-1": img}, "denied": None}


def rds_versions(upgrades=(), standard_end="2030-01-01T00:00:00Z", kind="instance"):
    return {"dbs": [{"kind": kind, "id": "db1", "arn": "arn:aws:rds:eu-west-1:1:db:db1",
                     "engine": "postgres", "version": "15.4", "lifecycle": "", "tags": {}}],
            "versions": {"postgres|15.4": {"major": "15", "upgrades": list(upgrades),
                                           "denied": None}},
            "support": {"postgres|15": {"standard_end": standard_end, "denied": None}},
            "clusters_denied": None}


def domain(policy, vpc=False, fgac=False, anonymous=False):
    return [{"name": "logs", "arn": "arn:aws:es:eu-west-1:1:domain/logs", "vpc": vpc,
             "endpoint": "search-logs.eu-west-1.es.amazonaws.com", "policy": policy,
             "fgac": fgac, "anonymous": anonymous, "denied": None}]


def everyone(cond=None):
    st = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "es:*", "Resource": "*"}
    if cond:
        st["Condition"] = cond
    return {"Statement": [st]}


def writes(n=3, capped=False, source="ec2.amazonaws.com", name="RunInstances"):
    return {"window_days": 7, "events": n, "capped": capped,
            "by_name": {f"{source}:{name}": n} if n else {},
            "sample": [{"time": "2026-10-26T03:00:00Z", "name": name, "source": source,
                        "user": "mallory"}] if n else []}


def empty_region():
    return dict(ec2__instances=reg([]), lambda__functions=reg([]),
                rds__instances=reg({"instances": [], "public_snapshots": []}),
                elbv2__load_balancers=reg([]),
                ec2__vpcs=reg({"vpcs": [{"id": "vpc-d", "default": True, "flow_logs": False,
                                         "tags": {}}], "subnets": []}))


def dns(value, rtype="CNAME", alias="", head=None, cf=()):
    return {"zones": [{"id": "Z1", "name": "example.com.", "private": False}],
            "records": [{"zone": "Z1", "name": "assets.example.com.", "type": rtype,
                         "values": [value] if value else [], "alias": alias}],
            "bucket_exists": head or {}}


def distribution(origin="site.s3.amazonaws.com", oac="", oai="", aliases=()):
    return [{"id": "E1", "arn": f"arn:aws:cloudfront::{ACCT}:distribution/E1",
             "domain": "d111.cloudfront.net", "aliases": list(aliases),
             "origins": [{"id": "o1", "domain": origin, "oac": oac, "oai": oai}]}]


def buckets(policy=None, is_public=False, name="site"):
    return {"account_bpa": {}, "account_bpa_denied": None, "buckets": [{
        "name": name, "arn": f"arn:aws:s3:::{name}", "region": R, "bpa": None,
        "bpa_denied": None, "policy": policy, "policy_denied": None,
        "policy_is_public": is_public, "public_acl_grants": [], "acl_denied": None,
        "tags": {}}]}


def get_object_to(principal, cond=None):
    st = {"Effect": "Allow", "Principal": principal, "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::site/*"}
    if cond:
        st["Condition"] = cond
    return {"Statement": [st]}


def auth(admin=True):
    pol = ([{"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}] if admin
           else [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}])
    return {"UserDetailList": [], "GroupDetailList": [], "Policies": [], "RoleDetailList": [
        {"RoleName": "ec2-admin", "Arn": ADMIN_ROLE, "Path": "/", "RolePolicyList": [],
         "AttachedManagedPolicies": pol, "InstanceProfileList": [{"Arn": PROFILE_ARN}]}]}


def analyzer(findings=(), active=True):
    return {"analyzers": [{"arn": "arn:aa/1", "type": "ACCOUNT",
                           "status": "ACTIVE" if active else "DISABLED"}] if active is not None else [],
            "findings": list(findings), "capped": False}


def aa_finding(principal=None, public=False, rtype="AWS::IAM::Role", resource=ROLE,
               action=("sts:AssumeRole",)):
    return {"id": "aa-1", "resource": resource, "resource_type": rtype,
            "principal": principal or {"AWS": "arn:aws:iam::999988887777:root"},
            "action": list(action), "is_public": public, "condition": {},
            "owner": ACCT}


def kms(rotation, spec="SYMMETRIC_DEFAULT", origin="AWS_KMS"):
    return [{"id": "k1", "arn": "arn:aws:kms:eu-west-1:1:key/k1", "spec": spec, "origin": origin,
             "rotation": rotation, "rotation_denied": None}]


def trails(validation=True, bucket="trail-logs"):
    return [{"arn": "arn:aws:cloudtrail:eu-west-1:1:trail/main", "name": "main", "home": R,
             "bucket": bucket, "validation": validation}]


EXTRA_CASES = {
    "net.apigw-no-auth": (
        snap(apigw__apis=reg([api()]), lambda__functions=reg([fn()])),
        snap(apigw__apis=reg([api(endpoint="PRIVATE")]), lambda__functions=reg([fn()]))),
    "srv.ami-outdated": (
        snap(ec2__instances=reg([inst()]),
             ec2__instance_images=reg(images(created="2025-01-01T00:00:00.000Z"))),
        snap(ec2__instances=reg([inst()]), ec2__instance_images=reg(images()))),
    "srv.rds-engine-outdated": (
        snap(rds__engine_versions=reg(rds_versions(upgrades=["15.8"]))),
        snap(rds__engine_versions=reg(rds_versions()))),
    "data.opensearch-open": (
        snap(opensearch__domains=reg(domain(everyone()))),
        snap(opensearch__domains=reg(domain(everyone({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}))))),
    "log.activity-in-unused-regions": (
        snap(cloudtrail__write_events=reg(writes()), **empty_region()),
        snap(cloudtrail__write_events=reg(writes(0)), **empty_region())),
    "net.dangling-dns": (
        snap(route53__records=dns("old-assets.s3-website-eu-west-1.amazonaws.com",
                                  head={"old-assets": "missing"}),
             cloudfront__distributions=[], s3__buckets=buckets()),
        snap(route53__records=dns("site.s3-website-eu-west-1.amazonaws.com"),
             cloudfront__distributions=[], s3__buckets=buckets())),
    "data.cloudfront-origin-exposed": (
        snap(cloudfront__distributions=distribution(),
             s3__buckets=buckets(get_object_to("*"), is_public=True)),
        snap(cloudfront__distributions=distribution(oac="E2OAC"),
             s3__buckets=buckets(get_object_to({"Service": "cloudfront.amazonaws.com"},
                                               {"StringEquals": {"aws:SourceArn": "arn:cf"}})))),
    "iam.instance-admin-role": (
        snap(ec2__instances=reg([inst(profile=PROFILE_ARN)]), iam__authorization_details=auth()),
        snap(ec2__instances=reg([inst(profile=PROFILE_ARN)]),
             iam__authorization_details=auth(admin=False))),
    "iam.access-analyzer-external": (
        snap(accessanalyzer__findings=reg(analyzer([aa_finding()]))),
        snap(accessanalyzer__findings=reg(analyzer()))),
    "log.kms-rotation-off": (
        snap(kms__key_rotation=reg(kms(False))),
        snap(kms__key_rotation=reg(kms(True)))),
    "log.cloudtrail-integrity": (
        snap(cloudtrail__trail_integrity=trails(validation=False), s3__buckets=buckets(name="trail-logs")),
        snap(cloudtrail__trail_integrity=trails(), s3__buckets=buckets(name="trail-logs"))),
}

# The shared catalogue test (test_checks_table) asks that every registered check has cases
# somewhere; these are they.
test_checks_table.CASES.update({k: v for k, v in EXTRA_CASES.items()
                                if k not in test_checks_table.CASES})


# ---------------------------------------------------------------- the catalogue contract
def test_catalogue_has_the_eleven_new_checks():
    assert set(EXTRA_CASES) <= set(CHECKS)
    for cid in EXTRA_CASES:
        s = CHECKS[cid].spec
        assert s.covers and s.does_not_cover and s.false_positives, f"{cid}: R5.5 fields"


@pytest.mark.parametrize("check_id", sorted(EXTRA_CASES))
def test_positive_fires(check_id):
    r = run(check_id, EXTRA_CASES[check_id][0])
    assert r.findings, f"{check_id} missed its positive case"
    assert all(f.check_id == check_id and f.evidence for f in r.findings)


@pytest.mark.parametrize("check_id", sorted(EXTRA_CASES))
def test_negative_silent(check_id):
    r = run(check_id, EXTRA_CASES[check_id][1])
    assert not r.findings, f"{check_id} fired on its negative: {[f.title for f in r.findings]}"


@pytest.mark.parametrize("check_id", sorted(EXTRA_CASES))
def test_missing_input_is_a_gap_not_a_pass(check_id):
    """Nothing collected and a recorded denial: no finding, at least one gap (R8.1)."""
    from cloudtools.core.collect import Miss, Snapshot
    spec = CHECKS[check_id].spec
    s = Snapshot(ACCT, [R], {}, meta={"collected_at": "2026-10-27T00:00:00Z"},
                 misses=[Miss(k, R, "AccessDenied", True, ()) for k in spec.collectors])
    r = run(check_id, s)
    assert not r.findings and r.gaps


def test_policy_has_the_new_reads_and_no_writes():
    from cloudtools.security.doctor import generate_policy
    acts = generate_policy({"max_tier": 0})["Statement"][0]["Action"]
    for a in ("apigateway:GET", "ec2:DescribeImages", "rds:DescribeDBEngineVersions",
              "es:DescribeDomains", "cloudtrail:LookupEvents", "route53:ListResourceRecordSets",
              "cloudfront:ListDistributions", "access-analyzer:ListFindings",
              "kms:GetKeyRotationStatus"):
        assert a in acts, a
    verbs = ("Describe", "List", "Get", "Lookup", "BatchGet", "Search", "Generate")
    assert all(a.split(":")[1].startswith(verbs) or a == "apigateway:GET" for a in acts), \
        [a for a in acts if not a.split(":")[1].startswith(verbs)]


def test_doctor_has_a_probe_for_every_new_collector():
    from cloudtools.security import doctor
    for cid in EXTRA_CASES:
        for k in CHECKS[cid].spec.collectors:
            assert doctor.probe_for(k), k


# ---------------------------------------------------------------- per-check details
def test_apigw_skips_api_key_options_and_mock_routes_by_collector_contract():
    """The collector only lists open routes; an HTTP API is always public."""
    r = run("net.apigw-no-auth", snap(apigw__apis=reg([api(kind="http", endpoint="HTTP")]),
                                      lambda__functions=reg([fn()])))
    assert r.findings and r.findings[0].resource["type"] == "api_gateway"
    none = run("net.apigw-no-auth", snap(apigw__apis=reg([api(open_=())]),
                                         lambda__functions=reg([fn()])))
    assert not none.findings


def test_apigw_resource_policy_makes_reach_possible():
    pol = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke",
                          "Resource": "*", "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]}
    r = run("net.apigw-no-auth", snap(apigw__apis=reg([api(policy=pol)]), lambda__functions=reg([fn()])))
    reach = [f for f in r.facts if f.src == INTERNET]
    assert reach and reach[0].status == "possible"


def test_ami_deprecated_and_deregistered_fire():
    dep = run("srv.ami-outdated", snap(ec2__instances=reg([inst()]),
                                       ec2__instance_images=reg(images(deprecation="2026-10-01T00:00:00.000Z"))))
    gone = run("srv.ami-outdated", snap(ec2__instances=reg([inst()]),
                                        ec2__instance_images=reg(images(gone=True))))
    assert dep.findings[0].qualifiers == {"reason": "deprecated"}
    assert gone.findings[0].qualifiers == {"reason": "deregistered"}
    stopped = run("srv.ami-outdated", snap(ec2__instances=reg([inst(state="stopped")]),
                                           ec2__instance_images=reg(images(gone=True))))
    assert not stopped.findings


def test_ami_age_is_configurable():
    s = snap(ec2__instances=reg([inst()]), ec2__instance_images=reg(images(created="2026-05-01T00:00:00.000Z")))
    assert not run("srv.ami-outdated", s).findings
    assert run("srv.ami-outdated", s, max_age_days=30).findings


def test_rds_past_standard_support_is_medium_and_data_driven():
    r = run("srv.rds-engine-outdated", snap(rds__engine_versions=reg(rds_versions(standard_end="2026-03-01T00:00:00Z"))))
    assert [(f.severity, f.qualifiers["reason"]) for f in r.findings] == [("medium", "extended-support")]
    unknown = run("srv.rds-engine-outdated", snap(rds__engine_versions=reg(
        {**rds_versions(), "support": {}})))
    assert not unknown.findings and unknown.gaps


def test_opensearch_vpc_or_fgac_is_not_open():
    assert not run("data.opensearch-open", snap(opensearch__domains=reg(domain(everyone(), vpc=True)))).findings
    assert not run("data.opensearch-open", snap(opensearch__domains=reg(domain(everyone(), fgac=True)))).findings
    assert run("data.opensearch-open", snap(opensearch__domains=reg(
        domain(everyone(), fgac=True, anonymous=True)))).findings


def test_unused_region_with_resources_is_not_reported_and_service_writes_are_ignored():
    used = empty_region()
    used["ec2__instances"] = reg([inst()])
    assert not run("log.activity-in-unused-regions", snap(cloudtrail__write_events=reg(writes()), **used)).findings
    blind = empty_region()
    blind.pop("lambda__functions")
    r = run("log.activity-in-unused-regions", snap(cloudtrail__write_events=reg(writes()), **blind))
    assert not r.findings and r.gaps, "unknown usage is a gap, never a verdict"


def test_dangling_dns_own_bucket_is_silent_without_a_gap():
    r = run("net.dangling-dns", EXTRA_CASES["net.dangling-dns"][1])
    assert not r.findings and not r.gaps and not r.facts


def test_instance_admin_role_only_running_instances():
    s = snap(ec2__instances=reg([inst(state="stopped", profile=PROFILE_ARN)]), iam__authorization_details=auth())
    assert not run("iam.instance-admin-role", s).findings


def test_dangling_dns_cloudfront_not_in_account():
    s = snap(route53__records=dns("d999.cloudfront.net"), cloudfront__distributions=distribution(),
             s3__buckets=buckets())
    r = run("net.dangling-dns", s)
    assert r.findings and r.findings[0].qualifiers["target"] == "cloudfront"
    ours = snap(route53__records=dns("d111.cloudfront.net"), cloudfront__distributions=distribution(),
                s3__buckets=buckets())
    assert not run("net.dangling-dns", ours).findings


def test_dangling_dns_alias_to_s3_website_uses_the_record_name():
    s = snap(route53__records=dns("", rtype="A", alias="s3-website-eu-west-1.amazonaws.com.",
                                  head={"assets.example.com": "missing"}),
             cloudfront__distributions=[], s3__buckets=buckets())
    assert run("net.dangling-dns", s).findings


def test_cloudfront_origin_without_oac_and_star_policy_fires_even_with_condition():
    pol = get_object_to("*", {"StringLike": {"aws:Referer": "https://example.com/*"}})
    r = run("data.cloudfront-origin-exposed", snap(cloudfront__distributions=distribution(),
                                                   s3__buckets=buckets(pol)))
    assert r.findings


def test_access_analyzer_off_is_a_gap():
    r = run("iam.access-analyzer-external", snap(accessanalyzer__findings=reg(analyzer(active=None))))
    assert not r.findings and any("Access Analyzer" in g.what for g in r.gaps)


def test_kms_asymmetric_or_imported_is_out_of_scope():
    for k in (kms(False, spec="RSA_2048"), kms(False, origin="EXTERNAL"), kms(None, spec="HMAC_256")):
        r = run("log.kms-rotation-off", snap(kms__key_rotation=reg(k)))
        assert not r.findings and not r.gaps, k


def test_kms_unknown_rotation_is_a_gap():
    r = run("log.kms-rotation-off", snap(kms__key_rotation=reg(kms(None))))
    assert not r.findings and r.gaps


def test_cloudtrail_bucket_public_fires():
    r = run("log.cloudtrail-integrity", snap(cloudtrail__trail_integrity=trails(),
                                             s3__buckets=buckets(get_object_to("*"), True, "trail-logs")))
    assert [f.qualifiers["aspect"] for f in r.findings] == ["bucket-public"]
    other = run("log.cloudtrail-integrity", snap(cloudtrail__trail_integrity=trails(bucket="central"),
                                                 s3__buckets=buckets(name="trail-logs")))
    assert not other.findings and other.gaps, "a bucket in another account is a gap"


# ---------------------------------------------------------------- graph: edges make paths
def _esc(src):
    return Fact(src, "can_escalate_to", ADMIN, "iam.admin-principals",
                [Evidence("t", src, "admin")], {}, "possible", 0.9, ["c"]).to_dict()


def _paths(results, extra=(), profile=None):
    facts = [f.to_dict() for r in results for f in r.facts] + list(extra)
    nodes = {n.id: n.__dict__ for r in results for n in r.nodes}
    return graph.find_paths(facts, nodes, profile or {})


def test_graph_apigw_internet_to_lambda_to_admin():
    r = run("net.apigw-no-auth", EXTRA_CASES["net.apigw-no-auth"][0])
    hops = {(f.src, f.type, f.dst) for f in r.facts}
    assert (INTERNET, "reaches", "arn:aws:apigateway:eu-west-1::/restapis/a1") in hops
    assert ("arn:aws:apigateway:eu-west-1::/restapis/a1", "reaches", FN) in hops
    assert not _paths([], [_esc(ROLE)])
    paths = _paths([r], [_esc(ROLE)])
    assert len(paths) == 1 and paths[0]["nodes"][0] == INTERNET and paths[0]["target"] == ADMIN
    assert paths[0]["status"] == "possible"


def test_graph_dangling_dns_creates_a_path_to_a_crown_jewel_name():
    r = run("net.dangling-dns", EXTRA_CASES["net.dangling-dns"][0])
    rec = "dns:assets.example.com"
    assert [(f.src, f.type, f.dst) for f in r.facts] == [(INTERNET, "can_write", rec)]
    assert _paths([r], profile={"crown_jewels": {"resources": [rec]}})
    neg = run("net.dangling-dns", EXTRA_CASES["net.dangling-dns"][1])
    assert not _paths([neg], profile={"crown_jewels": {"resources": [rec]}})


def test_graph_instance_admin_role_extends_a_compromised_host_to_admin():
    r = run("iam.instance-admin-role", EXTRA_CASES["iam.instance-admin-role"][0])
    assert [(f.src, f.type, f.dst) for f in r.facts] == [("i-1", "runs_as", ADMIN_ROLE)]
    prof = {"assume_compromised": ["i-1"]}
    assert not _paths([], [_esc(ADMIN_ROLE)], prof)
    paths = _paths([r], [_esc(ADMIN_ROLE)], prof)
    assert [p["nodes"] for p in paths] == [["i-1", ADMIN_ROLE, ADMIN]]


def test_graph_access_analyzer_external_principal_assumes_role_to_admin():
    r = run("iam.access-analyzer-external", EXTRA_CASES["iam.access-analyzer-external"][0])
    src = "external:999988887777"
    assert [(f.src, f.type, f.dst) for f in r.facts] == [(src, "can_assume", ROLE)]
    assert not _paths([], [_esc(ROLE)])
    paths = _paths([r], [_esc(ROLE)])
    assert [p["nodes"] for p in paths] == [[src, ROLE, ADMIN]]
    pub = run("iam.access-analyzer-external", snap(accessanalyzer__findings=reg(analyzer(
        [aa_finding({"AWS": "*"}, True, "AWS::S3::Bucket", "arn:aws:s3:::site", ["s3:GetObject"])]))))
    assert [(f.src, f.type) for f in pub.facts] == [(INTERNET, "is_public")]
    assert pub.findings[0].severity == "critical"


# ---------------------------------------------------------------- collectors over moto
def test_collectors_over_moto_feed_the_checks(monkeypatch):
    """The real collect stage (read-only guard on) for the collectors moto implements, then
    the checks on that snapshot. moto lacks LookupEvents, Access Analyzer, the RDS version
    APIs and (without openapi_spec_validator) API Gateway; those are fixture-tested above."""
    import json

    import boto3
    from moto import mock_aws

    from cloudtools.core.aws import AwsEnv
    from cloudtools.core.collect import collect
    for k, v in {"AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t", "AWS_DEFAULT_REGION": R}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    with mock_aws():
        ec2 = boto3.client("ec2", R)
        base = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        builder = ec2.run_instances(ImageId=base, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        golden = ec2.create_image(InstanceId=builder, Name="golden")["ImageId"]
        orphan = ec2.run_instances(ImageId=golden, MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
        ec2.deregister_image(ImageId=golden)
        boto3.client("opensearch", R).create_domain(DomainName="logs", AccessPolicies=json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "es:*", "Resource": "*"}]}))
        r53 = boto3.client("route53")
        z = r53.create_hosted_zone(Name="example.com", CallerReference="1")["HostedZone"]["Id"]
        r53.change_resource_record_sets(HostedZoneId=z, ChangeBatch={"Changes": [{"Action": "CREATE",
            "ResourceRecordSet": {"Name": "assets.example.com", "Type": "CNAME", "TTL": 60,
                                  "ResourceRecords": [{"Value": "old-assets.s3-website-eu-west-1.amazonaws.com"}]}}]})
        kms = boto3.client("kms", R)
        sym = kms.create_key()["KeyMetadata"]["KeyId"]
        kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")
        boto3.client("s3", R).create_bucket(Bucket="trail-logs",
                                             CreateBucketConfiguration={"LocationConstraint": R})
        boto3.client("cloudtrail", R).create_trail(Name="main", S3BucketName="trail-logs")
        env = AwsEnv(region=R, run_id="r-b3")
        s = collect(env, ["ec2.instances", "ec2.instance_images", "opensearch.domains",
                          "route53.records", "cloudfront.distributions",
                          "kms.key_rotation", "cloudtrail.trail_integrity"], [R], ACCT)
    s.meta = {"collected_at": "2026-10-27T00:00:00Z"}
    assert not s.misses, s.misses
    # s3.buckets (an existing collector) trips on moto's GetBucketPolicyStatus without a
    # policy (no IsPublic key), so its recorded shape stands in.
    s.data["s3.buckets"] = {"global": buckets(name="trail-logs")}
    assert s.get("ec2.instance_images", R)["images"][golden] is None
    ami = run("srv.ami-outdated", s)
    assert [(f.resource["id"], f.qualifiers["reason"]) for f in ami.findings] == [(orphan, "deregistered")]
    assert [f.resource["name"] for f in run("data.opensearch-open", s).findings] == ["logs"]
    dns_ = run("net.dangling-dns", s)
    assert [f.resource["name"] for f in dns_.findings] == ["assets.example.com"]
    assert dns_.findings[0].severity == "high"
    assert [f.resource["name"] for f in run("log.kms-rotation-off", s).findings] == [sym]
    assert [f.qualifiers["aspect"] for f in run("log.cloudtrail-integrity", s).findings] == ["validation"]


def test_validation_off_is_reported_once_not_twice():
    """CT-12 (production scan 2026-10-29): one multi-region, logging trail without log file
    validation came out under log.cloudtrail-not-multiregion AND log.cloudtrail-integrity."""
    t = {"arn": "arn:aws:cloudtrail:eu-west-1:1:trail/t", "name": "t", "home": "eu-west-1",
         "multi_region": True, "org": False, "logging": True, "status_denied": None,
         "validation": False, "kms": False}
    multi = run("log.cloudtrail-not-multiregion", snap(cloudtrail__trails=[t]))
    assert not multi.findings, [f.title for f in multi.findings]


# -- CT-13: Amplify-hosted domains (production scan 2026-10-29) -------------------------
def test_dangling_dns_amplify_hosted_domain_is_yours():
    """Amplify Hosting serves custom domains from CloudFront distributions in AWS's own
    account, so 8 of the company's domains were reported as pointing at a foreign target."""
    amp = test_checks_table.reg([{"app_id": "a1", "domain": "example.com",
                                  "targets": ["d999.cloudfront.net"]}])
    s = snap(route53__records=dns("d999.cloudfront.net"), cloudfront__distributions=distribution(),
             s3__buckets=buckets(), amplify__domains=amp)
    assert not run("net.dangling-dns", s).findings
    other = snap(route53__records=dns("d777.cloudfront.net"), cloudfront__distributions=distribution(),
                 s3__buckets=buckets(), amplify__domains=amp)
    assert run("net.dangling-dns", other).findings          # a real stranger still shows


def test_amplify_collector_reads_each_apps_cloudfront_names():
    from cloudtools.security import collectors_extra as cx

    class Amp:
        def can_paginate(self, op):
            return False

        def list_apps(self, **kw):
            return {"apps": [{"appId": "a1"}]}

        def list_domain_associations(self, appId, **kw):
            assert appId == "a1"
            return {"domainAssociations": [{"domainName": "example.com", "subDomains": [
                {"dnsRecord": "www CNAME d999.cloudfront.net"},
                {"dnsRecord": " CNAME D999.cloudfront.net."},
                {"dnsRecord": "verify CNAME _abc.acm-validations.aws."}]}]}

    class Env:
        def client(self, svc, region=None):
            assert svc == "amplify"
            return Amp()
    assert cx.amplify_domains(Env(), "eu-west-1") == [
        {"app_id": "a1", "domain": "example.com", "targets": ["d999.cloudfront.net"]}]
