"""One positive and one negative recorded snapshot per check (requirements §Non-functional
"Accuracy"). Snapshots are hand-built in the collectors' normalised shapes, so each case
states exactly the fact that should, or should not, fire."""
import pytest

from cloudtools.core.collect import GLOBAL, Miss, Snapshot
from cloudtools.security import scan  # noqa: F401 (registers checks)
from cloudtools.security.checks import CHECKS, CheckCtx

R = "eu-west-1"
ACCT = "123456789012"
AT = "2026-10-27T00:00:00Z"


def snap(**data):
    """snap(key=payload) for global keys or key={region: payload}; '.' spelled '__'."""
    d = {}
    for k, v in data.items():
        key = k.replace("__", ".")
        d[key] = v if isinstance(v, dict) and set(v) <= {R, GLOBAL, "us-east-1"} and v else {GLOBAL: v}
    return Snapshot(ACCT, [R], d, meta={"collected_at": AT})


def reg(payload):
    return {R: payload}


def sg(id_, rules, name="web", tags=None):
    return {"id": id_, "name": name, "vpc": "vpc-1", "tags": tags or {}, "ingress": rules}


def rule(proto="tcp", lo=22, hi=22, cidrs=("0.0.0.0/0",), ipv6=()):
    return {"proto": proto, "from": lo, "to": hi, "cidrs": list(cidrs), "ipv6": list(ipv6),
            "sg_refs": []}


def inst(id_="i-1", state="running", ip="", sgs=(), profile="", imds=False):
    return {"id": id_, "state": state, "tags": {}, "name": id_, "public_ip": ip,
            "subnet": "subnet-1", "vpc": "vpc-1", "sgs": list(sgs), "imds_v1": imds,
            "profile_arn": profile, "image_id": "ami-1", "launch_time": ""}


def lb(scheme="internet-facing", proto="HTTP", policy="", targets=()):
    return {"arn": "arn:lb/1", "name": "lb1", "scheme": scheme, "type": "application",
            "sgs": [], "listeners": [{"port": 443, "protocol": proto, "ssl_policy": policy}],
            "targets": list(targets)}


def fn(runtime="python3.12", url=()):
    return {"name": "f1", "arn": "arn:aws:lambda:eu-west-1:1:function:f1", "runtime": runtime,
            "role": "arn:aws:iam::1:role/r", "url_auth": list(url), "url_denied": None}


KEY_FP = "sha256:abcdefabcdef"


def akey(status, fp=KEY_FP):
    return {"user": "dev", "user_arn": "arn:aws:iam::1:user/dev", "key_fp": fp, "hint": "WXYZ",
            "status": status, "created": "2024-01-01T00:00:00Z", "last_used": None,
            "last_service": None}


def repo_hits(fp, extra=False):
    s = [{"rule": "aws-access-token", "kind": "aws_access_key_id", "fingerprint": fp, "hint": "WXYZ",
          "locations": ["app/.env:3"], "locations_total": 1, "in_worktree": True, "first_seen": None}]
    if extra:
        s.append({**s[0], "rule": "github-pat", "kind": "api_key", "fingerprint": "sha256:111111111111",
                  "hint": ""})
    return {"repos": [{"repo": "app", "path": "/src/app", "secrets": s}], "errors": []}


def secret(rotation, changed, n="a"):
    return {"name": n, "arn": f"arn:aws:secretsmanager:eu-west-1:1:secret:{n}", "rotation": rotation,
            "last_rotated": None, "last_changed": changed, "last_accessed": None,
            "created": "2024-01-01T00:00:00Z", "owning_service": "", "tags": {}}


def dbuser(managed=False, iam=False, id_="db1"):
    return {"kind": "instance", "id": id_, "arn": f"arn:aws:rds:eu-west-1:1:db:{id_}", "engine": "postgres",
            "master_user": "admin", "iam_auth": iam, "managed": managed, "tags": {}}


def rds(public=False, enc=True, minor=True, snaps=()):
    return {"instances": [{"id": "db1", "arn": "arn:rds:db1", "engine": "postgres",
                           "version": "15", "public": public, "encrypted": enc,
                           "auto_minor_upgrade": minor, "sgs": [], "tags": {}}],
            "public_snapshots": list(snaps)}


def cred_row(user="alice", pw="false", mfa="true", k1="false", rotated="N/A", used="N/A"):
    return {"user": user, "arn": f"arn:aws:iam::{ACCT}:user/{user}", "password_enabled": pw,
            "mfa_active": mfa, "access_key_1_active": k1, "access_key_1_last_rotated": rotated,
            "access_key_1_last_used_date": used, "access_key_2_active": "false"}


def auth_user(policy_arn):
    return {"UserDetailList": [{"UserName": "u1", "Arn": f"arn:aws:iam::{ACCT}:user/u1",
                                "AttachedManagedPolicies": [{"PolicyArn": policy_arn}],
                                "UserPolicyList": [], "GroupList": []}],
            "GroupDetailList": [], "RoleDetailList": [], "Policies": []}


def res_policy(cond=None):
    st = {"Effect": "Allow", "Principal": "*", "Action": "x:Do", "Resource": "*"}
    if cond:
        st["Condition"] = cond
    return {"Statement": [st]}


ORG = {"StringEquals": {"aws:PrincipalOrgID": "o-123"}}
OK_BPA = {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                             "RestrictPublicBuckets")}

CASES = {
    "net.sg-all-traffic-open": (
        snap(ec2__security_groups=reg([sg("sg-1", [rule("-1", None, None)])])),
        snap(ec2__security_groups=reg([sg("sg-1", [rule("-1", None, None, ["10.0.0.0/8"])])]))),
    "net.default-sg-has-rules": (
        snap(ec2__security_groups=reg([sg("sg-d", [rule(cidrs=["10.0.0.0/8"])], "default")])),
        snap(ec2__security_groups=reg([sg("sg-d", [], "default")]))),
    "net.nacl-admin-ports-open": (
        snap(ec2__network_acls=reg([{"id": "acl-1", "vpc": "v", "subnets": ["s"], "entries": [
            {"egress": False, "rule": 100, "proto": "-1", "action": "allow", "cidr": "0.0.0.0/0",
             "from": None, "to": None}]}])),
        snap(ec2__network_acls=reg([{"id": "acl-1", "vpc": "v", "subnets": ["s"], "entries": [
            {"egress": False, "rule": 10, "proto": "6", "action": "deny", "cidr": "0.0.0.0/0",
             "from": 22, "to": 22},
            {"egress": False, "rule": 11, "proto": "6", "action": "deny", "cidr": "0.0.0.0/0",
             "from": 3389, "to": 3389},
            {"egress": False, "rule": 100, "proto": "-1", "action": "allow", "cidr": "0.0.0.0/0",
             "from": None, "to": None}]}]))),
    "net.public-lb-listeners": (
        snap(elbv2__load_balancers=reg([lb(targets=[{"id": "i-1", "port": 8080}])])),
        snap(elbv2__load_balancers=reg([lb("internal")]))),
    "net.lb-outdated-tls": (
        snap(elbv2__load_balancers=reg([lb(proto="HTTPS", policy="ELBSecurityPolicy-2016-08")])),
        snap(elbv2__load_balancers=reg([lb(proto="HTTPS", policy="ELBSecurityPolicy-TLS13-1-2-2021-06")]))),
    "net.lambda-url-no-auth": (
        snap(lambda__functions=reg([fn(url=["NONE"])])),
        snap(lambda__functions=reg([fn(url=["AWS_IAM"])]))),
    "cred.inventory": (
        snap(iam__access_keys=[akey("Active")], repo__secrets=repo_hits(KEY_FP)),
        snap(iam__access_keys=[akey("Active")], repo__secrets=repo_hits("sha256:000000000000"))),
    "cred.repo-secrets": (
        snap(repo__secrets=repo_hits(KEY_FP, extra=True)),
        snap(repo__secrets=repo_hits(KEY_FP))),
    "cred.secret-not-rotated": (
        snap(secretsmanager__secrets=reg([secret(rotation=False, changed="2025-01-01T00:00:00Z")])),
        snap(secretsmanager__secrets=reg([secret(rotation=False, changed="2026-10-01T00:00:00Z"),
                                          secret(rotation=True, changed="2024-01-01T00:00:00Z", n="b")]))),
    "cred.db-static-master-password": (
        snap(rds__db_users=reg([dbuser()]), redshift__clusters=reg([])),
        snap(rds__db_users=reg([dbuser(managed=True), dbuser(iam=True, id_="db2")]),
             redshift__clusters=reg([{"id": "rs", "master_user": "awsuser", "managed": True}]))),
    "srv.public-ip": (
        snap(ec2__instances=reg([inst(ip="203.0.113.1")])),
        snap(ec2__instances=reg([inst(state="stopped", ip="203.0.113.1")]))),
    "srv.not-ssm-managed": (
        snap(ec2__instances=reg([inst()]), ssm__managed_instances=reg([])),
        snap(ec2__instances=reg([inst()]), ssm__managed_instances=reg(["i-1"]))),
    "srv.lambda-deprecated-runtime": (
        snap(lambda__functions=reg([fn("python3.7")])),
        snap(lambda__functions=reg([fn("python3.12")]))),
    "srv.eks-public-endpoint": (
        snap(eks__clusters=reg([{"name": "c", "arn": "arn:eks:c", "denied": None,
                                 "endpoint_public": True, "public_cidrs": ["0.0.0.0/0"]}])),
        snap(eks__clusters=reg([{"name": "c", "arn": "arn:eks:c", "denied": None,
                                 "endpoint_public": False, "public_cidrs": []}]))),
    "srv.rds-publicly-accessible": (snap(rds__instances=reg(rds(public=True))),
                                    snap(rds__instances=reg(rds()))),
    "srv.rds-auto-minor-upgrade-off": (snap(rds__instances=reg(rds(minor=False))),
                                       snap(rds__instances=reg(rds()))),
    "iam.root-access-keys": (snap(iam__account_summary={"AccountAccessKeysPresent": 1, "AccountMFAEnabled": 1}),
                             snap(iam__account_summary={"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1})),
    "iam.root-mfa": (snap(iam__account_summary={"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 0}),
                     snap(iam__account_summary={"AccountAccessKeysPresent": 0, "AccountMFAEnabled": 1})),
    "iam.access-key-age": (
        snap(iam__credential_report=[cred_row(k1="true", rotated="2026-01-01T00:00:00+00:00",
                                              used="2026-10-20T00:00:00+00:00")]),
        snap(iam__credential_report=[cred_row(k1="true", rotated="2026-10-01T00:00:00+00:00",
                                              used="2026-10-20T00:00:00+00:00")])),
    "iam.unused-user-live-keys": (
        snap(iam__credential_report=[cred_row(k1="true", rotated="2026-01-01T00:00:00+00:00",
                                              used="2026-02-01T00:00:00+00:00")]),
        snap(iam__credential_report=[cred_row(k1="true", rotated="2026-01-01T00:00:00+00:00",
                                              used="2026-10-25T00:00:00+00:00")])),
    "iam.admin-principals": (
        snap(iam__authorization_details=auth_user("arn:aws:iam::aws:policy/AdministratorAccess")),
        snap(iam__authorization_details=auth_user("arn:aws:iam::aws:policy/ReadOnlyAccess"))),
    "data.s3-account-bpa-off": (
        snap(s3__buckets={"account_bpa": None, "account_bpa_denied": None, "buckets": []}),
        snap(s3__buckets={"account_bpa": OK_BPA, "account_bpa_denied": None, "buckets": []})),
    "data.ebs-snapshot-public": (snap(ec2__public_snapshots=reg([{"id": "snap-1", "volume": "v", "tags": {}}])),
                                 snap(ec2__public_snapshots=reg([]))),
    "data.rds-snapshot-public": (
        snap(rds__instances=reg(rds(snaps=[{"id": "s1", "arn": "arn:rds:snap:s1", "denied": None}]))),
        snap(rds__instances=reg(rds()))),
    "data.ami-public": (snap(ec2__public_images=reg([{"id": "ami-1", "name": "n", "tags": {}}])),
                        snap(ec2__public_images=reg([]))),
    "data.sns-policy-public": (
        snap(sns__topics=reg([{"arn": "arn:aws:sns:eu-west-1:1:t", "policy": res_policy(), "policy_denied": None}])),
        snap(sns__topics=reg([{"arn": "arn:aws:sns:eu-west-1:1:t", "policy": res_policy(ORG), "policy_denied": None}]))),
    "data.kms-policy-public": (
        snap(kms__keys=reg([{"id": "k", "arn": "arn:aws:kms:eu-west-1:1:key/k", "policy": res_policy(),
                             "policy_denied": None, "rotation": True}])),
        snap(kms__keys=reg([{"id": "k", "arn": "arn:aws:kms:eu-west-1:1:key/k", "policy": res_policy(ORG),
                             "policy_denied": None, "rotation": True}]))),
    "data.ecr-policy-public": (
        snap(ecr__repositories=reg([{"name": "r", "arn": "arn:aws:ecr:eu-west-1:1:repository/r",
                                     "policy": res_policy(), "policy_denied": None, "scan_on_push": True}])),
        snap(ecr__repositories=reg([{"name": "r", "arn": "arn:aws:ecr:eu-west-1:1:repository/r",
                                     "policy": None, "policy_denied": None, "scan_on_push": True}]))),
    "data.rds-unencrypted": (snap(rds__instances=reg(rds(enc=False))), snap(rds__instances=reg(rds()))),
    "log.cloudtrail-not-multiregion": (
        snap(cloudtrail__trails=[{"arn": "t", "name": "t", "home": R, "multi_region": False, "org": False,
                                  "logging": True, "status_denied": None, "validation": True, "kms": False}]),
        snap(cloudtrail__trails=[{"arn": "t", "name": "t", "home": R, "multi_region": True, "org": False,
                                  "logging": True, "status_denied": None, "validation": True, "kms": True}])),
    "log.guardduty-off": (snap(guardduty__detectors=reg([])),
                          snap(guardduty__detectors=reg([{"id": "d", "status": "ENABLED", "denied": None}]))),
    "log.vpc-flow-logs-missing": (
        snap(ec2__vpcs=reg({"vpcs": [{"id": "vpc-1", "default": False, "flow_logs": False, "tags": {}}], "subnets": []})),
        snap(ec2__vpcs=reg({"vpcs": [{"id": "vpc-1", "default": False, "flow_logs": True, "tags": {}}], "subnets": []}))),
    "log.config-not-recording": (snap(config__recorders=reg([])),
                                 snap(config__recorders=reg([{"name": "default", "recording": True}]))),
}


# Tier 1 (sec.): collector payloads as config_secrets returns them (fingerprints only).
def t1_hit(kind="token", detector="github-pat", fp="sha256:222222222222"):
    return {"items": 1, "skipped": [], "hits": [{
        "detector": detector, "kind": kind, "fingerprint": fp, "preview": "ghp_****", "hint": "WXYZ",
        "location": "lambda:f1/env:GH", "resource": {"type": "lambda_function", "id": fn()["arn"],
                                                     "name": "f1", "api": "lambda:GetFunction"}}]}


T1_CLEAN = {"items": 1, "skipped": [], "hits": []}
CASES.update({
    "sec.config-secrets": (snap(sec__lambda=reg(t1_hit())), snap(sec__lambda=reg(T1_CLEAN))),
    "sec.leaked-aws-key": (
        snap(iam__access_keys=[akey("Active")],
             sec__lambda=reg(t1_hit("aws_access_key_id", "aws-access-token", KEY_FP))),
        snap(iam__access_keys=[akey("Active")],
             sec__lambda=reg(t1_hit("aws_access_key_id", "aws-access-token", "sha256:999999999999")))),
})

# Checks whose positive/negative cases live in tests/test_security_scan.py (moto lab).
LAB_TESTED = {"net.open-admin-ports", "srv.imdsv1-enabled", "iam.user-no-mfa",
              "iam.privilege-escalation", "iam.trust-without-external-id",
              "data.s3-public-bucket", "data.sqs-policy-public", "data.ebs-unencrypted"}
FACTS_ONLY = {"srv.workload-identities", "cred.accounts"}


def run(check_id, s):
    c = CHECKS[check_id]
    return c.fn(CheckCtx(s, c.spec, dict(c.spec.config)))


@pytest.mark.parametrize("check_id", sorted(CASES))
def test_positive_fires(check_id):
    r = run(check_id, CASES[check_id][0])
    assert r.findings, f"{check_id} missed its positive case"
    assert all(f.check_id == check_id for f in r.findings)
    assert all(f.evidence for f in r.findings), "every finding carries evidence"


@pytest.mark.parametrize("check_id", sorted(CASES))
def test_negative_silent(check_id):
    r = run(check_id, CASES[check_id][1])
    assert not r.findings, f"{check_id} fired on its negative case: {[f.title for f in r.findings]}"


def test_every_check_has_a_positive_and_negative_somewhere():
    missing = set(CHECKS) - set(CASES) - LAB_TESTED - FACTS_ONLY - __import__("test_cve").TESTED_HERE
    assert not missing, f"checks without recorded positive/negative cases: {sorted(missing)}"


def test_workload_identities_emits_runs_as_only_with_a_profile():
    auth = {"UserDetailList": [], "GroupDetailList": [], "Policies": [], "RoleDetailList": [
        {"RoleName": "r", "Arn": "arn:aws:iam::1:role/r", "Path": "/",
         "InstanceProfileList": [{"Arn": "arn:ip/p"}]}]}
    pos = run("srv.workload-identities", snap(ec2__instances=reg([inst(profile="arn:ip/p")]),
                                               lambda__functions=reg([]), iam__authorization_details=auth))
    neg = run("srv.workload-identities", snap(ec2__instances=reg([inst()]),
                                               lambda__functions=reg([]), iam__authorization_details=auth))
    assert [(f.src, f.type, f.dst) for f in pos.facts] == [("i-1", "runs_as", "arn:aws:iam::1:role/r")]
    assert not neg.facts and not pos.findings


def test_accepted_risk_tag_moves_finding_out():
    s = snap(ec2__instances=reg([{**inst(ip="203.0.113.1"),
                                  "tags": {"scanner:accepted-risk": "bastion, ticket SEC-1"}}]))
    r = run("srv.public-ip", s)
    assert r.findings[0].status == "accepted"
    assert r.findings[0].accepted_reason.startswith("bastion")


def test_severity_override_from_profile():
    c = CHECKS["srv.public-ip"]
    r = c.fn(CheckCtx(CASES["srv.public-ip"][0], c.spec, {"_severity_override": "info"}))
    assert r.findings[0].severity == "info"


def test_unauthenticated_function_url_exposes_its_role_as_possible():
    """Public code with no sign-in is assumed to have a flaw sooner or later, so the role it
    runs as is reachable: a `possible` edge with that stated as its condition, never confirmed."""
    from cloudtools.core.model import ADMIN, Evidence, Fact
    from cloudtools.security import graph
    pos = run("net.lambda-url-no-auth", CASES["net.lambda-url-no-auth"][0])
    ex = [f for f in pos.facts if f.type == "exposes_credentials"]
    assert [(f.src, f.dst, f.status) for f in ex] == [
        ("arn:aws:lambda:eu-west-1:1:function:f1", "arn:aws:iam::1:role/r", "possible")]
    assert ex[0].conditions and ex[0].confidence < 1
    neg = run("net.lambda-url-no-auth", CASES["net.lambda-url-no-auth"][1])
    assert not [f for f in neg.facts if f.type == "exposes_credentials"]
    esc = Fact("arn:aws:iam::1:role/r", "can_escalate_to", ADMIN, "iam.privilege-escalation",
               [Evidence("t", "r", "d")], {}, "possible", 0.7, ["c"]).to_dict()
    facts = [f.to_dict() for f in pos.facts] + [esc]
    paths = graph.find_paths(facts, {}, {})
    assert len(paths) == 1 and paths[0]["status"] == "possible", "found without assume_compromised"
    assert "instance metadata" not in paths[0]["steps"][1]["text"]


# AWS serves a cached credential report for up to 4 hours, so a user deleted since it was
# built still has a row. Seen in the lab on 2026-10-29: the post-teardown scan still
# reported scanner-lab-nomfa without MFA two hours after the user was deleted.
STALE = {
    "iam.user-no-mfa": cred_row(user="gone", pw="true", mfa="false"),
    "iam.access-key-age": cred_row(user="gone", k1="true", rotated="2026-01-01T00:00:00+00:00",
                                   used="2026-10-20T00:00:00+00:00"),
    "iam.unused-user-live-keys": cred_row(user="gone", k1="true", rotated="2026-01-01T00:00:00+00:00",
                                          used="2026-02-01T00:00:00+00:00"),
}
NO_USERS = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}


@pytest.mark.parametrize("check_id", sorted(STALE))
def test_credential_report_row_for_a_deleted_user_is_not_a_finding(check_id):
    assert not run(check_id, snap(iam__credential_report=[STALE[check_id]],
                                  iam__authorization_details=NO_USERS)).findings


@pytest.mark.parametrize("check_id", sorted(STALE))
def test_credential_report_row_for_a_live_user_still_fires(check_id):
    live = {**NO_USERS, "UserDetailList": [{"UserName": "gone", "Arn": STALE[check_id]["arn"]}]}
    assert run(check_id, snap(iam__credential_report=[STALE[check_id]],
                              iam__authorization_details=live)).findings


@pytest.mark.parametrize("check_id", sorted(STALE))
def test_without_the_user_list_every_row_is_kept_and_the_miss_is_a_gap(check_id):
    s = snap(iam__credential_report=[STALE[check_id]])
    s.misses.append(Miss("iam.authorization_details", GLOBAL, "AccessDenied", True,
                         ("iam:GetAccountAuthorizationDetails",)))
    r = run(check_id, s)
    assert r.findings and any("iam.authorization_details" in g.what for g in r.gaps)
