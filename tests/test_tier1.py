"""Tier 1 (`sec.`): secrets in AWS configuration. Opt-in only; content reads are allowed
by the read-only guard only on an AwsEnv built for tier >= 1, and every value found is
reduced to a salted fingerprint and a masked preview before it leaves the collector."""
import json

import boto3
import pytest
from moto import mock_aws

from cloudtools.core.aws import TIER1_ACTIONS, TIER1_OPERATIONS, AwsEnv, WriteRefused, is_read_only
from cloudtools.security.doctor import DATA_DENY

R = "eu-west-1"


# ------------------------------------------------------------------ the guard
@pytest.mark.parametrize("service,op", [("lambda", "GetFunction"), ("ec2", "DescribeInstanceAttribute"),
                                        ("ecs", "DescribeTaskDefinition"),
                                        ("cloudformation", "GetTemplate"),
                                        ("codebuild", "BatchGetProjects"),
                                        ("ssm", "GetParameterHistory")])
def test_content_reads_are_refused_at_tier_0_and_allowed_at_tier_1(service, op):
    assert not is_read_only(op, service), f"{service}:{op} must be refused at tier 0"
    assert is_read_only(op, service, tier=1)


@pytest.mark.parametrize("service,op", [("secretsmanager", "GetSecretValue"), ("ssm", "GetParameter"),
                                        ("ssm", "GetParameters"), ("ssm", "GetParametersByPath"),
                                        ("kms", "Decrypt"), ("s3", "GetObject"),
                                        ("appsync", "GetFunction"), ("cloudfront", "GetFunction")])
def test_data_reads_stay_refused_at_every_tier(service, op):
    for tier in (0, 1, 2, 3):
        assert not is_read_only(op, service, tier=tier), f"{service}:{op} allowed at tier {tier}"


def test_decryption_is_refused_at_every_tier_even_on_an_allowed_read():
    for tier in (0, 1, 2):
        assert not is_read_only("GetParameterHistory", "ssm", tier, {"Name": "/x", "WithDecryption": True})
    assert is_read_only("GetParameterHistory", "ssm", 1, {"Name": "/x", "WithDecryption": False})


def test_tier1_never_unlocks_a_write_or_an_always_denied_read():
    always = {"GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters",
              "GetParametersByPath", "Decrypt", "GetObject"}
    assert not always & {op for ops in TIER1_OPERATIONS.values() for op in ops}
    for op in ("UpdateFunctionConfiguration", "PutParameter", "ModifyInstanceAttribute",
               "UpdateStack", "UpdateProject", "RegisterTaskDefinition", "InvokeFunction"):
        assert not is_read_only(op, "lambda", tier=3)


def test_the_guard_on_a_real_client_follows_the_env_tier(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", R)
    with mock_aws():
        boto3.client("ssm").put_parameter(Name="/p", Value="v", Type="String")
        low = AwsEnv(region=R)
        with pytest.raises(WriteRefused):
            low.client("ssm").get_parameter_history(Name="/p")
        high = AwsEnv(region=R, max_tier=1)
        assert high.client("ssm").get_parameter_history(Name="/p")["Parameters"]
        with pytest.raises(WriteRefused):
            high.client("ssm").get_parameter_history(Name="/p", WithDecryption=True)
        with pytest.raises(WriteRefused):
            high.client("ssm").put_parameter(Name="/q", Value="v", Type="String")
        with pytest.raises(WriteRefused):
            high.client("ssm").get_parameter(Name="/p")


# ------------------------------------------------------------------ opt-in, policy, manifest
def _policy(tier):
    from cloudtools.core.capability import get, load_builtin
    load_builtin()
    pol = get("security.generate_policy").fn(None, profile="full", tier=tier)
    return set(pol["Statement"][0]["Action"]), set(pol["Statement"][1]["Action"])


def test_tier_0_policy_is_unchanged_and_has_no_content_reads():
    allow, deny = _policy(0)
    assert "lambda:GetFunction" in deny and not allow & set(TIER1_ACTIONS)
    assert deny == set(DATA_DENY)


def test_tier_1_policy_adds_the_content_reads_and_drops_only_their_denies():
    allow, deny = _policy(1)
    assert set(TIER1_ACTIONS) <= allow
    assert "lambda:GetFunction" not in deny
    for a in ("s3:GetObject", "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters",
              "ssm:GetParametersByPath", "kms:Decrypt"):
        assert a in deny, f"{a} must stay denied at tier 1"


def test_tier_1_checks_run_only_when_asked():
    from cloudtools.security.checks import select
    assert not [c for c in select(max_tier=0) if c.spec.id.startswith("sec.")]
    assert {"sec.config-secrets", "sec.leaked-aws-key"} <= {c.spec.id for c in select(max_tier=1)}


def test_scan_manifest_takes_a_tier_and_tier_0_actions_exclude_content_reads():
    from cloudtools.core.capability import get, load_builtin
    load_builtin()
    m = get("security.scan").manifest
    assert m.input_schema["properties"]["tier"] == {"type": "integer", "minimum": 0, "maximum": 2}
    assert not set(m.required_aws_actions) & set(TIER1_ACTIONS)
    assert set(TIER1_ACTIONS) <= set(m.optional_aws_actions)


def test_cli_tier_flag_and_range():
    from cloudtools.cli import build_parser
    p = build_parser()
    for cmd in (["security", "scan"], ["security", "run", "x"], ["security", "policy"]):
        assert p.parse_args(cmd).tier == 0
        assert p.parse_args(cmd + ["--tier", "1"]).tier == 1
        with pytest.raises(SystemExit):
            p.parse_args(cmd + ["--tier", "3"])


# ------------------------------------------------------------------ sources (moto / recorded)
import base64  # noqa: E402
import io  # noqa: E402
import re  # noqa: E402
import zipfile  # noqa: E402
from pathlib import Path  # noqa: E402

from botocore.stub import Stubber  # noqa: E402

from cloudtools.creds import config_secrets as cs  # noqa: E402

FIX = Path(__file__).with_name("fixtures") / "tier1"
SALT = "tier1-test-salt"
ACCT = "123456789012"


def canary(tag: str) -> str:
    """A GitHub-PAT-shaped value unique to one source; made here, never committed."""
    return "ghp_" + (f"T1{tag}" + "Zq8vT3kLm9Xw2Rb7Np4Hc6Jd1Fs5Gy0Ua8KeQwErTy")[:36]


def password(tag: str) -> str:
    return f"Pw{tag}#9xLq2Vt7"


def fill(text: str) -> str:
    text = re.sub(r"\{\{CANARY:(\w+)\}\}", lambda m: canary(m.group(1)), text)
    return re.sub(r"\{\{PASSWORD:(\w+)\}\}", lambda m: password(m.group(1)), text)


def fixture(name: str) -> str:
    return fill((FIX / name).read_text(encoding="utf-8"))


def env1(tier=1):
    e = AwsEnv(region=R, max_tier=tier)
    e.secret_salt = SALT
    return e


def detectors(out) -> set:
    return {(h["detector"], h["location"]) for h in out["hits"]}


def assert_no_value(obj, *values):
    text = json.dumps(obj, default=str)
    for v in values:
        assert v not in text, "a secret value left the collector"


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", R)
    with mock_aws():
        yield


def lambda_role():
    return boto3.client("iam").create_role(RoleName="fn", AssumeRolePolicyDocument="{}")["Role"]["Arn"]


def code_zip(files: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return b.getvalue()


def fixture_zip() -> bytes:
    root = FIX / "lambda_code"
    return code_zip({str(p.relative_to(root)): fill(p.read_text(encoding="utf-8"))
                     for p in sorted(root.rglob("*")) if p.is_file()})


def test_ec2_user_data_positive_and_negative(aws):
    ec2 = boto3.client("ec2")
    bad = ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                            UserData=fixture("user_data.sh"))["Instances"][0]["InstanceId"]
    ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1, UserData=fixture("user_data_clean.sh"))
    out = cs.ec2_user_data(env1(), R)
    assert out["items"] == 2 and not out["skipped"]
    assert detectors(out) == {("github-pat", f"ec2:{bad}/userData:4"),
                              ("generic-secret-entropy", f"ec2:{bad}/userData:5")}
    assert_no_value(out, canary("ec2"), password("ec2"))


def test_ec2_user_data_gzip_is_read(aws):
    import gzip
    ec2 = boto3.client("ec2")
    ec2.run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                      UserData=gzip.compress(f"T={canary('gz')}\n".encode()))
    assert [h["detector"] for h in cs.ec2_user_data(env1(), R)["hits"]] == ["github-pat"]


def test_lambda_env_and_code_positive_and_negative(aws, monkeypatch):
    role = lambda_role()
    lam = boto3.client("lambda")
    lam.create_function(FunctionName="pay", Runtime="python3.12", Role=role, Handler="app.handler",
                        Code={"ZipFile": code_zip({"a.py": "x=1"})},
                        Environment={"Variables": {"STRIPE_KEY": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
                                                   "DB_PASSWORD": password("lambdaenv"), "TABLE": "orders"}})
    lam.create_function(FunctionName="clean", Runtime="python3.12", Role=role, Handler="app.handler",
                        Code={"ZipFile": code_zip({"a.py": "x=1"})},
                        Environment={"Variables": {"TABLE": "orders", "SECRET_ARN": "arn:aws:secretsmanager:x"}})
    urls = []

    def fake_fetch(url, cap):
        urls.append(url)
        return fixture_zip() if "pay" in url else code_zip({"a.py": "x = 1\n"})
    monkeypatch.setattr(cs, "_fetch", fake_fetch)
    out = cs.lambda_secrets(env1(), R)
    assert out["items"] == 2 and len(urls) == 2 and all(u.startswith("https://") for u in urls)
    assert detectors(out) == {("stripe-access-token", "lambda:pay/env:STRIPE_KEY"),
                              ("generic-secret-entropy", "lambda:pay/env:DB_PASSWORD"),
                              ("github-pat", "lambda:pay/code:src/app.py:4")}, \
        "env + code found; vendored node_modules and the AWS docs example key skipped"
    assert_no_value(out, canary("lambdacode"), canary("vendored"), password("lambdaenv"),
                    "4eC39HqLyjWDarjtT1zdp7dc", *urls)


def test_lambda_code_over_the_cap_is_a_gap_not_a_pass(aws, monkeypatch):
    lam = boto3.client("lambda")
    lam.create_function(FunctionName="big", Runtime="python3.12", Role=lambda_role(), Handler="a.h",
                        Code={"ZipFile": code_zip({"a.py": "x=1"})})
    monkeypatch.setattr(cs, "CODE_MAX_BYTES", 10)
    monkeypatch.setattr(cs, "_fetch", lambda url, cap: pytest.fail("must not download over the cap"))
    out = cs.lambda_secrets(env1(), R)
    assert [s["why"] for s in out["skipped"]] == ["code larger than 0 MiB: not scanned"]


def test_fetch_caps_the_stream(monkeypatch):
    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False
    monkeypatch.setattr(cs.urllib.request, "urlopen", lambda url, timeout, context=None: Resp(b"x" * (3 * 2**20)))
    with pytest.raises(cs.TooLarge):
        cs._fetch("https://example.invalid/code", 2**20)
    with pytest.raises(ValueError):
        cs._fetch("file:///etc/passwd", 2**20)


def test_ecs_task_definition_environment_not_secret_refs(aws):
    ecs = boto3.client("ecs")
    td = json.loads(fixture("taskdef.json"))
    ecs.register_task_definition(**td)
    ecs.register_task_definition(family="clean", containerDefinitions=[
        {"name": "c", "image": "x", "memory": 128, "environment": [{"name": "LOG_LEVEL", "value": "debug"}]}])
    out = cs.ecs_task_definitions(env1(), R)
    assert out["items"] == 2
    assert detectors(out) == {("github-pat", "ecs:web:1/container:app/env:SLACK_TOKEN"),
                              ("generic-secret-entropy", "ecs:web:1/container:app/env:DB_PASSWORD")}
    assert_no_value(out, canary("ecs"), password("ecs"))


def _stub_cfn(env, template_key):
    rec = json.loads(fixture("cloudformation.json"))
    cf = env.client("cloudformation", R)
    st = Stubber(cf)
    st.add_response("describe_stacks", rec["describe_stacks"])
    sid = rec["describe_stacks"]["Stacks"][0]["StackId"]
    st.add_response("get_template", rec[template_key], {"StackName": sid, "TemplateStage": "Original"})
    st.activate()
    return st


@pytest.fixture
def fake_creds(monkeypatch):
    for k, v in (("AWS_ACCESS_KEY_ID", "testing"), ("AWS_SECRET_ACCESS_KEY", "testing"),
                 ("AWS_DEFAULT_REGION", R)):
        monkeypatch.setenv(k, v)


def test_cloudformation_template_and_parameters_recorded(fake_creds):
    env = env1()
    st = _stub_cfn(env, "get_template")
    out = cs.cloudformation_templates(env, R)
    st.assert_no_pending_responses()
    assert detectors(out) == {("github-pat", "cloudformation:billing/template:11"),
                              ("generic-secret-entropy", "cloudformation:billing/parameter:ApiToken")}, \
        "NoEcho '****' and !Ref are not secrets"
    assert_no_value(out, canary("cfn"), password("cfnparam"))


def test_cloudformation_clean_template_is_silent(fake_creds):
    env = env1()
    rec = json.loads(fixture("cloudformation.json"))
    rec["describe_stacks"]["Stacks"][0]["Parameters"] = rec["describe_stacks"]["Stacks"][0]["Parameters"][:2]
    cf = env.client("cloudformation", R)
    st = Stubber(cf)
    st.add_response("describe_stacks", rec["describe_stacks"])
    st.add_response("get_template", rec["get_template_clean"])
    st.activate()
    out = cs.cloudformation_templates(env, R)
    assert out["items"] == 1 and not out["hits"]


def test_cloudformation_get_template_is_refused_at_tier_0_even_when_stubbed(fake_creds):
    env = env1(tier=0)
    _stub_cfn(env, "get_template")
    with pytest.raises(WriteRefused):                # a refusal is a bug: raised, never a gap
        cs.cloudformation_templates(env, R)


def test_codebuild_plaintext_only(aws):
    cb = boto3.client("codebuild")
    base = dict(source={"type": "S3", "location": "b/k"}, artifacts={"type": "NO_ARTIFACTS"},
                serviceRole=f"arn:aws:iam::{ACCT}:role/cb")
    env_vars = [{"name": "NPM_TOKEN", "value": "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "type": "PLAINTEXT"},
                {"name": "GH_TOKEN", "value": "/ci/Gh2Tok9xQz", "type": "PARAMETER_STORE"},
                {"name": "DB_PASSWORD", "value": password("cb"), "type": "PLAINTEXT"}]
    cb.create_project(name="build", environment={"type": "LINUX_CONTAINER", "image": "i",
                                                 "computeType": "BUILD_GENERAL1_SMALL",
                                                 "environmentVariables": env_vars}, **base)
    cb.create_project(name="clean", environment={"type": "LINUX_CONTAINER", "image": "i",
                                                 "computeType": "BUILD_GENERAL1_SMALL",
                                                 "environmentVariables": [{"name": "STAGE", "value": "prod",
                                                                           "type": "PLAINTEXT"}]}, **base)
    out = cs.codebuild_projects(env1(), R)
    assert out["items"] == 2
    assert detectors(out) == {("npm-access-token", "codebuild:build/env:NPM_TOKEN"),
                              ("generic-secret-entropy", "codebuild:build/env:DB_PASSWORD")}
    assert_no_value(out, password("cb"), "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")


def test_ssm_plain_string_history_never_securestring(aws):
    ssm = boto3.client("ssm")
    ssm.put_parameter(Name="/app/github_token", Value=canary("ssmold"), Type="String")
    ssm.put_parameter(Name="/app/github_token", Value="moved-to-secrets-manager", Type="String", Overwrite=True)
    ssm.put_parameter(Name="/app/db_password", Value=password("ssmsecure"), Type="SecureString")
    ssm.put_parameter(Name="/app/log_level", Value="info", Type="String")
    out = cs.ssm_plain_parameters(env1(), R)
    assert out["items"] == 2, "SecureString parameters are not even asked for"
    assert detectors(out) == {("github-pat", "ssm:/app/github_token/v1")}, "an overwritten value is in the history"
    assert_no_value(out, canary("ssmold"), password("ssmsecure"))


# ------------------------------------------------------------------ runner conditions
def test_an_env_with_no_tier_set_stays_at_tier_0():
    from cloudtools.core.platform.standalone import StandalonePlatform
    assert AwsEnv(region=R).max_tier == 0
    assert StandalonePlatform(region=R).aws_env("r").max_tier == 0


def test_a_tier_1_collector_with_no_salt_is_a_gap_and_keeps_nothing(aws):
    from cloudtools.core.collect import collect
    boto3.client("ssm").put_parameter(Name="/app/token", Value=canary("nosalt"), Type="String")
    env = AwsEnv(region=R, max_tier=1)                     # no secret_salt
    snap = collect(env, ["sec.ssm_plain"], [R], ACCT)
    assert "sec.ssm_plain" not in snap.data
    assert [(m.key, m.why) for m in snap.misses] == [("sec.ssm_plain", "NoSalt")]
    assert canary("nosalt") not in snap.to_json()


# ------------------------------------------------------------------ end to end
AKID_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ8vT3kLm9"     # 40 chars, made up


def _plant_everywhere(role):
    """A canary in each of the six sources, plus an admin user's key in a Lambda env.
    Returns (key id, every value that must never be written anywhere)."""
    iam = boto3.client("iam")
    iam.create_user(UserName="deployer")
    iam.put_user_policy(UserName="deployer", PolicyName="admin", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    kid = iam.create_access_key(UserName="deployer")["AccessKey"]["AccessKeyId"]
    boto3.client("ec2").run_instances(ImageId="ami-12c6146b", MinCount=1, MaxCount=1,
                                      UserData=fixture("user_data.sh"))
    boto3.client("lambda").create_function(
        FunctionName="pay", Runtime="python3.12", Role=role, Handler="app.handler",
        Code={"ZipFile": code_zip({"a.py": "x=1"})},
        Environment={"Variables": {"AWS_ACCESS_KEY_ID": kid, "AWS_SECRET_ACCESS_KEY": AKID_SECRET,
                                   "GITHUB_TOKEN": canary("lambdaenv")}})
    boto3.client("ecs").register_task_definition(**json.loads(fixture("taskdef.json")))
    boto3.client("codebuild").create_project(
        name="build", source={"type": "S3", "location": "b/k"}, artifacts={"type": "NO_ARTIFACTS"},
        serviceRole=f"arn:aws:iam::{ACCT}:role/cb",
        environment={"type": "LINUX_CONTAINER", "image": "i", "computeType": "BUILD_GENERAL1_SMALL",
                     "environmentVariables": [{"name": "GH", "value": canary("codebuild"), "type": "PLAINTEXT"}]})
    boto3.client("ssm").put_parameter(Name="/app/gh", Value=canary("ssm"), Type="String")
    values = [kid, AKID_SECRET, canary("lambdaenv"), canary("lambdacode"), canary("ec2"), password("ec2"),
              canary("ecs"), password("ecs"), canary("codebuild"), canary("ssm"), canary("cfn"),
              password("cfnparam")]
    return kid, values


def _stub_cloudformation(monkeypatch):
    """moto's CloudFormation needs openapi_spec_validator (not installed): the recorded
    responses are served by a Stubber on the scanner's own, guarded client."""
    rec = json.loads(fixture("cloudformation.json"))
    orig = AwsEnv.client

    def client(self, service, region=None):
        c = orig(self, service, region)
        if service == "cloudformation" and not getattr(c, "_t1_stub", None):
            st = Stubber(c)
            st.add_response("describe_stacks", rec["describe_stacks"])     # doctor preflight probe
            st.add_response("describe_stacks", rec["describe_stacks"])
            st.add_response("get_template", rec["get_template"])
            st.activate()
            c._t1_stub = st
        return c
    monkeypatch.setattr(AwsEnv, "client", client)


def _scan(tmp_path, monkeypatch, capsys, *extra):
    from cloudtools.cli import main
    out = tmp_path / "out"
    urls = []

    def fake_fetch(url, cap):
        urls.append(url)
        return fixture_zip()
    monkeypatch.setattr(cs, "_fetch", fake_fetch)
    code = main(["security", "scan", "--profile", "full", "--region", R, "--regions", R,
                 "--out", str(out), "-q", "-v", *extra])
    rid = json.loads((out / "runs/latest-security.json").read_text())["run_id"]
    captured = capsys.readouterr()
    return code, out / "runs" / rid, urls, captured.out + captured.err


@pytest.fixture
def planted(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", R)
    monkeypatch.setenv("CLOUDTOOLS_SALT", "e2e-salt")
    with mock_aws():
        _stub_cloudformation(monkeypatch)
        yield _plant_everywhere(lambda_role())


def test_tier_1_end_to_end_key_in_lambda_env_is_a_critical_path_to_admin(planted, tmp_path, monkeypatch, capsys):
    from cloudtools.core.model import ADMIN
    from cloudtools.core.report import validate
    kid, values = planted
    _, run_dir, urls, console = _scan(tmp_path, monkeypatch, capsys, "--tier", "1")
    rep = json.loads((run_dir / "report.json").read_text())
    validate(rep)
    assert rep["run"]["max_tier"] == 1
    [leak] = [f for f in rep["findings"] if f["check_id"] == "sec.leaked-aws-key"]
    assert leak["severity"] == {"base": "high", "contextual": "critical"}, "raised: it is on a path"
    assert leak["secret"]["preview"] == kid[:4] + "****" + kid[-4:]
    assert leak["secret"]["location"] == "lambda:pay/env:AWS_ACCESS_KEY_ID"
    paths = [p for p in rep["paths"] if p["entry"] == leak["secret"]["fingerprint"].join(("leak:", ""))]
    assert paths and all(p["target"] == ADMIN for p in paths) and paths[0]["nodes"][1].endswith(":user/deployer")
    edge = next(f for f in rep["facts"] if f["type"] == "authenticates_as")
    assert edge["status"] == "possible" and edge["confidence"] == 0.9, "the secret key was seen beside the id"
    # every source found its own canary
    found = {f["secret"]["location"].split("/")[0].split(":")[0] for f in rep["findings"]
             if f["check_id"] == "sec.config-secrets"}
    assert found == {"ec2", "lambda", "ecs", "cloudformation", "codebuild", "ssm"}
    sec = {f["secret"]["location"] for f in rep["findings"] if f["check_id"] == "sec.config-secrets"}
    assert {"lambda:pay/env:AWS_SECRET_ACCESS_KEY", "lambda:pay/env:GITHUB_TOKEN",
            "lambda:pay/code:src/app.py:4", "ssm:/app/gh/v1", "codebuild:build/env:GH"} <= sec
    assert all(len(f["secret"]["preview"]) <= 12 for f in rep["findings"] if f["secret"])
    # ...and no value, key id or presigned URL is in any output, the log, or the console
    files = sorted(run_dir.iterdir())
    assert {"report.json", "report.html", "report.sarif", "findings.csv", "snapshot.json",
            "run.jsonl", "status.json"} <= {f.name for f in files}
    for f in files:
        text = f.read_text(encoding="utf-8")
        for v in values + urls:
            assert v not in text, f"a planted value is in {f.name}"
    for v in values + urls:
        assert v not in console, "a planted value reached the console"
    log = [json.loads(line) for line in (run_dir / "run.jsonl").read_text().splitlines()]
    assert any(e["event"] == "code.fetch" and e.get("outcome") == "ok" for e in log)


def test_without_tier_no_content_read_is_made_and_no_tier_1_check_runs(planted, tmp_path, monkeypatch, capsys):
    _, run_dir, urls, _ = _scan(tmp_path, monkeypatch, capsys)
    rep = json.loads((run_dir / "report.json").read_text())
    assert rep["run"]["max_tier"] == 0 and not urls
    assert not [c for c in rep["checks"] if c["id"].startswith("sec.")]
    calls = {e["action"] for e in map(json.loads, (run_dir / "run.jsonl").read_text().splitlines())
             if e["event"] == "api.call"}
    assert not calls & {op for ops in TIER1_OPERATIONS.values() for op in ops}


def test_doctor_finds_a_probe_for_every_tier_1_collector():
    from cloudtools.security import doctor
    for key in cs.SOURCES:
        svc, op, _ = doctor.probe_for(key)
        assert op.startswith(("list_", "describe_")), "a probe is a cheap list call, never a content read"


def test_an_env_missing_the_tier_attribute_refuses_get_function(aws):
    env = AwsEnv(region=R)
    del env.max_tier                                  # built elsewhere, never told a tier
    with pytest.raises(WriteRefused):
        env.client("lambda").get_function(FunctionName="any")


def test_code_download_uses_botocores_ca_bundle_not_the_system_one(monkeypatch):
    """python.org builds have no system CA bundle: on a real account (2026-10-28) 43 of 45 Lambda
    code downloads failed CERTIFICATE_VERIFY_FAILED while boto3 worked. The download must
    verify with the same bundle botocore uses (AWS_CA_BUNDLE, else certifi)."""
    import ssl
    from cloudtools.creds import config_secrets as cs
    seen = {}

    class _Resp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return b""

    def fake_urlopen(url, timeout=None, context=None):
        seen["ctx"] = context
        return _Resp()
    monkeypatch.setattr(cs.urllib.request, "urlopen", fake_urlopen)
    cs._fetch("https://example.invalid/code.zip", 10)
    ctx = seen["ctx"]
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname and ctx.cert_store_stats()["x509_ca"] > 0


def _zip(files: dict) -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def test_lambda_zip_skips_bundled_dependencies_and_minified_code():
    """A real account (2026-10-28): 1,329 'secrets' in 45 Lambdas, 1,328 of them inside bundled
    libraries (pydantic, cryptography, openai, ...) and minified build chunks. First-party
    code must still be scanned in full."""
    from cloudtools.creds.config_secrets import scan_zip
    # Code is scanned with the named rules only; the generic entropy rule is for config.
    first_party = 'OPENAI = "sk-proj-' + 'Zq8vT3kLm9Xw2Rb7Np4Hc6Jd' + 'T3BlbkFJ' + 'Qa1Lm9Xw2Rb7Np4Hc6Jd8Kf"\n'
    data = _zip({
        "handler.py": first_party,
        "app/settings.py": 'DB = "postgres://svc:Hq7vT3kLm9Xw2R@db.internal/app"\n',
        "pydantic/networks.py": '"""e.g. postgres://user:Sup3rPassw0rd@localhost/db"""\nsecret_key = "Ab3dEf7hIj9kLm2nOp4q"\n',
        "pydantic-2.9.2.dist-info/top_level.txt": "pydantic\n",
        "jwt/api_jws.py": 'secret = "Xy7zQw3eRt5yUi9oPa1s"\n',
        "PyJWT-2.9.0.dist-info/RECORD": "jwt/__init__.py,sha256=x,1\njwt/api_jws.py,sha256=y,2\n",
        "chunks/812.js": "var a=1;" * 400 + 'token="Lm9Xw2Rb7Np4Hc6JdQa1"' + ";" * 10,
    })
    hits, complete = scan_zip(data, "lambda:fn/code", "salt")
    files = sorted({h["location"].split("/code:", 1)[1].rsplit(":", 1)[0] for h in hits})
    assert complete and files == ["app/settings.py", "handler.py"], files


def test_generic_entropy_rule_is_for_config_not_code():
    """A real account (2026-10-28): 122 of 122 generic-entropy hits in Lambda code were type
    expressions (`token: Optional[...]`), build hashes and webpack names. In config (env
    vars, user data, templates, parameters) the same rule stays on."""
    from cloudtools.creds.config_secrets import scan_pair, scan_text, scan_zip
    code = 'session_token = "Zq8vT3kLm9Xw2Rb7Np4Hc6Jd"\ntoken: Optional[TokenResponse] = None\n'
    hits, _ = scan_zip(_zip({"app.py": code}), "lambda:fn/code", "salt")
    assert hits == []
    assert scan_text(code, "ec2:i-1/user-data", "salt"), "user data still gets the entropy rule"
    assert scan_pair("DB_PASSWORD", "Zq8vT3kLm9Xw2Rb7Np4Hc6Jd", "lambda:fn/env:DB_PASSWORD", "salt")
