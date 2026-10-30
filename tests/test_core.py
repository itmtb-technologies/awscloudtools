"""Core contract tests: ids, manifests, the read-only guard, redaction, isolation."""
import json
import subprocess
import sys

import boto3
import pytest
from moto import mock_aws

from cloudtools.core import model
from cloudtools.core.aws import AwsEnv, WriteRefused, is_read_only
from cloudtools.core.capability import Manifest, ManifestError, capability
from cloudtools.core.collect import COLLECTORS, Snapshot, collect, collector
from cloudtools.core.runlog import RunLog, redact


def _ev():
    return [model.Evidence("ec2:DescribeSecurityGroups", "sg-1", "0.0.0.0/0 -> tcp/22")]


def test_fact_ids_are_deterministic_and_order_free():
    a = model.Fact("internet", "reaches", "i-1", "net.x", _ev(), {"ports": [22], "p": "tcp"})
    b = model.Fact("internet", "reaches", "i-1", "net.y", _ev(), {"p": "tcp", "ports": [22]})
    assert a.id == b.id and a.id.startswith("f-")
    assert a.id != model.Fact("internet", "reaches", "i-2", "net.x", _ev()).id


def test_fact_with_conditions_is_possible_and_needs_evidence():
    f = model.Fact("r1", "can_assume", "r2", "iam.x", _ev(), conditions=["aws:SourceIp"])
    assert f.status == "possible"
    with pytest.raises(ValueError):
        model.Fact("a", "reaches", "b", "x", [])
    with pytest.raises(ValueError):
        model.Fact("a", "pwns", "b", "x", _ev())


def test_finding_id_and_accepted_risk():
    f = model.Finding("net.open-admin-ports", {"id": "sg-1"}, "SSH open", "high", _ev(),
                      {"summary": "restrict"}, {"port": 22})
    assert f.id == model.Finding("net.open-admin-ports", {"id": "sg-1"}, "other", "low",
                                 _ev(), {}, {"port": 22}).id
    model.apply_accepted_risk(f, {model.ACCEPT_TAG: "bastion"})
    assert f.status == "accepted" and f.to_dict()["severity"]["contextual"] == "high"


def test_fingerprint_never_contains_value():
    fp = model.fingerprint("AKIAABCDEFGHIJKLMNOP", "salt")
    assert "AKIA" not in fp and fp.startswith("sha256:")
    assert model.redacted_preview("AKIAABCDEFGHIJKLMNOP") == "AKIA****"


def _m(**kw):
    base = dict(id="test.thing", title="A thing", kind="view",
                description="Reads a thing for the tests of the manifest rules.",
                permission="test:read")
    return Manifest(**{**base, **kw})


def test_manifest_rules():
    assert _m().problems() == []
    assert _m(mutating=True).problems()                     # mutating but read_only/agent
    assert _m(mutating=True, read_only=False, requires_approval=True,
              agent_visible=False).problems() == []
    assert _m(permission="").problems()                     # hosted needs a permission
    nested = {"type": "object", "additionalProperties": False,
              "properties": {"regions": {"type": "array"}}}
    assert _m(input_schema=nested).problems()               # agent tools are flat
    loose = {"type": "object", "additionalProperties": False,
             "properties": {"q": {"type": "string"}}}
    assert _m(input_schema=loose).problems()                # strings need maxLength
    with pytest.raises(ManifestError):
        capability(_m(id="Bad Id"))


@pytest.mark.parametrize("op,ok", [
    ("DescribeSecurityGroups", True), ("ListUsers", True), ("GetBucketPolicy", True),
    ("GenerateCredentialReport", True), ("GetCallerIdentity", True),
    ("GetObject", False), ("GetSecretValue", False), ("GetParameter", False),
    ("Decrypt", False), ("GetFunction", False), ("GenerateDataKey", False),
    ("RunInstances", False), ("PutBucketPolicy", False), ("DeleteUser", False),
    ("CreateSnapshot", False), ("AuthorizeSecurityGroupIngress", False),
])
def test_allowlist(op, ok):
    assert is_read_only(op) is ok


@mock_aws
def test_guard_refuses_writes_before_they_leave_and_logs_reads():
    log = RunLog("r-test")
    env = AwsEnv(region="eu-west-1", run_id="r-test", log=log)
    ec2 = env.client("ec2")
    ec2.describe_security_groups()
    with pytest.raises(WriteRefused):
        ec2.create_security_group(GroupName="x", Description="x")
    assert not boto3.client("ec2", region_name="eu-west-1").describe_security_groups(
        Filters=[{"Name": "group-name", "Values": ["x"]}])["SecurityGroups"]
    calls = [e for e in log.events if e["event"] == "api.call"]
    assert calls and calls[0]["action"] == "DescribeSecurityGroups"
    assert calls[0]["outcome"] == "ok"


def test_user_agent_carries_run_id():
    env = AwsEnv(region="eu-west-1", run_id="r-ua")
    assert "run/r-ua" in env.client("ec2").meta.config.user_agent_extra


def test_redaction():
    line = redact(json.dumps({"k": "AKIAABCDEFGHIJKLMNOP", "password": "hunter2"}))
    assert "AKIAABCDEFGHIJKLMNOP" not in line and "hunter2" not in line
    log = RunLog("r")
    rec = log.emit("x", note="secret=s3cr3tvalue")
    assert "s3cr3tvalue" not in json.dumps(rec)


@mock_aws
def test_collect_runs_once_per_region_and_turns_failures_into_misses():
    calls = []

    @collector("test.ok", ["ec2:DescribeVpcs"])
    def ok(env, region):
        calls.append(region)
        return env.client("ec2", region).describe_vpcs()["Vpcs"]

    @collector("test.global", ["iam:ListUsers"], scope="global")
    def glob(env, region):
        calls.append("G")
        return []

    @collector("test.boom", ["x:Y"])
    def boom(env, region):
        raise RuntimeError("nope")

    try:
        env = AwsEnv(region="eu-west-1")
        snap = collect(env, ["test.ok", "test.global", "test.boom"],
                       ["eu-west-1", "us-east-1"], "123456789012")
        assert sorted(calls) == ["G", "eu-west-1", "us-east-1"]
        assert set(snap.regions_of("test.ok")) == {"eu-west-1", "us-east-1"}
        assert [m.region for m in snap.missed("test.boom")] == ["eu-west-1", "us-east-1"]
        again = Snapshot.from_json(snap.to_json())
        assert again.to_json() == snap.to_json()
    finally:
        for k in ("test.ok", "test.global", "test.boom"):
            COLLECTORS.pop(k, None)


@mock_aws
def test_a_collector_that_writes_fails_the_run_loudly():
    """A write attempt is a bug, never a gap: collect() must not swallow it."""
    @collector("test.writer", ["ec2:DescribeVpcs"])
    def writer(env, region):
        return env.client("ec2", region).create_security_group(GroupName="x", Description="x")

    try:
        with pytest.raises(WriteRefused):
            collect(AwsEnv(region="eu-west-1"), ["test.writer"], ["eu-west-1"], "1")
    finally:
        COLLECTORS.pop("test.writer", None)


def test_core_does_not_import_tools():
    import pathlib
    core = pathlib.Path(__file__).parent.parent / "src" / "cloudtools" / "core"
    for p in core.rglob("*.py"):
        text = p.read_text()
        for tool in ("cloudtools.security", "cloudtools.creds", "from ..security",
                     "from ...security", "from ..creds"):
            if tool in text and p.name != "capability.py":
                pytest.fail(f"{p} imports {tool}")


@pytest.mark.parametrize("service,op,ok", [
    ("iam", "ListUsers", True), ("identitystore", "ListUsers", True),
    ("cognito-idp", "ListUsers", False), ("cognito-idp", "AdminGetUser", False),
    ("cognito-idp", "ListUsersInGroup", False), ("cognito-idp", "DescribeUserPool", True),
])
def test_end_user_listing_is_refused_by_service(service, op, ok):
    """Cognito users are a customer's own end users (emails, phones): counted, never listed."""
    assert is_read_only(op, service) is ok


@mock_aws
def test_guard_refuses_cognito_user_listing_before_it_leaves():
    env = AwsEnv(region="eu-west-1", run_id="r-test")
    with pytest.raises(WriteRefused):
        env.client("cognito-idp").list_users(UserPoolId="eu-west-1_x")


def _rep(findings, checks):
    return {"findings": findings, "accepted": [], "checks": checks, "run": {"run_id": "r-2"}}


def test_resolved_only_when_the_check_ran_fully_and_saw_its_input():
    """Not checked is not fixed: a finding whose check was excluded, errored, saw a gap or
    had no input this run is carried as not_rechecked, never counted as resolved."""
    from cloudtools.core import diff
    old = [{"id": f"fd-{c}", "check_id": c, "severity": {"base": "high"}} for c in
           ("fixed", "excluded", "errored", "partial", "no-input")]
    prev = {"findings": old, "accepted": [], "run": {"run_id": "r-1"}}
    rows = [{"id": "fixed", "status": "ran"}, {"id": "errored", "status": "error"},
            {"id": "partial", "status": "partial"},
            {"id": "no-input", "status": "ran", "stats": {"evaluated": False}}]
    rep = _rep([], rows)
    diff.apply(rep, prev)
    assert [f["id"] for f in rep["resolved"]] == ["fd-fixed"]
    assert sorted(f["id"] for f in rep["not_rechecked"]) == [
        "fd-errored", "fd-excluded", "fd-no-input", "fd-partial"]


def test_repo_checks_say_not_evaluated_without_repos():
    from cloudtools.security import scan
    from test_checks_table import akey, snap
    results, rows = scan.evaluate(snap(iam__access_keys=[akey("Active")]),
                                  {"include": ["cred.inventory", "cred.repo-secrets"]})
    by = {r["id"]: r for r in rows}
    assert by["cred.inventory"]["stats"]["evaluated"] is False
    assert by["cred.repo-secrets"]["stats"]["evaluated"] is False


def _finding(**over):
    from cloudtools.core.model import Evidence, Finding
    f = Finding("cve.inspector", {"id": "i-1", "type": "ec2_instance"}, "t", "high",
                [Evidence("inspector2:ListFindings", "i-1", "d")], {"summary": "patch"}, **over)
    return f.to_dict() | {"diff": "new"}


def test_report_v1_finding_fields_are_closed_and_typed():
    """Schema v1 freezes the finding: CVE and secret blocks are typed, an undocumented
    field fails, and a secret block can only hold a fingerprint, never a value."""
    import jsonschema
    from cloudtools.core.report import FINDING
    ok_cve = _finding(cve={"id": "CVE-2024-3094", "package": "xz", "installed_version": "5.6.0",
                           "fixed_version": "5.6.1", "cvss": 10.0, "source": "inspector"})
    jsonschema.validate(ok_cve, FINDING)
    ok_sec = _finding(secret={"detector": "aws-access-token", "fingerprint": "sha256:0123456789ab",
                              "preview": "AKIA****", "location": "lambda:fn/env:KEY"})
    jsonschema.validate(ok_sec, FINDING)
    for bad in (_finding() | {"surprise": 1},
                _finding(secret={"detector": "x", "fingerprint": "AKIAIOSFODNN7EXAMPLE",
                                 "preview": "AKIA****", "location": "l"}),
                _finding(cve={"id": "not-a-cve", "package": "p", "installed_version": "1",
                              "fixed_version": None, "cvss": 5, "source": "osv"})):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(bad, FINDING)


def test_findings_in_regions_not_scanned_are_not_resolved():
    """A one-region scan after an all-region scan must not 'resolve' the other regions'
    findings (a real account, 2026-10-27: 91 such findings, then shown as 'regressed')."""
    from cloudtools.core import diff
    def fd(i, region):
        return {"id": f"fd-{i}", "check_id": "c", "severity": {"base": "low"},
                "resource": {"id": f"r{i}", "region": region}}
    prev = {"findings": [fd(1, "ap-south-1"), fd(2, "us-east-1"), fd(3, "")],
            "accepted": [], "run": {"run_id": "r-1"}}
    rep = {"findings": [], "accepted": [], "checks": [{"id": "c", "status": "ran"}],
           "run": {"run_id": "r-2", "regions": ["ap-south-1"]}}
    diff.apply(rep, prev)
    assert sorted(f["id"] for f in rep["resolved"]) == ["fd-1", "fd-3"]   # scanned region, global
    assert [f["id"] for f in rep["not_rechecked"]] == ["fd-2"]


def test_profiles_accept_tiers_up_to_2_for_this_release():
    """Launch scope: tiers 0, 1 and 2. Tier 3 (data sampling) is refused; 2b is a
    separate opt-in command, not a max_tier."""
    from cloudtools.security import profiles
    for t in (0, 1, 2):
        assert profiles.validate({**profiles.load("quick"), "max_tier": t})["max_tier"] == t
    with pytest.raises(profiles.ProfileError):
        profiles.validate({**profiles.load("quick"), "max_tier": 3})


def test_local_store_writes_are_atomic(tmp_path):
    """A poller reading status.json while a scan rewrites it must never see an empty or
    partial file (an empty read made get_run_status say 'no such scan' under load)."""
    import threading
    from cloudtools.core.platform.standalone import LocalStore
    store = LocalStore(tmp_path)
    body = json.dumps({"state": "running", "pad": "x" * 200_000}).encode()
    store.put("runs/r/status.json", body)
    stop, bad = threading.Event(), []

    def writer():
        while not stop.is_set():
            store.put("runs/r/status.json", body)

    t = threading.Thread(target=writer)
    t.start()
    try:
        for _ in range(3000):
            got = store.get("runs/r/status.json")
            if got != body:
                bad.append(len(got or b""))
    finally:
        stop.set()
        t.join()
    assert not bad, f"{len(bad)} torn reads, e.g. lengths {bad[:5]}"



def test_local_store_rides_out_a_windows_busy_file(tmp_path, monkeypatch):
    """Windows raises PermissionError for a moment while a file is being replaced (the
    atomic test failed that way on windows-latest, 2026-10-29). macOS and Linux never
    do, so this simulates it: two busy reads, then the real one."""
    from pathlib import Path
    from cloudtools.core.platform.standalone import LocalStore
    store = LocalStore(tmp_path)
    store.put("runs/r/status.json", b"{}")
    real, busy = Path.read_bytes, iter([True, True])

    def flaky(self):
        if next(busy, False):
            raise PermissionError(13, "busy")
        return real(self)
    monkeypatch.setattr(Path, "read_bytes", flaky)
    assert store.get("runs/r/status.json") == b"{}"

    def always(self):
        raise PermissionError(13, "held open")
    monkeypatch.setattr(Path, "read_bytes", always)
    with pytest.raises(PermissionError):
        store.get("runs/r/status.json")

def test_run_log_lines_never_tear_under_parallel_emits(tmp_path):
    """Collectors emit from a thread pool. Windows doesn't make small appends atomic, so
    unserialised writes tore run.jsonl there (CI, windows-latest 3.12, 2026-10-28). On POSIX
    this passes even without the lock; the Windows CI job is the real check."""
    import threading
    from cloudtools.core.runlog import RunLog, file_sink
    path = tmp_path / "run.jsonl"
    log = RunLog("r-t", [file_sink(path)])
    pad = "x" * 3000

    def burst(i):
        for j in range(200):
            log.emit("api.call", n=i, j=j, pad=pad)

    ts = [threading.Thread(target=burst, args=(i,)) for i in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1600 and all(json.loads(line)["event"] == "api.call" for line in lines)


@pytest.mark.parametrize("key", ["runs/../../outside/x/status.json", "/etc/passwd", "runs//x",
                                 "runs/./x", ""])
def test_local_store_refuses_a_key_that_leaves_its_folder(tmp_path, key):
    """run_id reaches the key from an HTTP query (get_run_status); 0.1.3 read
    `runs/../../outside/x/status.json` from outside the output folder (review 2026-10-30)."""
    from cloudtools.core.platform.standalone import LocalStore
    store = LocalStore(tmp_path / "out")
    for op in (lambda: store.get(key), lambda: store.put(key, b"{}")):
        with pytest.raises(ValueError):
            op()


def test_csv_cells_cannot_start_a_formula():
    """A security group may be named `=HYPERLINK(...)` (AWS accepts it, dry run 2026-10-30)
    and its name is a CSV cell; a spreadsheet would run it."""
    import csv, io
    from cloudtools.core import publish
    f = {"id": "fd-1", "severity": {"base": "high", "contextual": "high"}, "status": "open",
         "check_id": "net.sg-open", "title": "+cmd", "remediation": {"summary": "@SUM(1)"},
         "resource": {"id": "sg-1", "name": "=HYPERLINK(CONCAT(CHAR(104)),CHAR(120))", "region": "-x"}}
    row = list(csv.reader(io.StringIO(publish.to_csv({"findings": [f], "accepted": []}).decode())))[1]
    assert not [c for c in row if c[:1] in ("=", "+", "-", "@", "\t", "\r")], row
    assert row[8] == "'=HYPERLINK(CONCAT(CHAR(104)),CHAR(120))"


@pytest.mark.parametrize("service,op", [
    # named Get*/BatchGet*, but they mint credentials or create something
    ("cognito-identity", "GetId"), ("cognito-identity", "GetCredentialsForIdentity"),
    ("cognito-identity", "GetOpenIdToken"), ("cognito-identity", "GetOpenIdTokenForDeveloperIdentity"),
    ("redshift", "GetClusterCredentials"), ("redshift", "GetClusterCredentialsWithIAM"),
    ("sso", "GetRoleCredentials"), ("lightsail", "GetInstanceAccessDetails"),
    # ... or read data, which the scanner never does
    ("dynamodb", "GetItem"), ("dynamodb", "BatchGetItem"), ("kinesis", "GetRecords"),
    ("dynamodbstreams", "GetRecords"), ("logs", "GetLogEvents"), ("athena", "GetQueryResults"),
    ("logs", "GetQueryResults"), ("glacier", "GetJobOutput"), ("kinesis-video-media", "GetMedia"),
    ("codecommit", "GetBlob"), ("codecommit", "GetFile"), ("ecr", "BatchGetImage"),
    ("ecr", "GetDownloadUrlForLayer"),
])
def test_guard_refuses_reads_that_mint_or_read_data(service, op):
    """The prefix allowlist let these through (review 2026-10-30). No collector calls one;
    the guard is what stops a future one."""
    assert is_read_only(op, service, tier=2) is False
