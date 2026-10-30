"""The GitHub variant end to end: the CLI over a moto lab, outputs, run log, diff on the
second run, snapshot replay with no AWS calls, doctor, policy, and the generic call."""
import json

import jsonschema
import pytest
from moto import mock_aws

from cloudtools.core.capability import all_capabilities, load_builtin
from cloudtools.cli import main
from test_security_scan import R, build_lab

load_builtin()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", R)
    with mock_aws():
        ids = build_lab()
        yield tmp_path, ids


def _scan(out, *extra):
    return main(["security", "scan", "--region", R, "--regions", R, "--out", str(out), *extra])


def _latest(out):
    from cloudtools.core.report import validate
    rid = json.loads((out / "runs/latest-security.json").read_text())["run_id"]
    rep = json.loads((out / f"runs/{rid}/report.json").read_text())
    assert validate(rep) == [], "every report must validate against schema v1"
    return rid, rep


def test_scan_writes_outputs_log_and_exit_code(lab, capsys):
    out, ids = lab
    code = _scan(out, "--profile", "full")
    rid, rep = _latest(out)
    assert code == 4 if rep["summary"]["highest_new"] == "critical" else code == 3
    run_dir = out / "runs" / rid
    for f in ("report.json", "report.html", "report.sarif", "findings.csv", "snapshot.json", "run.jsonl"):
        assert (run_dir / f).exists(), f
    events = [json.loads(line)["event"] for line in (run_dir / "run.jsonl").read_text().splitlines()]
    assert events[0] == "run.start" and events[-1] == "run.end"
    assert {"api.call", "check.start", "check.end", "graph.done"} <= set(events)
    assert "SENSITIVE" in (run_dir / "report.html").read_text()
    printed = capsys.readouterr().out
    assert "SENSITIVE" in printed and rid in printed


def test_lab_attack_path_and_chokepoint(lab):
    out, ids = lab
    _scan(out)
    _, rep = _latest(out)
    to_admin = [p for p in rep["paths"] if p["target"] == "admin_equivalent" and p["nodes"][1] == ids["bad"]]
    assert to_admin, "internet -> open SSH instance -> IMDSv1 role -> escalation -> admin"
    imds = next(f for f in rep["findings"] if f["check_id"] == "srv.imdsv1-enabled")
    assert imds["severity"] == {"base": "high", "contextual": "critical"} and imds["on_paths"]
    assert rep["chokepoints"] and rep["chokepoints"][0]["paths_broken"] >= 1


def test_second_run_is_unchanged_and_resolved_is_tracked(lab):
    out, _ = lab
    _scan(out)
    _, first = _latest(out)
    _scan(out)
    _, second = _latest(out)
    assert second["run"]["baseline"] == first["run"]["run_id"]
    assert {f["diff"] for f in second["findings"]} == {"unchanged"}
    assert second["summary"]["highest_new"] is None
    import boto3
    boto3.client("iam").delete_login_profile(UserName="lab-nomfa")
    _scan(out)
    _, third = _latest(out)
    assert any(f["check_id"] == "iam.user-no-mfa" for f in third["resolved"])
    # The diff tally counts resolved too (it read 0 on the lab teardown while 362 resolved).
    assert third["summary"]["diff"]["resolved"] == len(third["resolved"]) == third["summary"]["resolved"]


def test_evaluate_snapshot_reproduces_findings_without_aws(lab, monkeypatch):
    out, _ = lab
    _scan(out)
    rid, rep = _latest(out)
    snap = out / "runs" / rid / "snapshot.json"
    import botocore.client
    def no_aws(*a, **k):
        raise AssertionError("evaluate --snapshot made an AWS call")
    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", no_aws)
    main(["security", "evaluate", "--snapshot", str(snap), "--out", str(out / "replay"), "-q"])
    _, again = _latest(out / "replay")
    assert sorted(f["id"] for f in again["findings"]) == sorted(f["id"] for f in rep["findings"])


def test_sarif_is_valid_2_1_0_shape(lab):
    out, _ = lab
    _scan(out, "--profile", "ci")
    rid, rep = _latest(out)
    sarif = json.loads((out / "runs" / rid / "report.sarif").read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} <= rule_ids
    minimal = {"type": "object", "required": ["version", "runs"], "properties": {"runs": {
        "type": "array", "items": {"type": "object", "required": ["tool", "results"]}}}}
    jsonschema.validate(sarif, minimal)


def test_doctor_all_runnable_under_full_access(lab, capsys):
    out, _ = lab
    code = main(["security", "doctor", "--region", R, "--regions", R, "--out", str(out), "--json"])
    d = json.loads(capsys.readouterr().out)
    assert code == 0 and d["summary"]["blocked"] == 0 and d["matrix"]
    assert d["duration_ms"] < 60_000


def test_policy_has_actions_and_data_denies(tmp_path, capsys):
    main(["security", "policy", "--write", str(tmp_path)])
    pol = json.loads((tmp_path / "cloudtools-policy.json").read_text())
    allow, deny = pol["Statement"]
    assert "ec2:DescribeSecurityGroups" in allow["Action"] and "iam:GetCredentialReport" in allow["Action"]
    assert not any(a.startswith(("ec2:Run", "ec2:Create", "iam:Create", "s3:Put")) for a in allow["Action"])
    assert {"s3:GetObject", "secretsmanager:GetSecretValue", "kms:Decrypt"} <= set(deny["Action"])
    assert "AWS admin" in (tmp_path / "ask-your-admin.txt").read_text() or \
        "permissions" in (tmp_path / "ask-your-admin.txt").read_text()


def test_generic_call_reaches_views(lab, capsys):
    out, _ = lab
    _scan(out, "-q")
    capsys.readouterr()
    main(["call", "security.list_findings", "min_severity=high", "page_size=3", "--out", str(out)])
    res = json.loads(capsys.readouterr().out)
    assert res["findings"] and len(res["findings"]) <= 3
    assert all(f["severity"]["contextual"] in ("high", "critical") for f in res["findings"])
    fid = res["findings"][0]["id"]
    main(["call", "security.explain_finding", f"finding_id={fid}", "--out", str(out)])
    ex = json.loads(capsys.readouterr().out)
    assert ex["finding"]["id"] == fid and "notice" in ex


def test_every_capability_valid_and_agent_tools_fit_the_gateway():
    caps = all_capabilities()
    assert {c.manifest.id for c in caps} >= {"security.scan", "security.run_check",
                                             "security.list_findings", "security.chokepoints",
                                             "security.doctor", "security.generate_policy"}
    for c in caps:
        assert c.manifest.problems() == []
        if c.manifest.mutating:
            assert not c.manifest.agent_visible


def test_usage_error_exits_64_not_2():
    """2 means 'a new medium finding'; a typo in a CI pipeline must not look like one."""
    with pytest.raises(SystemExit) as e:
        main(["security", "scan", "--no-such-flag"])
    assert e.value.code == 64


def test_async_scan_returns_at_once_and_status_tracks_it(lab):
    """R11.4: a scan started with wait=false returns a run id immediately; get_run_status
    goes queued/running -> succeeded, and the report equals a synchronous scan's."""
    import time
    from cloudtools.core.capability import get
    from cloudtools.core.platform.standalone import StandalonePlatform
    out, _ = lab
    plat = StandalonePlatform(region=R, output=str(out))
    started = get("security.scan").fn(plat, profile="quick", regions=R, wait=False)
    assert started["state"] in ("queued", "running") and started["run_id"].startswith("r-")
    states = []
    for _ in range(300):
        st = get("security.get_run_status").fn(plat, run_id=started["run_id"])
        states.append(st["state"])
        if st["state"] in ("succeeded", "failed"):
            break
        time.sleep(0.1)
    assert st["state"] == "succeeded", st
    assert st["summary"]["open"] >= 1 and st["exit_code"] in (0, 2, 3, 4)
    plat.join()
    sync = get("security.scan").fn(StandalonePlatform(region=R, output=str(out / "sync")),
                                   profile="quick", regions=R, full=True)
    rep = json.loads((out / f"runs/{started['run_id']}/report.json").read_text())
    assert sorted(f["id"] for f in rep["findings"]) == sorted(f["id"] for f in sync["findings"])


def test_failed_scan_is_reported_as_failed(tmp_path):
    from cloudtools.core.capability import get
    from cloudtools.core.platform.standalone import StandalonePlatform
    plat = StandalonePlatform(region=R, output=str(tmp_path))
    bad = tmp_path / "broken.json"
    bad.write_text("{not json", encoding="utf-8")
    rid = "r-test-failed"
    from cloudtools.security import profiles, runner
    with pytest.raises(Exception):
        runner.run_scan(plat, profiles.load("quick"), snapshot_text=bad.read_text(), run_id=rid)
    st = get("security.get_run_status").fn(plat, run_id=rid)
    assert st["state"] == "failed" and st["error"]


def test_why_reachable_and_find_paths_on_the_lab(lab, capsys):
    out, ids = lab
    _scan(out, "-q")
    capsys.readouterr()
    main(["call", "security.why_reachable", f"resource={ids['bad']}", "--out", str(out)])
    why = json.loads(capsys.readouterr().out)
    assert why["total"] >= 1 and all(p["nodes"][-1] == ids["bad"] for p in why["paths"])
    main(["call", "security.find_paths", "entry=internet", "target=admin_equivalent", "--out", str(out)])
    fp = json.loads(capsys.readouterr().out)
    assert fp["total"] >= 1 and all(p["entry"] == "internet" for p in fp["paths"])
    main(["call", "security.why_reachable", f"resource={ids['good']}", "--out", str(out)])
    assert json.loads(capsys.readouterr().out)["total"] == 0, "the hardened twin is not reachable"


class _Stub:
    """A client whose one operation returns or raises what AWS really does for that state."""
    def __init__(self, op, result=None, code=None, msg=""):
        self.op, self.result, self.code, self.msg = op, result, code, msg

    def __getattr__(self, name):
        from botocore.exceptions import ClientError
        def call(**kw):
            if self.code:
                raise ClientError({"Error": {"Code": self.code, "Message": self.msg}}, name)
            return self.result
        return call


def test_doctor_reports_services_on_off_not_allowed():
    """A real account showed 'macie denied' and 'securityhub ok' when both were simply switched off."""
    from cloudtools.security.doctor import service_state
    cases = {
        ("guardduty", _Stub("list_detectors", {"DetectorIds": []})): "off",
        ("guardduty", _Stub("list_detectors", {"DetectorIds": ["d1"]})): "on",
        ("securityhub", _Stub("describe_hub", code="InvalidAccessException",
                              msg="Account 1 is not subscribed to AWS Security Hub")): "off",
        ("securityhub", _Stub("describe_hub", {"HubArn": "arn"})): "on",
        ("inspector2", _Stub("batch_get_account_status",
                             {"accounts": [{"state": {"status": "DISABLED"}}]})): "off",
        ("inspector2", _Stub("batch_get_account_status",
                             {"accounts": [{"state": {"status": "ENABLED"}}]})): "on",
        ("macie", _Stub("get_macie_session", code="AccessDeniedException",
                        msg="Macie is not enabled")): "off",
        ("macie", _Stub("get_macie_session", code="AccessDeniedException",
                        msg="User is not authorized to perform: macie2:GetMacieSession")): "not allowed",
        ("macie", _Stub("get_macie_session", {"status": "ENABLED"})): "on",
        ("access-analyzer", _Stub("list_analyzers", {"analyzers": []})): "off",
        ("access-analyzer", _Stub("list_analyzers", {"analyzers": [{"status": "ACTIVE"}]})): "on",
    }
    for (name, client), want in cases.items():
        assert service_state(name, client) == want, (name, client.result, client.msg)


def test_doctor_text_names_the_real_policy_flag():
    from cloudtools.security.doctor import to_text
    d = {"caller": "c", "account": "1", "regions": ["r"], "duration_ms": 1,
         "summary": {"runnable": 0, "partial": 0, "blocked": 1},
         "matrix": [{"check": "x", "status": "blocked", "missing_actions": ["a:B"], "regions_denied": []}],
         "services": {}, "fixes": [{"option": 1, "how": "h"}]}
    assert "policy --write" in to_text(d) and "--out ." not in to_text(d)


def test_scan_preflight_skips_blocked_checks_as_gaps(lab, monkeypatch):
    """R4.5: a check whose inputs are denied everywhere is not run; it becomes a gap that
    names the missing permission, and its old findings are 'not re-checked', not 'resolved'."""
    from cloudtools.security import doctor
    out, _ = lab
    _scan(out, "-q")
    real = doctor._probe
    monkeypatch.setattr(doctor, "_probe", lambda env, region, svc, op, kw:
                        "denied" if op == "describe_security_groups" else real(env, region, svc, op, kw))
    _scan(out, "-q")
    _, rep = _latest(out)
    blocked = {g["check_id"] for g in rep["gaps"] if "blocked" in g["why"]}
    # Only security groups are denied: checks reading nothing else are blocked and skipped...
    assert {"net.sg-all-traffic-open", "net.default-sg-has-rules"} <= blocked
    assert all("ec2:DescribeSecurityGroups" in g["needs"] for g in rep["gaps"]
               if g["check_id"] in blocked)
    rows = {r["id"]: r["status"] for r in rep["checks"]}
    assert not blocked & set(rows), "a blocked check must not run"
    # A check that also reads routes, NACLs and instances is not blocked by this alone.
    # (Here the collector itself still succeeds, since only the probe is faked; the
    # partial -> not re-checked rule is covered by test_core and the blind-region test.)
    assert "net.open-admin-ports" not in blocked


def test_doctor_finds_probes_declared_in_a_collectors_own_module():
    """A collector module declares `PROBES = {key: (service, op, kwargs)}` next to its
    collectors; the doctor looks it up at run time, so import order can't lose it (B1 found
    that doctor imports scan before defining its own PROBES)."""
    import sys
    import types
    from cloudtools.core.collect import COLLECTORS, collector
    from cloudtools.security import doctor
    mod = types.ModuleType("cloudtools_test_probe_mod")
    mod.PROBES = {"test.thing": ("sts", "get_caller_identity", {})}
    sys.modules[mod.__name__] = mod
    def thing(env, region):
        return []
    thing.__module__ = mod.__name__
    collector("test.thing", ["sts:GetCallerIdentity"])(thing)
    try:
        assert doctor.probe_for("test.thing") == ("sts", "get_caller_identity", {})
        assert doctor.probe_for("ec2.security_groups")[1] == "describe_security_groups"
    finally:
        COLLECTORS.pop("test.thing")
        sys.modules.pop(mod.__name__)


def test_cli_has_serve_and_cve_commands(capsys):
    """Merge-time wiring: `cloudtools serve` (HTTP API, loopback only) and
    `cloudtools cve update-db` (offline OSV download) are reachable from the main CLI."""
    from cloudtools.cli import build_parser
    from cloudtools import serve_cli
    a = build_parser().parse_args(["serve", "--port", "8123"])
    assert a.fn is serve_cli.cmd_serve and a.port == 8123
    assert main(["cve", "update-db", "--help"]) == 0
    assert "OSV" in capsys.readouterr().out
    assert main(["cve", "no-such-cmd"]) == 64


def test_tier_flag_never_selects_nothing_new():
    """`--tier N` with the default (quick) profile must run tier-N checks. On a real account
    (2026-10-28) `--tier 2` ran no tier-1 check: they were mvp=False, and quick runs MVP only."""
    from cloudtools.security import profiles, scan
    for tier in (1, 2):
        prof = {**profiles.load("quick"), "max_tier": tier}
        picked = scan.select(prof["include"], prof["exclude"], tier, prof["mvp_only"])
        assert {c.spec.tier for c in picked} >= set(range(tier + 1)), f"quick at tier {tier}"


def test_mq_probe_uses_a_page_size_mq_accepts():
    """MQ ListBrokers rejects MaxResults < 5 (BadRequest), which the doctor counted as
    'allowed': the MQ probe proved nothing and logged 17 errors per scan (2026-10-28)."""
    from cloudtools.security import doctor, scan  # noqa: F401
    assert doctor.probe_for("mq.users")[2].get("MaxResults", 5) >= 5


def test_version_flag_prints_the_package_version(capsys):
    from cloudtools import __version__
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"cloudtools {__version__}"


def test_doctor_fixes_point_only_at_files_that_ship():
    """0.1.3 offered "Deploy the scanner-role CloudFormation stack" at
    infra/onboarding/aws-security-readonly.yaml, which never existed (review 2026-10-30)."""
    from pathlib import Path
    from cloudtools.security import doctor, profiles
    root = Path(__file__).resolve().parents[1]
    fixes = doctor.fixes(["iam:ListUsers"], profiles.load("quick"))
    assert [f["option"] for f in fixes] == list(range(1, len(fixes) + 1))
    for f in fixes:
        if "template" in f:
            assert (root / f["template"]).exists(), f["template"]
