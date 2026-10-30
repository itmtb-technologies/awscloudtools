"""Tier 2 (`cve.`) and the two OS checks, offline: recorded AWS responses replayed through
the real, guarded AwsEnv clients (tests/fixtures/cve/aws_*.json, hand-built in the
documented response shapes), and a pinned OSV fixture (tests/fixtures/cve/osv). No call
leaves the process: a before-call hook answers from the fixture, after botocore has
validated the request and the read-only guard has passed it."""
import io
import json
import socket
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from botocore.awsrequest import AWSResponse

from cloudtools.core.aws import AwsEnv
from cloudtools.core.collect import Snapshot, collect
from cloudtools.core.report import validate
from cloudtools.security import graph, scan
from cloudtools.security.checks import CHECKS, select

FIX = Path(__file__).parent / "fixtures" / "cve"
OSV = str(FIX / "osv")
R = "eu-west-1"
ACCT = "123456789012"
AT = "2026-10-27T00:00:00Z"
KEYS = ["ssm.instance_information", "ssm.patch_states", "ssm.inventory_applications",
        "inspector2.findings"]
# Checks whose positive and negative recorded cases live in this file (test_checks_table).
TESTED_HERE = {"srv.os-end-of-life", "srv.software-not-visible", "cve.inspector",
               "cve.missing-patches", "cve.osv-packages"}
TIER2 = {**scan.QUICK, "max_tier": 2, "settings": {"cve.osv-packages": {"db_path": OSV}}}


def ec2(id_, state="running", name=None):
    return {"id": id_, "state": state, "tags": {}, "name": name or id_, "public_ip": "",
            "subnet": "subnet-1", "vpc": "vpc-1", "sgs": [], "imds_v1": False,
            "profile_arn": "", "image_id": "ami-1", "key_name": "", "launch_time": ""}


# ------------------------------------------------------------------ fixture replay
def replay(env, fixture: dict, subst: dict | None = None):
    """Answer every ssm / inspector2 call on env's clients from `fixture`. An operation the
    fixture does not name fails the test: nothing unplanned is ever called."""
    text = json.dumps(fixture)
    for k, v in (subst or {}).items():
        text = text.replace("{" + k + "}", v)
    fx = json.loads(text)
    calls = []

    def answer(model, params, **_):
        op = f"{model.service_model.endpoint_prefix}:{model.name}"
        calls.append(op)
        body = json.loads(params.get("body") or b"{}")
        rule = fx.get(op)
        assert rule is not None, f"unplanned call {op}"
        token = body.get("NextToken") or body.get("nextToken")
        if op == "ssm:ListInventoryEntries":
            rule = rule.get(body["InstanceId"] + (f"#{token}" if token else ""))
        elif op == "ssm:DescribeInstancePatchStates":
            rule = {"InstancePatchStates": [s for s in rule["InstancePatchStates"]
                                            if s["InstanceId"] in body["InstanceIds"]]}
        elif isinstance(rule, list):
            pages, rule = rule, rule[0]
            for n, pg in enumerate(pages[:-1]):
                if (pg.get("NextToken") or pg.get("nextToken")) == token:
                    rule = pages[n + 1]
        if "error" in rule:
            return (AWSResponse("https://x", 400, {}, None),
                    {"Error": {"Code": rule["error"], "Message": "denied by fixture"},
                     "ResponseMetadata": {"HTTPStatusCode": 400}})
        return AWSResponse("https://x", 200, {}, None), {**rule, "ResponseMetadata": {"HTTPStatusCode": 200}}

    for svc in ("ssm", "inspector2"):
        env.client(svc, R).meta.events.register("before-call.*.*", answer)
    return calls


@pytest.fixture(autouse=True)
def fake_creds(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": R}.items():
        monkeypatch.setenv(k, v)


def recorded(name: str, extra: dict | None = None, keys=KEYS, subst=None) -> Snapshot:
    env = AwsEnv(region=R, run_id="r-cve-test")
    replay(env, json.loads((FIX / name).read_text(encoding="utf-8")), subst)
    snap = collect(env, keys, [R], ACCT)
    snap.meta = {"collected_at": AT}
    for k, v in (extra or {}).items():
        snap.data[k] = {R: v}
    return snap


POS_EC2 = [ec2("i-0ubuntu18", name="web-18"), ec2("i-0debian12", name="api-12"),
           ec2("i-0al2023"), ec2("i-0lost"), ec2("i-0empty"), ec2("i-0bsd"), ec2("i-0nearly"),
           ec2("i-0nossm", name="legacy"), ec2("i-0stopped", "stopped")]


@pytest.fixture(scope="module")
def pos():
    import os
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    return recorded("aws_positive.json", {"ec2.instances": POS_EC2})


@pytest.fixture(scope="module")
def neg():
    import os
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    return recorded("aws_negative.json", {"ec2.instances": [ec2("i-0debian12")]})


def run(snap, profile=TIER2):
    results, rows = scan.evaluate(snap, profile)
    rep = scan.build_report(snap, results, rows, profile, {
        "run_id": "r-cve", "tool_version": "t", "started_at": "", "ended_at": "",
        "platform": "standalone", "initiator": "test", "caller": "test", "profile": "t"})
    graph.analyse(rep, profile)
    return rep, results


def hits(rep, cid):
    return [f for f in rep["findings"] if f["check_id"] == cid]


def gaps(rep, cid):
    return [g for g in rep["gaps"] if g["check_id"] == cid]


# ------------------------------------------------------------------ collectors
def test_collectors_normalise_recorded_responses(pos):
    info = pos.get("ssm.instance_information", R)
    assert [i["id"] for i in info][:2] == ["i-0al2023", "i-0bsd"] and len(info) == 7, "both pages read"
    assert pos.get("ssm.patch_states", R)["states"]["i-0ubuntu18"]["critical"] == 2
    assert "i-0lost" not in pos.get("ssm.patch_states", R)["managed"], "only online agents"
    inv = pos.get("ssm.inventory_applications", R)
    assert [e["name"] for e in inv["i-0debian12"]["entries"]] == ["bash", "curl", "openssl", "xz-utils"]
    assert inv["i-0nearly"] == {"denied": "denied", "entries": []}
    assert inv["i-0al2023"]["entries"][0]["release"] == "1.amzn2023.0.12"
    ins = pos.get("inspector2.findings", R)
    assert ins["status"] == {"account": "ENABLED", "ec2": "ENABLED", "ecr": "ENABLED", "lambda": "DISABLED"}
    by = {f["vuln_id"]: f for f in ins["findings"]}
    assert len(by) == 3, "both ListFindings pages read"
    assert by["CVE-2023-38545"]["packages"] == [{"name": "curl", "version": "7.58.0-2ubuntu3.24",
                                                 "fixed": "7.58.0-2ubuntu3.25"}]
    assert by["CVE-2024-6387"]["packages"][0]["fixed"] is None, "NotAvailable is no fix"
    assert by["CVE-2024-3094"]["resource_type"] == "ecr_image"
    assert by["CVE-2024-3094"]["resource_name"] == "shop/api:v1.4"


def test_inspector_off_makes_no_list_findings_call():
    env = AwsEnv(region=R, run_id="r")
    calls = replay(env, json.loads((FIX / "aws_negative.json").read_text(encoding="utf-8")))
    collect(env, ["inspector2.findings"], [R], ACCT)
    assert calls == ["inspector2:BatchGetAccountStatus"]


def test_every_collector_call_is_a_guarded_read():
    from cloudtools.core.aws import is_read_only
    for op in ("DescribeInstanceInformation", "DescribeInstancePatchStates",
               "ListInventoryEntries", "BatchGetAccountStatus", "ListFindings"):
        assert is_read_only(op)


# ------------------------------------------------------------------ tier selection
def test_tier_selection_through_max_tier():
    t0 = {c.spec.id for c in select(max_tier=0)}
    t2 = {c.spec.id for c in select(max_tier=2)}
    cve = {"cve.inspector", "cve.missing-patches", "cve.osv-packages"}
    assert {"srv.os-end-of-life", "srv.software-not-visible"} <= t0
    assert not cve & t0 and cve <= t2
    assert all(CHECKS[c].spec.tier == 2 for c in cve)
    _, rows = scan.evaluate(Snapshot(ACCT, [R], {}), {**scan.QUICK, "max_tier": 0})
    assert not {r["id"] for r in rows} & cve


# ------------------------------------------------------------------ srv.os-end-of-life
def test_os_eol_positive(pos):
    rep, res = run(pos)
    by = {f["resource"]["id"]: f for f in hits(rep, "srv.os-end-of-life")}
    assert by["i-0ubuntu18"]["severity"]["base"] == "high" and "2023-05-31" in by["i-0ubuntu18"]["title"]
    assert by["i-0ubuntu18"]["resource"]["name"] == "web-18"
    assert any("ubuntu.com/about/release-cycle" in e["resource"] for e in by["i-0ubuntu18"]["evidence"])
    assert by["i-0lost"]["severity"]["base"] == "high", "CentOS 7, last reported OS"
    assert by["i-0nearly"]["severity"]["base"] == "low", "Windows 2016: 77 days left"
    assert "i-0debian12" not in by and "i-0al2023" not in by and "i-0empty" not in by
    g = gaps(rep, "srv.os-end-of-life")
    assert any("FreeBSD 14.1" in x["what"] for x in g), "unknown release is a gap"
    assert any("without SSM" in x["what"] and x["what"].startswith("OS of 1 ") for x in g)


def test_os_eol_negative(neg):
    rep, res = run(neg)
    assert hits(rep, "srv.os-end-of-life") == [] and gaps(rep, "srv.os-end-of-life") == []
    assert res["srv.os-end-of-life"].stats["evaluated"] is True


def test_os_eol_dates_are_data_with_sources():
    from cloudtools.security.checks.vuln import data_file
    d = data_file("os_eol.json")
    assert d["entries"] and all(e["source"].startswith("https://") and e["eol"] for e in d["entries"])
    src = (Path(__file__).parents[1] / "src/cloudtools/security/checks/vuln.py").read_text(encoding="utf-8")
    import re
    assert not re.search(r"20\d\d-\d\d-\d\d", src), "no end-of-life date hard-coded in the check"


# ------------------------------------------------------------------ srv.software-not-visible
def test_software_not_visible_positive(pos):
    rep, _ = run(pos)
    by = {f["resource"]["id"]: f for f in hits(rep, "srv.software-not-visible")}
    assert set(by) == {"i-0nossm", "i-0lost", "i-0empty"}
    assert "not registered with SSM" in by["i-0nossm"]["title"]
    assert "ConnectionLost" in by["i-0lost"]["title"]
    assert "Inventory is empty" in by["i-0empty"]["title"]
    g = gaps(rep, "srv.software-not-visible")
    assert {x["what"].split("(")[-1].rstrip(")") for x in g} >= {"i-0nossm", "i-0lost", "i-0empty", "i-0nearly"}
    assert all("AWS-GatherSoftwareInventory" in x["why"] for x in g if "i-0nearly" not in x["what"])
    assert next(x for x in g if "i-0nearly" in x["what"])["needs"] == ["ssm:ListInventoryEntries"]


def test_software_not_visible_negative(neg):
    rep, _ = run(neg)
    assert hits(rep, "srv.software-not-visible") == [] and gaps(rep, "srv.software-not-visible") == []


# ------------------------------------------------------------------ cve.inspector
def test_inspector_positive_maps_the_cve_block(pos):
    rep, res = run(pos)
    fs = {f["cve"]["id"]: f for f in hits(rep, "cve.inspector")}
    assert set(fs) == {"CVE-2023-38545", "CVE-2024-6387", "CVE-2024-3094"}
    assert fs["CVE-2023-38545"]["cve"] == {"id": "CVE-2023-38545", "package": "curl",
                                           "installed_version": "7.58.0-2ubuntu3.24",
                                           "fixed_version": "7.58.0-2ubuntu3.25", "cvss": 9.8,
                                           "source": "inspector"}
    assert fs["CVE-2024-6387"]["severity"]["base"] == "critical"
    assert fs["CVE-2024-3094"]["resource"]["type"] == "ecr_image"
    assert all(f["evidence"] for f in fs.values())
    g = gaps(rep, "cve.inspector")
    assert len(g) == 1 and "LAMBDA" in g[0]["why"] and "free trial" in g[0]["why"]
    assert res["cve.inspector"].stats["evaluated"] is True
    edges = {(f["from"], f["to"]) for f in rep["facts"] if f["type"] == "has_vulnerability"}
    assert ("i-0ubuntu18", "vuln:cve.inspector:i-0ubuntu18") in edges


def test_inspector_off_is_a_gap_never_clean(neg):
    rep, res = run(neg)
    assert hits(rep, "cve.inspector") == []
    g = gaps(rep, "cve.inspector")
    assert len(g) == 1 and "not enabled" in g[0]["why"] and "not a clean one" in g[0]["why"]
    assert "aws inspector2 enable --region eu-west-1 --resource-types EC2 ECR LAMBDA" in g[0]["why"]
    assert "Cost:" in g[0]["why"]
    assert res["cve.inspector"].stats["evaluated"] is False
    assert next(r for r in rep["checks"] if r["id"] == "cve.inspector")["status"] == "partial"


def test_inspector_on_with_no_findings_is_clean():
    snap = Snapshot(ACCT, [R], {"inspector2.findings": {R: {"status": {
        "account": "ENABLED", "ec2": "ENABLED", "ecr": "ENABLED", "lambda": "ENABLED"},
        "findings": []}}}, meta={"collected_at": AT})
    rep, res = run(snap)
    assert hits(rep, "cve.inspector") == [] and gaps(rep, "cve.inspector") == []
    assert res["cve.inspector"].stats["evaluated"] is True



def _insp(*rows):
    """Inspector snapshot from (resource, cve, severity, cvss, [(package, version, fixed)])."""
    return Snapshot(ACCT, [R], {"inspector2.findings": {R: {"status": {
        "account": "ENABLED", "ec2": "ENABLED", "ecr": "ENABLED", "lambda": "ENABLED"},
        "findings": [{"arn": f"arn:insp:{rid}:{vid}", "vuln_id": vid, "severity": sev,
                      "score": cvss, "cvss": cvss, "title": vid, "resource_type": "ec2_instance",
                      "resource_id": rid, "resource_name": rid, "fix_available": "YES",
                      "packages": [{"name": n, "version": v, "fixed": fx} for n, v, fx in pk]}
                     for rid, vid, sev, cvss, pk in rows]}}}, meta={"collected_at": AT})


# One finding per CVE made 4,222 findings on one lab host, 3,841 of them its kernel
# (2026-10-29). One upgrade closes a package's CVEs, so a finding is one package on one host.
def test_inspector_groups_cves_by_package_on_each_resource():
    k = ("linux-image-aws", "5.15.0.1084", None)
    rep, res = run(_insp(
        ("i-1", "CVE-2024-0001", "MEDIUM", 5.5, [("linux-image-aws", "5.15.0.1084", "5.15.0.1090")]),
        ("i-1", "CVE-2024-0002", "CRITICAL", 9.8, [("linux-image-aws", "5.15.0.1084", "5.15.0.1100")]),
        ("i-1", "CVE-2024-0003", "HIGH", 7.0, [k]),
        ("i-1", "CVE-2024-0004", "LOW", 2.0, [("curl", "7.81.0", "7.81.1")]),
        ("i-2", "CVE-2024-0002", "CRITICAL", 9.8, [("linux-image-aws", "5.15.0.1084", "5.15.0.1100")])))
    fs = {(f["resource"]["id"], f["cve"]["package"]): f for f in hits(rep, "cve.inspector")}
    assert set(fs) == {("i-1", "linux-image-aws"), ("i-1", "curl"), ("i-2", "linux-image-aws")}
    kern = fs[("i-1", "linux-image-aws")]
    assert kern["severity"]["base"] == "critical"
    assert kern["cve"]["id"] == "CVE-2024-0002" and kern["cve"]["cvss"] == 9.8
    assert kern["cve"]["ids"] == ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"]
    assert kern["cve"]["fixed_version"] == "5.15.0.1100"       # the version that clears them
    assert "3 known vulnerabilities" in kern["title"]
    assert "fixes 2 of 3" in kern["remediation"]["summary"]
    assert "1 has no fixed version yet" in kern["remediation"]["summary"]
    two = run(_insp(*[("i-1", f"CVE-2024-{i:04d}", "HIGH", 7.0, [("vim", "8.0", "8.1")])
                      for i in range(1200)]))[0]
    (v,) = hits(two, "cve.inspector")
    assert v["title"].startswith("1,200 known vulnerabilities in vim")
    assert v["remediation"]["summary"] == "Update vim to 8.1 or later; that fixes all 1,200."
    assert len(kern["evidence"]) == 3
    assert fs[("i-1", "curl")]["title"].startswith("CVE-2024-0004 in curl")   # one CVE reads as before
    assert res["cve.inspector"].stats["findings"] == 3 and res["cve.inspector"].stats["cves"] == 5
    vuln = {n["id"]: n for n in rep["nodes"] if n["id"].startswith("vuln:cve.inspector:")}
    assert "4" in json.dumps(vuln["vuln:cve.inspector:i-1"])   # the host's CVE count, not groups


def test_inspector_group_id_is_stable_when_a_cve_is_added():
    one = run(_insp(("i-1", "CVE-2024-0001", "HIGH", 7.0, [("openssl", "3.0.2", "3.0.3")])))[0]
    two = run(_insp(("i-1", "CVE-2024-0001", "HIGH", 7.0, [("openssl", "3.0.2", "3.0.3")]),
                    ("i-1", "CVE-2024-0009", "HIGH", 7.5, [("openssl", "3.0.2", "3.0.4")])))[0]
    assert [f["id"] for f in hits(one, "cve.inspector")] == [f["id"] for f in hits(two, "cve.inspector")]


def test_inspector_cve_in_two_packages_is_reported_on_both():
    rep, _ = run(_insp(("i-1", "CVE-2023-38545", "CRITICAL", 9.8,
                        [("curl", "7.58.0", "7.58.1"), ("libcurl4", "7.58.0", "7.58.1")])))
    assert sorted(f["cve"]["package"] for f in hits(rep, "cve.inspector")) == ["curl", "libcurl4"]

# ------------------------------------------------------------------ cve.missing-patches
def test_missing_patches_positive(pos):
    rep, _ = run(pos)
    by = {f["resource"]["id"]: f for f in hits(rep, "cve.missing-patches")}
    assert set(by) == {"i-0ubuntu18", "i-0al2023"}
    assert by["i-0ubuntu18"]["severity"]["base"] == "high" and "2 critical" in by["i-0ubuntu18"]["title"]
    assert by["i-0al2023"]["severity"]["base"] == "low"
    assert "critical non-compliant 2" in by["i-0ubuntu18"]["evidence"][0]["detail"]
    no_scan = {g["what"] for g in gaps(rep, "cve.missing-patches")}
    assert {w.split("(")[-1].rstrip(")") for w in no_scan} == {"i-0empty", "i-0bsd", "i-0nearly"}


def test_missing_patches_negative(neg):
    rep, _ = run(neg)
    assert hits(rep, "cve.missing-patches") == [] and gaps(rep, "cve.missing-patches") == []


# ------------------------------------------------------------------ cve.osv-packages
def test_osv_positive_and_deduplicated_against_inspector(pos):
    rep, res = run(pos)
    fs = hits(rep, "cve.osv-packages")
    assert [(f["resource"]["id"], f["cve"]["id"]) for f in fs] == [("i-0debian12", "CVE-2024-0727")]
    assert fs[0]["cve"] == {"id": "CVE-2024-0727", "package": "openssl",
                            "installed_version": "3.0.11-1~deb12u1",
                            "fixed_version": "3.0.11-1~deb12u2", "cvss": None, "source": "osv"}
    st = res["cve.osv-packages"].stats
    assert st["duplicates_of_inspector"] == 1, "curl CVE-2023-38545 on i-0ubuntu18 is Inspector's"
    both = [f for f in rep["findings"] if f["resource"]["id"] == "i-0ubuntu18" and (f.get("cve") or {}).get("id") == "CVE-2023-38545"]
    assert [f["check_id"] for f in both] == ["cve.inspector"], "one finding per CVE per resource (R5.3)"
    g = {x["what"] for x in gaps(rep, "cve.osv-packages")}
    assert any("Amazon Linux 2023" in w for w in g) and any("FreeBSD" in w for w in g)
    assert any("i-0nearly" in w for w in g)


def test_osv_without_inspector_reports_the_duplicate_itself(pos):
    snap = Snapshot(pos.account, pos.regions, {k: v for k, v in pos.data.items()
                                               if k != "inspector2.findings"}, meta=pos.meta)
    rep, res = run(snap, {**TIER2, "exclude": ["cve.inspector"]})
    ids = {(f["resource"]["id"], f["cve"]["id"]) for f in hits(rep, "cve.osv-packages")}
    assert ids == {("i-0debian12", "CVE-2024-0727"), ("i-0ubuntu18", "CVE-2023-38545")}
    assert res["cve.osv-packages"].stats["duplicates_of_inspector"] == 0


def test_osv_negative(neg):
    rep, res = run(neg)
    assert hits(rep, "cve.osv-packages") == [] and gaps(rep, "cve.osv-packages") == []
    assert res["cve.osv-packages"].stats["packages"] == 2


def test_osv_without_database_is_a_gap(pos, tmp_path):
    rep, res = run(pos, {**TIER2, "settings": {"cve.osv-packages": {"db_path": str(tmp_path / "none")}}})
    assert hits(rep, "cve.osv-packages") == []
    g = gaps(rep, "cve.osv-packages")
    assert len(g) == 1 and "cloudtools cve update-db" in g[0]["why"]
    assert res["cve.osv-packages"].stats == {"evaluated": False}


def test_osv_matching_makes_no_network_call(pos, monkeypatch):
    def no(*a, **k):
        raise AssertionError("network use during evaluation")
    monkeypatch.setattr(socket.socket, "connect", no)
    monkeypatch.setattr(socket, "create_connection", no)
    rep, _ = run(pos)
    assert hits(rep, "cve.osv-packages")


def test_version_ordering_and_ranges():
    from cloudtools.security.checks.vuln import affected, vercmp
    assert vercmp("3.0.11-1~deb12u1", "3.0.11-1~deb12u2") < 0
    assert vercmp("1.0~rc1", "1.0") < 0 and vercmp("1:0.9", "2.0") > 0
    assert vercmp("5.2.15-2+b2", "5.2.15-2+b1") > 0 and vercmp("1.10", "1.9") > 0
    rng = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.2"}, {"fixed": "1.5"},
                                                       {"introduced": "2.0"}, {"last_affected": "2.1"}]}]}
    assert affected(rng, "1.1") == (False, None)
    assert affected(rng, "1.4") == (True, "1.5")
    assert affected(rng, "1.5") == (False, None)
    assert affected(rng, "2.1") == (True, None) and affected(rng, "2.2") == (False, None)


# ------------------------------------------------------------------ update-db
def test_update_db_writes_zips_the_check_can_read(tmp_path):
    from cloudtools import cve_cli
    from cloudtools.security.checks.vuln import load_osv

    def fake_fetch(url):
        assert url.startswith("https://osv-vulnerabilities.storage.googleapis.com/")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for f in (FIX / "osv" / "Debian").glob("*.json"):
                z.writestr(f.name, f.read_text(encoding="utf-8"))
        return buf.getvalue()

    out = io.StringIO()
    m = cve_cli.update_db(str(tmp_path), ["Debian", "Rocky Linux"], fetch=fake_fetch, out=out)
    assert m["failed"] == [] and m["ecosystems"]["Debian"]["records"] == 3
    assert m["ecosystems"]["Rocky Linux"]["url"].endswith("/Rocky%20Linux/all.zip")
    assert (tmp_path / "Debian" / "all.zip").exists()
    db = load_osv(str(tmp_path))
    assert db["records"] == 6 and ("Debian:12", "openssl") in db["index"]


def test_update_db_keeps_old_copy_when_a_download_fails(tmp_path):
    from cloudtools import cve_cli
    (tmp_path / "Debian").mkdir()
    (tmp_path / "Debian" / "all.zip").write_bytes(b"old")

    def broken(url):
        raise OSError("offline")
    m = cve_cli.update_db(str(tmp_path), ["Debian"], fetch=broken, out=io.StringIO())
    assert m["failed"] == ["Debian"] and (tmp_path / "Debian" / "all.zip").read_bytes() == b"old"
    assert cve_cli.main(["update-db", "--bogus"]) == 64


# ------------------------------------------------------------------ graph (R5.2)
def test_cve_on_reachable_lab_host_is_raised_and_unreachable_is_not():
    """Known answer: the same MEDIUM CVE on lab-bad (internet -> open SSH, public IP, IGW)
    and on lab-good (no route in). Only lab-bad's goes up a level."""
    from moto import mock_aws
    from test_security_scan import build_lab
    with mock_aws():
        ids = build_lab()
        env = AwsEnv(region=R, run_id="r-lab")
        snap = scan.collect_snapshot(env, [R], scan.select(max_tier=0, mvp_only=True))
        lab = json.loads((FIX / "aws_lab_graph.json").read_text(encoding="utf-8"))
        replay(env, lab, {"bad": ids["bad"], "good": ids["good"]})
        snap.data["inspector2.findings"] = collect(env, ["inspector2.findings"], [R], snap.account).data["inspector2.findings"]
    rep, _ = run(snap, {**scan.QUICK, "max_tier": 2})
    assert validate(rep) == []
    by = {f["resource"]["id"]: f for f in hits(rep, "cve.inspector")}
    assert by[ids["bad"]]["severity"] == {"base": "medium", "contextual": "high"}
    assert by[ids["bad"]]["on_paths"], "the path internet -> lab-bad -> its vulnerabilities"
    assert by[ids["good"]]["severity"] == {"base": "medium", "contextual": "medium"}
    assert by[ids["good"]]["on_paths"] == []
    p = next(p for p in rep["paths"] if p["id"] in by[ids["bad"]]["on_paths"])
    assert p["entry"] == "internet" and p["nodes"][-2] == ids["bad"]
    assert "runs vulnerable software" in p["steps"][-1]["text"]


# ------------------------------------------------------------------ contract
def test_every_report_validates_against_schema_v1(pos, neg):
    for snap in (pos, neg):
        rep, _ = run(snap)
        assert validate(rep) == []
        assert not [r for r in rep["checks"] if r["status"] == "error"], rep["checks"]
        from cloudtools.core import publish
        assert publish.to_html(rep) and publish.to_csv(rep)
        assert publish.to_sarif(rep, scan.check_catalogue())


def test_doctor_has_a_probe_for_every_new_collector_in_any_import_order():
    code = ("import {first}; from cloudtools.security import doctor, collectors_cve; "
            "[doctor.probe_for(k) for k in collectors_cve.PROBES]; "
            "from cloudtools.security.checks import select; "
            "[doctor.probe_for(k) for c in select(max_tier=2) for k in c.spec.collectors]")
    for first in ("cloudtools.security.scan", "cloudtools.security.capabilities",
                  "cloudtools.security.doctor"):
        r = subprocess.run([sys.executable, "-c", code.format(first=first)],
                           capture_output=True, text=True,
                           env={**__import__("os").environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")})
        assert r.returncode == 0, f"import {first} first: {r.stderr[-400:]}"


def test_tier2_profile_with_osv_setting_validates():
    from cloudtools.security import profiles
    p = profiles.validate({**profiles.BUILTIN["quick"], "max_tier": 2,
                           "settings": {"cve.osv-packages": {"db_path": OSV}}})
    assert p["max_tier"] == 2
    with pytest.raises(profiles.ProfileError):
        profiles.validate({**profiles.BUILTIN["quick"], "settings": {"cve.osv-packages": {"bogus": 1}}})


# ------------------------------------------------------------------ OSV memory (live lab)
def _osv_zip(tmp_path):
    (tmp_path / "Debian").mkdir()
    with zipfile.ZipFile(tmp_path / "Debian" / "all.zip", "w") as z:
        for f in sorted((FIX / "osv").rglob("*.json")):
            z.writestr(f.name, f.read_text(encoding="utf-8"))
    return tmp_path


def test_load_osv_keeps_only_wanted_packages(tmp_path):
    """The live lab's Ubuntu copy is 72,856 records (793 MB): loading all of it drove the
    scan into swap on an 8 GB machine (2026-10-29). Only installed packages are indexed."""
    from cloudtools.security.checks.vuln import load_osv
    db = load_osv(str(_osv_zip(tmp_path)), wanted={("Debian:12", "openssl"), ("PyPI", "nope")})
    assert set(db["index"]) == {("Debian:12", "openssl")}
    assert db["records"] == 5                           # still counts the whole copy


def test_load_osv_never_parses_an_unwanted_record(tmp_path, monkeypatch):
    from cloudtools.security.checks import vuln
    parsed = []
    real = vuln.json.loads
    monkeypatch.setattr(vuln.json, "loads", lambda s, *a, **k: parsed.append(1) or real(s, *a, **k))
    vuln._DB_CACHE.clear()
    vuln.load_osv(str(_osv_zip(tmp_path)), wanted={("Debian:12", "openssl")})
    assert len(parsed) == 1, "only the one record naming openssl should be parsed"


def test_load_osv_ecosystem_must_match_not_just_the_name(tmp_path):
    """'curl' is in both a PyPI and an Ubuntu 18.04 record; Ubuntu 20.04 wants neither."""
    from cloudtools.security.checks.vuln import load_osv
    db = load_osv(str(_osv_zip(tmp_path)), wanted={("Ubuntu:20.04:LTS", "curl")})
    assert db["index"] == {}


def test_load_osv_fingerprint_is_stable_and_tracks_content(tmp_path):
    from cloudtools.security.checks import vuln
    root = _osv_zip(tmp_path)
    a = vuln.load_osv(str(root), wanted={("Debian:12", "bash")})["fingerprint"]
    vuln._DB_CACHE.clear()
    b = vuln.load_osv(str(root), wanted={("Debian:12", "openssl")})["fingerprint"]
    assert a == b, "the fingerprint names the copy, not the subset a scan needed"
    with zipfile.ZipFile(root / "Debian" / "all.zip", "a") as z:
        z.writestr("NEW.json", json.dumps({"id": "NEW", "affected": []}))
    vuln._DB_CACHE.clear()
    assert vuln.load_osv(str(root), wanted=set())["fingerprint"] != a


def test_load_osv_keeps_only_installed_versions_and_matches_the_same(tmp_path):
    """A kernel record lists thousands of versions; 4,411 such records took 4 GB in the
    live lab. Given the installed versions, only those are kept, and the answer is unchanged."""
    from cloudtools.security.checks.vuln import affected, load_osv
    (tmp_path / "x.json").write_text(json.dumps({"id": "X-1", "aliases": ["CVE-2024-1"],
        "details": "long text " * 500,
        "affected": [{"package": {"ecosystem": "Ubuntu:20.04:LTS", "name": "linux"},
                      "versions": [f"5.4.0-{i}.{i}" for i in range(3000)],
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4.0-9999.1"}]}]}]}),
        encoding="utf-8")
    full = load_osv(str(tmp_path))
    slim = load_osv(str(tmp_path), wanted={("Ubuntu:20.04:LTS", "linux"): {"5.4.0-7.7", "6.0"}})
    (rec, aff), = slim["index"][("Ubuntu:20.04:LTS", "linux")]
    assert aff["versions"] == ["5.4.0-7.7"] and "details" not in rec and rec["aliases"] == ["CVE-2024-1"]
    (_, full_aff), = full["index"][("Ubuntu:20.04:LTS", "linux")]
    for v in ("5.4.0-7.7", "6.0"):
        assert affected(aff, v) == affected(full_aff, v)


# ------------------------------------------------------------------ kernels (live lab)
def test_osv_leaves_kernel_packages_to_inspector(pos, tmp_path):
    """Live lab, 2026-10-29: a 24.04 host on the 7.0 HWE kernel lists binary `linux-aws`;
    OSV's `linux-aws` is the 6.8 source package, whose unfixed CVEs then matched every
    version: 2,466 false hits, none shared with Inspector. Kernels go to Inspector."""
    import copy
    import shutil
    db = tmp_path / "osv"
    shutil.copytree(OSV, db)
    for eco, name in (("Ubuntu:18.04:LTS", "linux-aws"), ("Debian:12", "linux-image-6.1.0-18-cloud-amd64")):
        (db / f"K-{name}.json").write_text(json.dumps({"id": f"K-{name}", "aliases": [f"CVE-2026-{len(name)}"],
            "affected": [{"package": {"ecosystem": eco, "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}), encoding="utf-8")
    data = copy.deepcopy(pos.data)
    inv = data["ssm.inventory_applications"][R]
    inv["i-0ubuntu18"]["entries"].append({"name": "linux-aws", "version": "7.0.0-1014.14~18.04.1"})
    inv["i-0debian12"]["entries"].append({"name": "linux-image-6.1.0-18-cloud-amd64", "version": "6.1.76-1"})
    snap = Snapshot(pos.account, pos.regions, data, meta=pos.meta)
    rep, res = run(snap, {**TIER2, "settings": {"cve.osv-packages": {"db_path": str(db)}}})
    assert not [f for f in hits(rep, "cve.osv-packages") if f["cve"]["package"].startswith("linux")]
    assert res["cve.osv-packages"].stats["kernel_packages_skipped"] == 2
    kernel_gaps = [g["what"] for g in gaps(rep, "cve.osv-packages") if "kernel" in g["what"]]
    # i-0ubuntu18 has Inspector findings, so Inspector covers its kernel; i-0debian12 has none.
    assert len(kernel_gaps) == 1 and "i-0debian12" in kernel_gaps[0]
    # The other, real, match on i-0debian12 is unchanged.
    assert ("i-0debian12", "CVE-2024-0727") in {(f["resource"]["id"], f["cve"]["id"]) for f in hits(rep, "cve.osv-packages")}
