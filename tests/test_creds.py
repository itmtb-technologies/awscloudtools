"""Credential inventory, ported from credscan: a key id leaked into a repo and live in IAM
becomes an attack-graph entry point; no secret value survives anywhere."""
import json
import shutil
import subprocess

import boto3
import pytest
from moto import mock_aws

from cloudtools.core.model import ADMIN, Evidence, Fact
from cloudtools.core.platform.base import Refused
from cloudtools.creds.repo_secrets import key_id_fp, scan_repo
from cloudtools.security import graph, runner
from test_checks_table import CASES, KEY_FP, akey, repo_hits, run, snap

needs_gitleaks = pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
GH_TOKEN = "ghp_" + "Zq8vT3kLm9Xw2Rb7Np4Hc6Jd1Fs5Gy0Ua8Ke"      # canary: must never be persisted


def git_repo(tmp_path, files: dict):
    repo = tmp_path / "leaky"
    repo.mkdir()
    for name, body in files.items():
        (repo / name).write_text(body)
    run_ = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
    run_("init", "-q")
    run_("add", "-A")
    run_("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "x")
    return repo


@needs_gitleaks
def test_repo_scan_keeps_fingerprints_never_values(tmp_path):
    kid = "AKIAQ3EGRV7XJ4TL6PNM"
    repo = git_repo(tmp_path, {"config.py": f'AWS_ACCESS_KEY_ID = "{kid}"\nGH = "{GH_TOKEN}"\n'})
    out = scan_repo(str(repo), salt="s1")
    text = json.dumps(out)
    assert GH_TOKEN not in text and kid not in text
    kinds = {s["kind"]: s for s in out["secrets"]}
    assert kinds["aws_access_key_id"]["fingerprint"] == key_id_fp(kid)
    assert kinds["aws_access_key_id"]["hint"] == kid[-4:]
    assert len(out["secrets"]) >= 2 and all(s["locations"] for s in out["secrets"])
    assert scan_repo(str(repo), salt="s2")["secrets"] != out["secrets"], "the salt is applied"


def test_active_leaked_key_is_an_entry_point_with_a_possible_edge():
    r = run("cred.inventory", CASES["cred.inventory"][0])
    assert [f.severity for f in r.findings] == ["high"]
    [fa] = r.facts
    assert (fa.src, fa.type, fa.dst, fa.status) == (f"leak:{KEY_FP}", "authenticates_as",
                                                    "arn:aws:iam::1:user/dev", "possible")
    assert [n.labels for n in r.nodes] == [["entry_point"]] and r.nodes[0].type == "leaked_credential"
    esc = Fact("arn:aws:iam::1:user/dev", "can_escalate_to", ADMIN, "iam.admin-principals",
               [Evidence("t", "r", "d")], {}, "possible", 0.7, ["c"]).to_dict()
    nodes = {n.id: {"id": n.id, "type": n.type, "labels": n.labels} for n in r.nodes}
    paths = graph.find_paths([fa.to_dict(), esc], nodes, {})
    assert len(paths) == 1 and paths[0]["entry"] == f"leak:{KEY_FP}" and paths[0]["target"] == ADMIN


def test_inactive_leaked_key_is_low_and_opens_no_path():
    r = run("cred.inventory", snap(iam__access_keys=[akey("Inactive")], repo__secrets=repo_hits(KEY_FP)))
    assert [f.severity for f in r.findings] == ["low"] and not r.facts and not r.nodes


def test_no_repos_given_reports_nothing_and_no_gap():
    for cid in ("cred.inventory", "cred.repo-secrets"):
        r = run(cid, snap(iam__access_keys=[akey("Active")]))
        assert not r.findings and not r.gaps


def test_repo_scan_is_refused_outside_standalone():
    class Hosted:
        name = "hosted"
    with pytest.raises(Refused):
        runner._scan_repos(Hosted(), ["/tmp"], None)


@needs_gitleaks
def test_end_to_end_leak_to_admin_through_the_cli(tmp_path, monkeypatch):
    from cloudtools.cli import main
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("CLOUDTOOLS_SALT", "test-salt")
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="ci-bot")
        iam.put_user_policy(UserName="ci-bot", PolicyName="admin", PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
        kid = iam.create_access_key(UserName="ci-bot")["AccessKey"]["AccessKeyId"]
        repo = git_repo(tmp_path, {"deploy.sh": f"export AWS_ACCESS_KEY_ID={kid}\nexport GH={GH_TOKEN}\n"})
        out = tmp_path / "out"
        main(["security", "scan", "--region", "eu-west-1", "--regions", "eu-west-1", "--out", str(out),
              "--repo", str(repo), "-q"])
    rid = json.loads((out / "runs/latest-security.json").read_text())["run_id"]
    rep = json.loads((out / f"runs/{rid}/report.json").read_text())
    leak = [f for f in rep["findings"] if f["check_id"] == "cred.inventory"]
    assert leak and leak[0]["severity"]["contextual"] == "critical"     # high, raised: on a path
    assert any(p["entry"].startswith("leak:") and p["target"] == ADMIN for p in rep["paths"])
    assert any(f["check_id"] == "cred.repo-secrets" for f in rep["findings"])
    for f in (out / "runs" / rid).iterdir():
        assert GH_TOKEN not in f.read_text(), f"secret value persisted in {f.name}"


@needs_gitleaks
def test_inventory_view_lists_keys_and_marks_the_leak(tmp_path, monkeypatch, capsys):
    from cloudtools.cli import main
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("CLOUDTOOLS_SALT", "test-salt")
    with mock_aws():
        iam = boto3.client("iam")
        for u in ("leaky", "clean"):
            iam.create_user(UserName=u)
        kid = iam.create_access_key(UserName="leaky")["AccessKey"]["AccessKeyId"]
        iam.create_access_key(UserName="clean")
        repo = git_repo(tmp_path, {"a.env": f"AWS_ACCESS_KEY_ID={kid}\n"})
        out = tmp_path / "out"
        main(["security", "scan", "--region", "eu-west-1", "--regions", "eu-west-1",
              "--out", str(out), "--repo", str(repo), "-q"])
    capsys.readouterr()
    main(["call", "cred.inventory", "--out", str(out)])
    inv = json.loads(capsys.readouterr().out)
    assert inv["repos_scanned"] == 1 and inv["total"] == 2
    by = {r["user"]: r for r in inv["keys"]}
    assert by["leaky"]["leak"] and by["clean"]["leak"] is None
    assert kid not in json.dumps(inv) and by["leaky"]["key"] == "…" + kid[-4:]


def test_iam_tag_named_after_a_key_id_is_not_stored(monkeypatch):
    """The IAM console keeps a key's description as a user tag keyed by the key id. Stored
    verbatim it put key ids in every report, which the repo scan then found as 'leaks'."""
    from cloudtools.core.aws import AwsEnv
    from cloudtools.security.collectors import authorization_details
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    with mock_aws():
        iam = boto3.client("iam")
        iam.create_user(UserName="u")
        kid = iam.create_access_key(UserName="u")["AccessKey"]["AccessKeyId"]
        iam.tag_user(UserName="u", Tags=[{"Key": kid, "Value": "laptop key"}, {"Key": "team", "Value": "x"}])
        out = authorization_details(AwsEnv(region="eu-west-1"), "global")
    tags = {t["Key"]: t["Value"] for t in out["UserDetailList"][0]["Tags"]}
    assert kid not in json.dumps(out)
    assert tags["team"] == "x" and tags[f"access-key-description:…{kid[-4:]}"] == "laptop key"


@needs_gitleaks
def test_repo_scan_skips_the_scanners_own_output(tmp_path):
    from cloudtools.creds.repo_secrets import scan_repos
    repo = git_repo(tmp_path, {"app.py": f'GH = "{GH_TOKEN}"\n'})
    (repo / "reports").mkdir()
    (repo / "reports" / "report.json").write_text('{"k": "AKIAQ3EGRV7XJ4TL6PNM"}')
    out = scan_repos([str(repo)], "s", exclude=[str(repo / "reports")])
    locs = [loc for s in out["repos"][0]["secrets"] for loc in s["locations"]]
    assert locs and not any("reports/" in loc for loc in locs)
