"""The HTTP front door (standalone): routes generated from the manifests, jobs answer 202
and run through the submit port, views answer 200, and the same snapshot gives the same
finding ids through the CLI and through HTTP (parity)."""
import json
import time

import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

from cloudtools import http_app, serve_cli
from cloudtools.cli import main
from cloudtools.core.capability import all_capabilities, load_builtin
from cloudtools.core.platform.standalone import StandalonePlatform
from test_security_scan import R, build_lab

load_builtin()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", R)
    with mock_aws():
        ids = build_lab()
        yield tmp_path, ids


def _client(out):
    plat = StandalonePlatform(region=R, output=str(out), initiator="http")
    return TestClient(http_app.create_app(lambda _r: plat)), plat


def _wait(client, run_id, timeout=60.0):
    deadline = time.monotonic() + timeout
    while True:
        st = client.get("/v1/security/get_run_status", params={"run_id": run_id})
        assert st.status_code == 200, st.text
        body = st.json()
        if body["state"] in ("succeeded", "failed") or time.monotonic() > deadline:
            return body
        time.sleep(0.05)


def test_every_capability_has_exactly_one_route():
    app = http_app.create_app(lambda _r: None)
    served = http_app.routes(app)
    for cap in all_capabilities():
        assert http_app.route_for(cap.manifest) in served, cap.manifest.id
    assert ("GET", "/health") in served
    assert len(served) == len(all_capabilities()) + 1


def test_jobs_are_post_and_views_are_get():
    for cap in all_capabilities():
        method, path = http_app.route_for(cap.manifest)
        assert method == ("POST" if cap.manifest.kind == "job" else "GET")
        assert path.startswith("/v1/") and " " not in path


def test_hosted_only_leaves_out_unhosted_capabilities():
    served = http_app.routes(http_app.create_app(lambda _r: None, hosted_only=True))
    for cap in all_capabilities():
        assert (http_app.route_for(cap.manifest) in served) == cap.manifest.hosted, cap.manifest.id


def test_same_snapshot_same_finding_ids_through_cli_and_http(lab):
    """Parity: the CLI's `evaluate --snapshot` and HTTP's POST /v1/security/evaluate over
    the same snapshot give identical finding ids (and the HTTP report validates)."""
    from cloudtools.core.report import validate
    out, _ = lab
    main(["security", "scan", "--region", R, "--regions", R, "--out", str(out / "scan"), "-q"])
    rid = json.loads((out / "scan/runs/latest-security.json").read_text())["run_id"]
    snap = out / "scan" / "runs" / rid / "snapshot.json"
    main(["security", "evaluate", "--snapshot", str(snap), "--out", str(out / "cli"), "-q"])
    cli_rid = json.loads((out / "cli/runs/latest-security.json").read_text())["run_id"]
    cli_rep = json.loads((out / f"cli/runs/{cli_rid}/report.json").read_text())

    client, plat = _client(out / "http")
    r = client.post("/v1/security/evaluate", json={"snapshot": str(snap)})
    assert r.status_code == 202, r.text
    started = r.json()
    assert started["state"] == "queued" and started["poll"] == "security.get_run_status"
    st = _wait(client, started["run_id"])
    assert st["state"] == "succeeded", st
    report_rid = st["result"]["run_id"]
    http_rep = json.loads((out / f"http/runs/{report_rid}/report.json").read_text())
    assert validate(http_rep) == []
    assert cli_rep["findings"], "the lab must produce findings for parity to mean anything"
    assert sorted(f["id"] for f in http_rep["findings"]) == sorted(f["id"] for f in cli_rep["findings"])
    # ...and the view over HTTP lists the same ids
    ids, n = [], 1
    while True:
        page = client.get("/v1/security/list_findings",
                          params={"run_id": report_rid, "page_size": 100, "page": n})
        assert page.status_code == 200
        ids += [f["id"] for f in page.json()["findings"]]
        if len(ids) >= page.json()["total"]:
            break
        n += 1
    assert sorted(ids) == sorted(f["id"] for f in cli_rep["findings"])
    plat.join()


def test_scan_job_returns_202_at_once_and_status_reaches_succeeded(lab):
    out, _ = lab
    client, plat = _client(out)
    r = client.post("/v1/security/scan", json={"profile": "quick", "regions": R})
    assert r.status_code == 202 and r.json()["run_id"].startswith("r-")
    assert r.json()["status_url"] == f"/v1/security/get_run_status?run_id={r.json()['run_id']}"
    st = _wait(client, r.json()["run_id"])
    assert st["state"] == "succeeded", st
    assert st["result"]["summary"]["open"] >= 1
    plat.join()


def test_wait_is_not_an_http_input(lab):
    """Over HTTP a job is always async: `wait` is not accepted, so a caller can't hold a
    request (or a Lambda) open for a whole scan."""
    out, _ = lab
    client, _ = _client(out)
    r = client.post("/v1/security/scan", json={"wait": True})
    assert r.status_code == 400 and r.json()["error_code"] == "VALIDATION"


def test_unknown_inputs_and_bad_types_are_400_with_the_tc_error_shape(tmp_path):
    client, _ = _client(tmp_path)
    r = client.get("/v1/security/list_findings", params={"nope": "1"})
    assert r.status_code == 400 and set(r.json()) == {"detail", "error_code"}
    r = client.get("/v1/security/list_findings", params={"page": "x"})
    assert r.status_code == 400
    r = client.post("/v1/security/scan", content=b"[1]")
    assert r.status_code == 400
    r = client.post("/v1/security/scan", json={"repos": ["/etc"]})   # CLI-only, never HTTP
    assert r.status_code == 400


def test_missing_run_is_404_not_500(tmp_path):
    client, _ = _client(tmp_path)
    r = client.get("/v1/security/list_findings")
    assert r.status_code == 404 and r.json()["error_code"] == "NOT_FOUND"
    r = client.get("/v1/security/get_run_status", params={"run_id": "r-nope"})
    assert r.status_code == 404


def test_internal_errors_never_leak_their_text(tmp_path, monkeypatch):
    from cloudtools.core.capability import get
    cap = get("security.list_checks")
    monkeypatch.setattr(cap, "fn", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("secret-ish detail")))
    client, _ = _client(tmp_path)
    r = client.get("/v1/security/list_checks")
    assert r.status_code == 500 and "secret-ish" not in r.text


def test_a_refused_authorize_is_403(tmp_path):
    from cloudtools.core.platform.base import Refused

    class No(StandalonePlatform):
        def authorize(self, manifest, confirm=False):
            raise Refused("no", "FORBIDDEN")
    plat = No(region=R, output=str(tmp_path))
    client = TestClient(http_app.create_app(lambda _r: plat))
    assert client.get("/v1/security/list_checks").status_code == 403
    r = client.post("/v1/security/scan", json={})
    assert r.status_code == 403
    assert not (tmp_path / "runs").exists(), "a refused job must not even be queued"


def test_requested_tier_counts_profile_and_tier_input():
    from cloudtools.core.capability import get
    m = get("security.scan").manifest
    assert http_app.requested_tier(m, {"profile": "quick"}) == 0
    assert http_app.requested_tier(m, {"tier": 2}) == 2


def test_serve_binds_loopback_only(monkeypatch):
    seen = {}
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    assert serve_cli.main(["--port", "9999", "--out", "/tmp/x"]) == 0
    assert seen["host"] == "127.0.0.1" and seen["port"] == 9999
    with pytest.raises(SystemExit):                 # there is no way to ask for another host
        serve_cli.main(["--host", "0.0.0.0"])


# -- the local server against a web page (security review 2026-10-30) ---------------------
# A page the user visits can send requests to 127.0.0.1 (cross-site POST, no preflight for
# text/plain) and, after DNS rebinding, read the answers. Shown live on 0.1.3: a foreign
# Host read the findings (200) and a text/plain POST started a scan (202).

def _served(tmp_path, token="t0ken-for-tests"):
    import argparse
    a = argparse.Namespace(aws_profile=None, region=R, out=str(tmp_path), verbose=False, port=8765)
    return TestClient(serve_cli.build_app(a, token)), token


@pytest.mark.parametrize("host", ["attacker.example:8765", "attacker.example", "127.0.0.1:9999"])
def test_serve_refuses_a_host_that_is_not_this_server(tmp_path, host):
    client, token = _served(tmp_path)
    r = client.get("/v1/security/list_checks", headers={"Host": host, "Authorization": f"Bearer {token}"})
    assert r.status_code == 403 and r.json()["error_code"] == "FORBIDDEN"


@pytest.mark.parametrize("auth", [None, "Bearer wrong", "t0ken-for-tests", "Bearer t0ken-for-testsX"])
def test_serve_needs_this_launchs_token(tmp_path, auth):
    client, _ = _served(tmp_path)
    headers = {"Host": "127.0.0.1:8765", **({"Authorization": auth} if auth else {})}
    r = client.post("/v1/security/scan", content='{"profile": "quick"}',
                    headers={**headers, "Content-Type": "text/plain"})
    assert r.status_code == 401 and r.json()["error_code"] == "UNAUTHENTICATED"
    assert not (tmp_path / "runs").exists(), "nothing may start without the token"


@pytest.mark.parametrize("host", ["127.0.0.1:8765", "localhost:8765"])
def test_serve_answers_its_own_host_with_the_token(tmp_path, host):
    client, token = _served(tmp_path)
    assert client.get("/health", headers={"Host": host}).status_code == 200
    r = client.get("/v1/security/list_checks", headers={"Host": host, "Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_hosted_scan_takes_only_a_built_in_profile(tmp_path):
    """`profile` is a name or a file path to the loader; hosted, a path would read the
    worker's disk. Only the built-in names are accepted there."""
    plat = StandalonePlatform(region=R, output=str(tmp_path), initiator="http")
    client = TestClient(http_app.create_app(lambda _r: plat, hosted_only=True))
    r = client.post("/v1/security/scan", json={"profile": "/etc/hosts"})
    assert r.status_code == 400 and r.json()["error_code"] == "VALIDATION"
    assert not (tmp_path / "runs").exists()
