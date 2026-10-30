"""Attack graph known answers (requirements §Attack path analysis, worked example)."""
from cloudtools.core.model import ADMIN, INTERNET, Evidence, Fact
from cloudtools.security import graph

EV = [Evidence("test", "r", "d")]


def fact(src, t, dst, check, status="confirmed", conf=0.9, **q):
    f = Fact(src, t, dst, check, EV, q, status, conf, ["c"] if status == "possible" else [])
    return f.to_dict()


def finding(fid, check, rid, sev="medium", fix="fix it"):
    return {"id": fid, "check_id": check, "resource": {"id": rid}, "title": fid,
            "severity": {"base": sev, "contextual": sev}, "remediation": {"summary": fix},
            "evidence": [], "on_paths": []}


def five_step_chain():
    """internet -> public LB -> instance:8080 -> IMDSv1 exposes role -> role passes roles
    -> admin. Five individually medium facts, one critical path."""
    facts = [fact(INTERNET, "reaches", "lb", "net.public-lb-listeners", ports=[443]),
             fact("lb", "reaches", "i-1", "net.public-lb-listeners", ports=[8080]),
             fact("i-1", "exposes_credentials", "role", "srv.imdsv1-enabled", "possible", 0.6),
             fact("role", "can_escalate_to", ADMIN, "iam.privilege-escalation", "possible", 0.7)]
    nodes = {"lb": {"id": "lb", "type": "load_balancer", "name": "web-lb"},
             "i-1": {"id": "i-1", "type": "ec2_instance", "name": "web-1"},
             "role": {"id": "role", "type": "iam_role", "name": "web-role"},
             ADMIN: {"id": ADMIN, "type": "admin_equivalent", "labels": ["crown_jewel"]}}
    findings = [finding("fd-imds", "srv.imdsv1-enabled", "i-1", fix="Require IMDSv2"),
                finding("fd-pe", "iam.privilege-escalation", "role", "high", "Scope PassRole"),
                finding("fd-mfa", "iam.user-no-mfa", "u", "high"),          # not on the graph
                finding("fd-lonely", "srv.imdsv1-enabled", "i-9", "high")]  # emits, no path
    return facts, nodes, findings


def test_worked_example_gives_one_possible_path_with_product_confidence():
    facts, nodes, _ = five_step_chain()
    paths = graph.find_paths(facts, nodes, {})
    assert len(paths) == 1
    p = paths[0]
    assert p["entry"] == INTERNET and p["target"] == ADMIN and p["length"] == 4
    assert p["status"] == "possible"
    assert p["confidence"] == round(0.9 * 0.9 * 0.6 * 0.7, 4)
    assert "full control of the account" in p["steps"][-1]["text"]
    assert all("exploit" not in s["text"].lower() for s in p["steps"])


def test_path_ids_are_deterministic():
    facts, nodes, _ = five_step_chain()
    assert graph.find_paths(facts, nodes, {})[0]["id"] == graph.find_paths(list(reversed(facts)), nodes, {})[0]["id"]


def test_depth_bound():
    facts, nodes, _ = five_step_chain()
    assert graph.find_paths(facts, nodes, {}, max_depth=3) == []


def test_chokepoints_and_contextual_severity():
    facts, nodes, findings = five_step_chain()
    rep = {"facts": facts, "nodes": list(nodes.values()), "findings": findings}
    graph.analyse(rep, {})
    by = {f["id"]: f for f in rep["findings"]}
    assert by["fd-imds"]["severity"]["contextual"] == "high"       # raised: on the path
    assert by["fd-pe"]["severity"]["contextual"] == "critical"
    assert by["fd-mfa"]["severity"]["contextual"] == "high"         # untouched: no facts
    assert by["fd-lonely"]["severity"]["contextual"] == "high"      # no fact matched -> base
    top = {c["check_id"]: c for c in rep["chokepoints"]}
    assert top["srv.imdsv1-enabled"]["paths_broken"] == 1 and "IMDSv2" in top["srv.imdsv1-enabled"]["fix"]


def test_high_finding_with_a_fact_but_no_path_is_lowered():
    facts, nodes, findings = five_step_chain()
    facts.append(fact(INTERNET, "reaches", "i-9", "net.open-admin-ports", ports=[22]))
    findings.append(finding("fd-dead-end", "net.open-admin-ports", "i-9", "high"))
    rep = {"facts": facts, "nodes": list(nodes.values()), "findings": findings}
    graph.analyse(rep, {})
    f = next(x for x in rep["findings"] if x["id"] == "fd-dead-end")
    assert f["severity"] == {"base": "high", "contextual": "medium"} and f["on_paths"] == []


def test_what_if_fixing_imds_removes_the_path():
    facts, nodes, findings = five_step_chain()
    rep = {"facts": facts, "nodes": list(nodes.values()), "findings": findings}
    graph.analyse(rep, {})
    w = graph.what_if(rep, {}, fix_findings=["fd-imds"])
    assert w["paths_before"] == 1 and w["paths_after"] == 0 and len(w["paths_removed"]) == 1
    keep = graph.what_if(rep, {}, fix_findings=["fd-mfa"])
    assert keep["paths_after"] == 1


def test_parallel_edge_keeps_path_alive_in_what_if():
    facts, nodes, findings = five_step_chain()
    facts.append(fact("lb", "reaches", "i-1", "net.other-check", ports=[8443]))
    rep = {"facts": facts, "nodes": list(nodes.values()), "findings": findings}
    used = graph.find_paths(facts, nodes, {})[0]["edges"][1]       # the lb -> i-1 edge in use
    w = graph.what_if(rep, {}, remove_edges=[used])
    assert w["paths_after"] == 1, "a second edge between the same nodes keeps the path"
    assert w["paths_removed"] == [], "and the path must not be reported as removed"


def test_tagged_data_store_is_a_crown_jewel():
    facts = [fact(INTERNET, "is_public", "arn:aws:s3:::payroll", "data.s3-public-bucket")]
    nodes = {"arn:aws:s3:::payroll": {"id": "arn:aws:s3:::payroll", "type": "s3_bucket",
                                      "tags": {"data-class": "restricted"}}}
    assert graph.find_paths(facts, nodes, {}) == []
    prof = {"crown_jewels": {"tags": {"data-class": ["confidential", "restricted"]}}}
    assert len(graph.find_paths(facts, nodes, prof)) == 1


def test_runs_as_is_only_followed_from_assumed_compromised_workloads():
    facts, nodes, _ = five_step_chain()
    facts = [f for f in facts if f["type"] != "exposes_credentials"]
    facts.append(fact("i-1", "runs_as", "role", "srv.workload-identities", conf=1.0))
    assert graph.find_paths(facts, nodes, {}) == [], "reaching a host is not owning its role"
    paths = graph.find_paths(facts, nodes, {"assume_compromised": ["i-1"]})
    assert {p["entry"] for p in paths} == {"i-1", "internet"}   # i-1 itself is now an entry


def test_chokepoint_counts_only_the_findings_on_the_paths_it_breaks():
    facts, nodes, findings = five_step_chain()
    facts.append(fact("role-2", "can_escalate_to", ADMIN, "iam.privilege-escalation", "possible", 0.7))
    findings.append(finding("fd-pe2", "iam.privilege-escalation", "role-2", "high"))  # off-path
    rep = {"facts": facts, "nodes": list(nodes.values()), "findings": findings}
    graph.analyse(rep, {})
    pe = next(c for c in rep["chokepoints"] if c["check_id"] == "iam.privilege-escalation")
    assert pe["findings"] == ["fd-pe"] and pe["headline"].startswith("Fixing 1 ")


def test_paths_to_any_resource_and_from_a_chosen_entry():
    """find_paths(entry, target) and why_reachable(resource): the target need not be a crown
    jewel, and an entry filter keeps only paths that start there."""
    facts, nodes, _ = five_step_chain()
    to_host = graph.find_paths(facts, nodes, {}, targets={"i-1"})
    assert [p["nodes"] for p in to_host] == [[INTERNET, "lb", "i-1"]]
    assert graph.find_paths(facts, nodes, {}, targets={"i-1"}, sources={"lb"})[0]["nodes"] == ["lb", "i-1"]
    assert graph.find_paths(facts, nodes, {}, targets={"i-1"}, sources={"role"}) == []
