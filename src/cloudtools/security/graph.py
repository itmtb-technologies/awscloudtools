"""Attack-path analysis over the facts (requirements §Attack path analysis).

Facts are directed edges. Paths run from entry points to crown jewels, bounded in depth
(R7.4). A path's confidence is the product of its edges' confidences, and it is
`possible` if any edge is (R7.3). Chokepoints rank the fixes by how many paths each one
breaks (R7.8). Findings on a path to a crown jewel are raised a level, and a
graph-participating finding on no path is lowered (R7.7).

Narration describes the exposure and the fix, never how to exploit it (R7.9).
"""
from __future__ import annotations

from collections import defaultdict
from itertools import islice

import networkx as nx

from ..core.model import ADMIN, INTERNET, SEVERITIES, stable_id

DEFAULT_DEPTH = 6
K_PER_PAIR = 5
MAX_PATHS = 500

NARRATE = {
    "reaches": "{src} can reach {dst}{ports}",
    "runs_as": "{src} runs with the permissions of {dst}",
    "exposes_credentials": "{src} can leak the credentials of {dst}{via}",
    "contains_credential": "{src} holds a credential",
    "authenticates_as": "a leaked credential signs in as {dst}",
    "can_assume": "{src} can assume {dst}",
    "can_read": "{src} can read {dst}", "can_write": "{src} can modify {dst}",
    "can_execute_on": "{src} can run code on {dst}",
    "can_escalate_to": "{src} can gain full control of the account{via}",
    "can_disable": "{src} can turn off {dst}",
    "is_public": "{dst} is readable by anyone",
    "has_vulnerability": "{src} runs vulnerable software",
}
VIA = {"imdsv1": "instance metadata v1", "public-code": "code anyone can invoke without signing in"}


def _label(node_id: str, nodes: dict) -> str:
    if node_id == INTERNET:
        return "the internet"
    if node_id == ADMIN:
        return "full account control"
    n = nodes.get(node_id) or {}
    name = n.get("name") or node_id.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    return f"{n.get('type', 'resource').replace('_', ' ')} {name}"


def _narrate(fact: dict, nodes: dict) -> str:
    q = fact.get("qualifiers") or {}
    ports = f" on port {', '.join(map(str, q['ports']))}" if q.get("ports") else ""
    via = q.get("via")
    via = [via] if isinstance(via, str) else via or []
    via = f" (via {', '.join(VIA.get(v, v) for v in via)})" if via else ""
    return NARRATE.get(fact["type"], "{src} -> {dst}").format(
        src=_label(fact["from"], nodes), dst=_label(fact["to"], nodes), ports=ports, via=via)


def crown_jewels(nodes: dict, facts: list[dict], profile: dict) -> set[str]:
    cj = profile.get("crown_jewels") or {}
    tags = cj.get("tags") or {}
    out = {ADMIN} if any(f["to"] == ADMIN for f in facts) else set()
    out |= {n for n in cj.get("resources", []) if n in nodes or any(f["to"] == n for f in facts)}
    for nid, n in nodes.items():
        if "crown_jewel" in n.get("labels", []):
            out.add(nid)
        for k, allowed in tags.items():
            v = (n.get("tags") or {}).get(k)
            if v is not None and (v in allowed if isinstance(allowed, list) else v == allowed):
                out.add(nid)
    for f in facts:
        if f["type"] == "can_disable":
            out.add(f["to"])
    return out


def entry_points(nodes: dict, facts: list[dict], profile: dict) -> set[str]:
    out = {INTERNET} if any(f["from"] == INTERNET for f in facts) else set()
    out |= {nid for nid, n in nodes.items() if "entry_point" in n.get("labels", [])
            and n.get("type") in ("external_principal", "leaked_credential")}
    out |= set(profile.get("assume_compromised", []))
    return out


def build(facts: list[dict]) -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    for f in facts:
        g.add_edge(f["from"], f["to"], key=f["id"], fact=f)
    return g


def _best_edge(g, u, v, removed: set) -> dict | None:
    """Between two nodes keep the most confident edge (confirmed beats possible)."""
    cands = [d["fact"] for k, d in g[u][v].items() if k not in removed]
    if not cands:
        return None
    return max(cands, key=lambda f: (f["status"] == "confirmed", f["confidence"], f["id"]))


def find_paths(facts: list[dict], nodes: dict, profile: dict, removed: set | None = None,
               max_depth: int | None = None, sources: set | None = None,
               targets: set | None = None) -> list[dict]:
    """Paths from entry points to crown jewels; or, with `sources` / `targets`, from and to
    any nodes asked for (find_paths, why_reachable). A chosen source is treated as
    compromised: asking "what can X reach" assumes X is already held."""
    removed = removed or set()
    depth = max_depth or (profile.get("graph") or {}).get("max_depth", DEFAULT_DEPTH)
    # Reaching a workload does not hand over its role: `runs_as` is traversable only
    # from workloads the user marks "assume compromised" (requirements: entry points).
    # Otherwise the route to a role must be a real exposure such as exposes_credentials.
    compromised = set(profile.get("assume_compromised", [])) | set(sources or ())
    live = [f for f in facts if f["id"] not in removed
            and (f["type"] != "runs_as" or f["from"] in compromised)]
    g = build(live)
    simple = nx.DiGraph()
    simple.add_edges_from((u, v) for u, v in g.edges())
    targets = set(targets) if targets else crown_jewels(nodes, live, profile)
    out: dict[str, dict] = {}
    for src in sorted(set(sources) if sources else entry_points(nodes, live, profile)):
        if src not in simple:
            continue
        for dst in sorted(targets):
            if dst == src or dst not in simple or not nx.has_path(simple, src, dst):
                continue
            for hops in islice(nx.shortest_simple_paths(simple, src, dst), K_PER_PAIR):
                if len(hops) - 1 > depth:
                    break
                edges = [_best_edge(g, a, b, removed) for a, b in zip(hops, hops[1:])]
                if any(e is None for e in edges):
                    continue
                pid = stable_id("p-", [e["id"] for e in edges])
                conf = 1.0
                for e in edges:
                    conf *= e["confidence"]
                out[pid] = {
                    "id": pid, "entry": src, "target": dst, "length": len(edges),
                    "nodes": list(hops),
                    "edges": [e["id"] for e in edges],
                    "status": "confirmed" if all(e["status"] == "confirmed" for e in edges) else "possible",
                    "confidence": round(conf, 4),
                    "steps": [{"fact": e["id"], "text": _narrate(e, nodes),
                               "evidence": e["evidence"], "conditions": e["conditions"]}
                              for e in edges],
                    "summary": f"{_label(src, nodes)} → {_label(dst, nodes)} in {len(edges)} steps",
                }
                if len(out) >= MAX_PATHS:
                    break
    return sorted(out.values(), key=lambda p: (-p["confidence"], p["length"], p["id"]))


def _finding_edges(findings: list[dict], facts_by_id: dict) -> dict[str, set[str]]:
    """finding id -> the fact ids its fix would remove: same check, and the finding's
    resource is the edge's source, target or cited evidence."""
    by_check = defaultdict(list)
    for f in facts_by_id.values():
        by_check[f["emitted_by"]].append(f)
    out = {}
    for fd in findings:
        rid = fd["resource"]["id"]
        hits = {f["id"] for f in by_check.get(fd["check_id"], [])
                if rid in (f["from"], f["to"]) or any(e.get("resource") == rid for e in f["evidence"])}
        if hits:
            out[fd["id"]] = hits
    return out


def chokepoints(paths: list[dict], findings: list[dict], facts_by_id: dict, top: int = 10) -> list[dict]:
    """Fixes (by check) ranked by the number of paths they break (R7.8)."""
    fe = _finding_edges(findings, facts_by_id)
    by_fix: dict[str, dict] = {}
    fd_by_id = {f["id"]: f for f in findings}
    for fid, edges in fe.items():
        fd = fd_by_id[fid]
        k = fd["check_id"]
        fix = by_fix.setdefault(k, {"check_id": k, "findings": set(), "edges": set(),
                                    "fix": fd["remediation"].get("summary", "")})
        fix["findings"].add(fid)
        fix["edges"] |= edges
    out = []
    for k, fix in by_fix.items():
        broken = [p for p in paths if set(p["edges"]) & fix["edges"]]
        if not broken:
            continue
        # Name only the findings whose own edges are on a broken path, not every finding
        # of the check: one on-path role out of 19 is "fix 1", not "fix 19".
        on = {e for p in broken for e in p["edges"]}
        fids = sorted(f for f in fix["findings"] if fe[f] & on)
        edges = sorted(fix["edges"] & on)
        broken = [p["id"] for p in broken]
        n = len(fids)
        out.append({"id": stable_id("c-", k, edges), "check_id": k,
                    "fix": fix["fix"], "findings": fids,
                    "edges": edges, "paths_broken": len(broken),
                    "paths": sorted(broken),
                    "headline": f"Fixing {n} {k} finding{'s' if n > 1 else ''} breaks "
                                f"{len(broken)} of {len(paths)} path{'s' if len(paths) != 1 else ''}"})
    out.sort(key=lambda c: (-c["paths_broken"], c["check_id"]))
    return out[:top]


def _shift(sev: str, d: int) -> str:
    i = max(0, min(len(SEVERITIES) - 1, SEVERITIES.index(sev) + d))
    return SEVERITIES[i]


def contextualise(findings: list[dict], paths: list[dict], facts_by_id: dict) -> None:
    """R7.7, in place: on a path -> one level up; emits facts but on no path -> one down."""
    fe = _finding_edges(findings, facts_by_id)
    emitting = {f["emitted_by"] for f in facts_by_id.values()}
    edge_paths = defaultdict(list)
    for p in paths:
        for e in p["edges"]:
            edge_paths[e].append(p["id"])
    for fd in findings:
        on = sorted({pid for e in fe.get(fd["id"], ()) for pid in edge_paths.get(e, ())})
        fd["on_paths"] = on
        base = fd["severity"]["base"]
        if on:
            fd["severity"]["contextual"] = _shift(base, +1)
        elif fd["check_id"] in emitting and fd["id"] in fe and base in ("high", "critical"):
            fd["severity"]["contextual"] = _shift(base, -1)
        else:
            fd["severity"]["contextual"] = base


def analyse(report: dict, profile: dict) -> dict:
    """Paths, chokepoints and contextual severity for a report, in place. Returns stats."""
    if not (profile.get("graph") or {}).get("enabled", True):
        return {"paths": 0, "chokepoints": 0}
    nodes = {n["id"]: n for n in report["nodes"]}
    facts_by_id = {f["id"]: f for f in report["facts"]}
    paths = find_paths(report["facts"], nodes, profile)
    report["paths"] = paths
    report["chokepoints"] = chokepoints(paths, report["findings"], facts_by_id)
    contextualise(report["findings"], paths, facts_by_id)
    return {"nodes": len(nodes), "edges": len(facts_by_id), "paths": len(paths),
            "chokepoints": len(report["chokepoints"])}


def what_if(report: dict, profile: dict, remove_edges: list[str] | None = None,
            fix_findings: list[str] | None = None) -> dict:
    """R7.10: remove edges (directly or by fixing findings) and list the paths that vanish."""
    nodes = {n["id"]: n for n in report["nodes"]}
    facts_by_id = {f["id"]: f for f in report["facts"]}
    removed = set(remove_edges or [])
    fe = _finding_edges(report["findings"], facts_by_id)
    for fid in fix_findings or []:
        removed |= fe.get(fid, set())
    # Compare by node sequence: removing one of two parallel edges keeps the path alive.
    before = find_paths(report["facts"], nodes, profile)
    after = {tuple(p["nodes"]) for p in find_paths(report["facts"], nodes, profile, removed)}
    gone = [p for p in before if tuple(p["nodes"]) not in after]
    return {"removed_edges": sorted(removed), "paths_before": len(before),
            "paths_after": len(after), "paths_removed": [p["id"] for p in gone],
            "summaries": [p["summary"] for p in gone]}
