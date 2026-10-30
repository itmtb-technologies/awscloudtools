"""Internet reachability of an instance, traced through what AWS actually enforces in
order: a route to an internet gateway, the subnet's network ACL, then the security
groups, then a public IP (requirements `net.` row: "traced through routes and internet
gateways to what is actually reachable").

Deliberately conservative: anything it cannot see makes the answer `possible`, never
`confirmed` and never "not reachable" (R6.3, R8.1).
"""
from __future__ import annotations

from dataclasses import dataclass, field

WORLD4, WORLD6 = "0.0.0.0/0", "::/0"


def _port_in(port: int, lo, hi) -> bool:
    if lo is None and hi is None:
        return True                       # all ports
    lo = -1 if lo is None else lo
    hi = 65535 if hi is None else hi
    return lo == -1 or lo <= port <= hi


def sg_world_ports(sg: dict, ports: list[int]) -> dict[int, list[str]]:
    """{port: [source cidr]} for each port in `ports` open to the world in this SG."""
    out: dict[int, list[str]] = {}
    for r in sg.get("ingress", []):
        world = [c for c in r["cidrs"] if c == WORLD4] + [c for c in r["ipv6"] if c == WORLD6]
        if not world or r["proto"] not in ("-1", "tcp", "6"):
            continue
        for p in ports:
            if r["proto"] == "-1" or _port_in(p, r["from"], r["to"]):
                out.setdefault(p, []).extend(world)
    return {p: sorted(set(c)) for p, c in out.items()}


def nacl_allows_world(nacl: dict | None, port: int) -> bool | None:
    """Evaluate inbound NACL rules lowest-number-first, as AWS does. None = no NACL seen."""
    if nacl is None:
        return None
    for e in nacl["entries"]:
        if e["egress"] or e["cidr"] not in (WORLD4, WORLD6):
            continue
        if e["proto"] not in ("-1", "6") or not _port_in(port, e["from"], e["to"]):
            continue
        return e["action"] == "allow"
    return False


@dataclass
class Reach:
    status: str                            # confirmed | possible | none
    conditions: list = field(default_factory=list)
    evidence: list = field(default_factory=list)   # (source, resource, detail)


def instance_reach(inst: dict, port: int, sgs: dict, nacls_by_subnet: dict,
                   rt_by_subnet: dict, main_rt_by_vpc: dict) -> Reach:
    """Can the internet open `port` on this instance? sgs/nacls/route tables are the
    region's collected payloads keyed for lookup; None for a payload means unseen."""
    if inst.get("state") != "running" or not inst.get("public_ip"):
        return Reach("none")
    cond, ev = [], []
    open_sgs = [g for g in inst["sgs"] if sgs is not None and port in sg_world_ports(sgs.get(g, {}), [port])]
    if sgs is None:
        cond.append("security groups not readable")
    elif not open_sgs:
        return Reach("none")
    else:
        ev += [("ec2:DescribeSecurityGroups", g, f"world -> tcp/{port}") for g in open_sgs]
    rt = rt_by_subnet.get(inst["subnet"]) if rt_by_subnet is not None else None
    if rt is None and main_rt_by_vpc is not None:
        rt = main_rt_by_vpc.get(inst["vpc"])
    if rt_by_subnet is None or rt is None:
        cond.append("route table not readable")
    elif not rt["default_to_igw"]:
        return Reach("none")
    else:
        ev.append(("ec2:DescribeRouteTables", rt["id"], "0.0.0.0/0 -> igw"))
    nacl = nacls_by_subnet.get(inst["subnet"]) if nacls_by_subnet is not None else None
    allowed = nacl_allows_world(nacl, port)
    if allowed is None:
        cond.append("network ACL not readable")
    elif not allowed:
        return Reach("none")
    else:
        ev.append(("ec2:DescribeNetworkAcls", nacl["id"], f"allows world -> {port}"))
    ev.append(("ec2:DescribeInstances", inst["id"], f"public ip {inst['public_ip']}"))
    return Reach("possible" if cond else "confirmed", cond, ev)


def region_index(ctx, region: str):
    """Lookups for one region, or None where the collector missed (unseen, not empty)."""
    sg_list = ctx.per_region("ec2.security_groups").get(region)
    nacls = ctx.per_region("ec2.network_acls").get(region)
    rts = ctx.per_region("ec2.route_tables").get(region)
    sgs = None if sg_list is None else {g["id"]: g for g in sg_list}
    nacl_by_subnet = None if nacls is None else {s: a for a in nacls for s in a["subnets"]}
    rt_by_subnet = None if rts is None else {s: t for t in rts for s in t["subnets"]}
    main_rt = None if rts is None else {t["vpc"]: t for t in rts if t["main"]}
    return sgs, nacl_by_subnet, rt_by_subnet, main_rt
