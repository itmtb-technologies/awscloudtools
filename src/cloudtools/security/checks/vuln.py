"""Vulnerabilities: OS end of life, software visibility (tier 0) and CVEs (tier 2, `cve.`).

Sources, in order of trust: Inspector v2 (AWS's own scanner), SSM Patch Manager's
compliance counts, and SSM Inventory matched against an OFFLINE copy of OSV. Package
lists never leave the machine: OSV matching reads `cloudtools cve update-db`'s download,
and with no download the check is a gap, never a clean result (R8.1).

Graph (R5.2): each host or image with a CVE gets a `has_vulnerability` edge to one
vulnerability node per (check, resource), labelled `crown_jewel`. A path that reaches
the host then runs on to that node, so `graph.contextualise` raises the CVE findings on
it; a host no path reaches keeps (or, high/critical, loses one level of) its severity.
De-duplication (R5.3): an OSV match Inspector already reports on the same resource is
dropped, and counted in stats.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import date
from importlib import resources
from pathlib import Path

from ...core.model import CheckResult, Node
from . import CheckSpec, check

OSV_DEFAULT_DIR = "~/.cache/cloudtools/osv"


def data_file(name: str) -> dict:
    return json.loads((resources.files("cloudtools.security") / "data" / name)
                      .read_text(encoding="utf-8"))


def _names(ctx, region: str) -> dict:
    """instance id -> Name tag, where ec2.instances was collected (optional input)."""
    return {i["id"]: i["name"] for i in ctx.per_region("ec2.instances").get(region) or []}


def _vuln_node(ctx, rid: str, rtype: str, region: str, name: str, count: int, worst: str,
               evidence: list, conditions=(), confidence=1.0):
    """The has_vulnerability edge and its two nodes for one resource."""
    target = f"vuln:{ctx.spec.id}:{rid}"
    fact = ctx.fact(rid, "has_vulnerability", target, evidence, {"source": ctx.spec.id},
                    conditions, confidence)
    nodes = [Node(rid, rtype, ctx.account, region, name),
             Node(target, "vulnerability", ctx.account, region,
                  f"{count} known vulnerabilit{'y' if count == 1 else 'ies'} on {name}",
                  labels=["crown_jewel"], attrs={"count": count, "worst": worst})]
    return fact, nodes


# ---------------------------------------------------------------- tier 0: the OS itself
def _eol_entry(entries: list, name: str, version: str) -> dict | None:
    for e in entries:
        v = e["version"]
        if re.search(e["platform"], name or "") and (
                not v or version == v or version.startswith(v + ".")):
            return e
    return None


@check(CheckSpec(
    "srv.os-end-of-life", "Instance OS past (or near) end of support", "server", "high",
    ("ssm.instance_information", "ec2.instances"), config={"warn_days": 180},
    covers="SSM-managed instances whose OS release (PlatformName/PlatformVersion) is past "
           "the vendor's end of security support, per data/os_eol.json (dated, with a "
           "source URL per release); low when within `warn_days` of it.",
    does_not_cover="Instances without an SSM agent (srv.software-not-visible); paid "
                   "extended support (ESM, ELS) the account may have bought.",
    false_positives="Releases covered by a paid extended-support contract."))
def os_end_of_life(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    entries = data_file("os_eol.json")["entries"]
    today = ctx.now.date()
    warn = int(ctx.config.get("warn_days", 180))
    unknown, hidden, seen = {}, {}, 0
    for region, info in ctx.per_region("ssm.instance_information").items():
        names = _names(ctx, region)
        for i in info:
            seen += 1
            e = _eol_entry(entries, i["platform_name"], i["platform_version"])
            label = f"{i['platform_name']} {i['platform_version']}".strip() or "unknown OS"
            if not e:
                unknown.setdefault((region, label), []).append(i["id"])
                continue
            days = (date.fromisoformat(e["eol"]) - today).days
            if days > warn:
                continue
            name = names.get(i["id"], i["id"])
            past = days < 0
            res.findings.append(ctx.finding(
                {"id": i["id"], "name": name, "region": region, "type": "ec2_instance"},
                f"{name} runs {e['release']}, "
                + (f"out of support since {e['eol']}" if past else f"out of support on {e['eol']}"),
                [("ssm:DescribeInstanceInformation", i["id"], f"PlatformName/Version {label}"),
                 ("data/os_eol.json", e["source"], f"end of support {e['eol']}")],
                {"summary": "Upgrade to a supported OS release (or buy extended support "
                            "and accept the risk with the scanner:accepted-risk tag)."},
                severity="high" if past else "low", qualifiers={"eol": e["eol"]}))
        # running EC2 instances SSM does not know: their OS is unseen, not supported
        known = {i["id"] for i in info}
        for inst in ctx.per_region("ec2.instances").get(region) or []:
            if inst["state"] == "running" and inst["id"] not in known:
                hidden.setdefault(region, []).append(inst["id"])
    for (region, label), ids in sorted(unknown.items()):
        res.gaps.append(ctx.gap(f"end of life of {label} ({len(ids)} instance(s))",
                                "release not in data/os_eol.json: unknown, not supported", [], region))
    for region, ids in sorted(hidden.items()):
        res.gaps.append(ctx.gap(f"OS of {len(ids)} running instance(s) without SSM",
                                "no SSM agent reports their OS; see srv.software-not-visible",
                                ["ssm:DescribeInstanceInformation"], region))
    res.stats = {"instances": seen, "unknown_os": sum(map(len, unknown.values())),
                 "not_visible": sum(map(len, hidden.values())), "evaluated": seen > 0 or not hidden}
    return res


INVENTORY_HOWTO = ("enable SSM Inventory: a State Manager association running "
                   "AWS-GatherSoftwareInventory (or Quick Setup Host Management)")
SSM_HOWTO = ("install or start the SSM agent and give the instance a role with "
             "AmazonSSMManagedInstanceCore, then " + INVENTORY_HOWTO)


@check(CheckSpec(
    "srv.software-not-visible", "Instance software not visible to the scanner", "server", "low",
    ("ec2.instances", "ssm.instance_information", "ssm.inventory_applications"),
    covers="Running instances whose installed software cannot be read: no online SSM "
           "agent, or SSM Inventory empty. Each is a finding and a gap: CVE checks cannot "
           "see these hosts, which is not the same as them being clean.",
    does_not_cover="Containers and Lambda code (Inspector covers ECR and Lambda).",
    false_positives="Instances where SSM is blocked by design; overlaps srv.not-ssm-managed "
                    "for the no-agent case."))
def software_not_visible(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    info_all = ctx.per_region("ssm.instance_information")
    inv_all = ctx.per_region("ssm.inventory_applications")
    for region, insts in ctx.per_region("ec2.instances").items():
        if region not in info_all:
            continue                      # unseen: the collector gap already says so
        info = {i["id"]: i for i in info_all[region]}
        inv = inv_all.get(region)
        for i in insts:
            if i["state"] != "running":
                continue
            m = info.get(i["id"])
            rsc = {"id": i["id"], "name": i["name"], "region": region, "type": "ec2_instance"}
            if m is None or m["ping"] != "Online":
                why = "not registered with SSM" if m is None else f"SSM agent {m['ping']}"
                res.findings.append(ctx.finding(
                    rsc, f"{i['name']}: installed software not visible ({why})",
                    [("ssm:DescribeInstanceInformation", i["id"], why)],
                    {"summary": SSM_HOWTO[0].upper() + SSM_HOWTO[1:] + "."},
                    qualifiers={"reason": "no-ssm"}, tags=i["tags"]))
                res.gaps.append(ctx.gap(f"software on {i['name']} ({i['id']})",
                                        f"{why}; to see it, {SSM_HOWTO}", [], region))
                continue
            if inv is None:
                continue                  # inventory collector missed: its gap says so
            x = inv.get(i["id"])
            if x and x["denied"]:
                res.gaps.append(ctx.gap(f"inventory of {i['name']} ({i['id']})", x["denied"],
                                        ["ssm:ListInventoryEntries"], region))
            elif not x or not x["entries"]:
                res.findings.append(ctx.finding(
                    rsc, f"{i['name']}: SSM Inventory is empty",
                    [("ssm:ListInventoryEntries", i["id"], "AWS:Application: 0 entries")],
                    {"summary": INVENTORY_HOWTO[0].upper() + INVENTORY_HOWTO[1:] + "."},
                    qualifiers={"reason": "no-inventory"}, tags=i["tags"]))
                res.gaps.append(ctx.gap(f"software on {i['name']} ({i['id']})",
                                        f"SSM Inventory has no AWS:Application data; {INVENTORY_HOWTO}",
                                        [], region))
    return res


# ---------------------------------------------------------------- tier 2: Inspector
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
            "INFORMATIONAL": "info", "UNTRIAGED": "medium"}
CVE_ID = re.compile(r"^[A-Z][A-Z0-9]*-[A-Za-z0-9.:_-]+$")
INSPECTOR_TYPES = {"ec2": ("EC2", "ec2_instance"), "ecr": ("ECR", "ecr_image"),
                   "lambda": ("LAMBDA", "lambda_function")}
INSPECTOR_COST = ("Cost: Inspector bills per EC2 instance scanned per month, per ECR image "
                  "scan and per Lambda function per month; a new account gets a 15-day free "
                  "trial (https://aws.amazon.com/inspector/pricing/).")


def _cvss(x):
    return float(x) if isinstance(x, (int, float)) and 0 <= x <= 10 else None


def cve_block(vid: str, pkg: dict, cvss, source: str) -> dict | None:
    vid = (vid or "").upper()
    if not CVE_ID.match(vid):
        return None
    return {"id": vid, "package": pkg.get("name", ""), "installed_version": pkg.get("version", ""),
            "fixed_version": pkg.get("fixed"), "cvss": _cvss(cvss), "source": source}


def _worst(sevs) -> str:
    order = ("info", "low", "medium", "high", "critical")
    return max(sevs, key=order.index) if sevs else "info"


@check(CheckSpec(
    "cve.inspector", "Known vulnerability reported by Amazon Inspector", "vulnerability", "high",
    ("inspector2.findings",), tier=2, references=("AWS FSBP Inspector.1",),
    covers="Active Inspector v2 package-vulnerability findings on EC2 instances, ECR images "
           "and Lambda functions, one per package on each resource with every CVE in it, the "
           "worst one's CVSS, and the fixed version that clears them. Inspector off (or one resource type off) is a gap, with "
           "the steps to enable it and its cost.",
    does_not_cover="Network-reachability and code findings from Inspector; suppressed findings."))
def inspector(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    enabled_regions, findings_n, cves_n = 0, 0, 0
    for region, p in sorted(ctx.per_region("inspector2.findings").items()):
        st = p["status"]
        on = [k for k in INSPECTOR_TYPES if st.get(k) == "ENABLED"]
        off = [k for k in INSPECTOR_TYPES if k not in on]
        enable = (f"aws inspector2 enable --region {region} --resource-types "
                  + " ".join(INSPECTOR_TYPES[k][0] for k in off))
        if not on:
            res.gaps.append(ctx.gap(
                "Inspector v2 CVE scanning (EC2, ECR, Lambda)",
                f"Inspector is not enabled (account {st.get('account')}): no CVE result, "
                f"which is not a clean one. Enable: `{enable}`. {INSPECTOR_COST}",
                ["inspector2:Enable"], region))
            continue
        enabled_regions += 1
        for k in off:
            res.gaps.append(ctx.gap(
                f"Inspector {INSPECTOR_TYPES[k][0]} scanning",
                f"resource type {k} is {st.get(k)}: its CVEs are unseen. Enable: "
                f"`aws inspector2 enable --region {region} --resource-types "
                f"{INSPECTOR_TYPES[k][0]}`. {INSPECTOR_COST}", ["inspector2:Enable"], region))
        # One finding per package on a resource, not per CVE: one upgrade closes them all,
        # and per CVE the lab's old host alone had 4,222 (3,841 its kernel).
        # A CVE in two packages is reported on both, since each needs its own upgrade.
        grouped: dict[tuple, dict] = {}
        for f in p["findings"]:
            for pk in f["packages"] or [{"name": "", "version": "", "fixed": None}]:
                g = grouped.setdefault((f["resource_id"], pk["name"]), {"f": f, "cves": {}})
                g["cves"].setdefault(f["vuln_id"].upper(), []).append((f, pk))
        per_resource: dict[str, dict] = {}
        for (rid, name), g in sorted(grouped.items()):
            f, cves = g["f"], g["cves"]
            sev_of = {vid: _worst([SEVERITY.get(x["severity"], "medium") for x, _ in hs])
                      for vid, hs in cves.items()}
            cvss_of = {vid: max((x["cvss"] for x, _ in hs if x["cvss"] is not None), default=None)
                       for vid, hs in cves.items()}
            order = ("info", "low", "medium", "high", "critical")
            worst = max(sorted(cves), key=lambda v: (order.index(sev_of[v]), cvss_of[v] or -1))
            fixes = [pk["fixed"] for hs in cves.values() for _, pk in hs[:1] if pk.get("fixed")]
            fixed_n = sum(1 for hs in cves.values() if hs[0][1].get("fixed"))
            top = None
            for v in fixes:
                top = v if top is None or vercmp(v, top) > 0 else top
            pk = {**cves[worst][0][1], "fixed": top}
            label = name or "the package"
            n = len(cves)
            if n == 1:
                title = f"{worst} in {pk['name']} {pk['version']} on {f['resource_name']}"
                fix = (f"Update {label} to {top} or later" if top
                       else f"No fixed version of {label} yet; mitigate or replace it")
            else:
                title = (f"{n:,} known vulnerabilities in {pk['name']} {pk['version']} on "
                         f"{f['resource_name']} (worst {worst}, {sev_of[worst]})")
                fix = (f"Update {label} to {top} or later; that fixes "
                       + (f"all {n:,}" if fixed_n == n else f"{fixed_n:,} of {n:,}")
                       if top else f"No fixed version of {label} yet for any of its {n:,} CVEs; "
                                   "mitigate or replace it")
                if top and fixed_n < n:
                    fix += (f"; {n - fixed_n:,} {'has' if n - fixed_n == 1 else 'have'} "
                            "no fixed version yet")
            block = cve_block(worst, pk, max((c for c in cvss_of.values() if c is not None),
                                             default=None), "inspector")
            if block is not None and n > 1:
                block["ids"] = sorted(cves)
            res.findings.append(ctx.finding(
                {"id": rid, "name": f["resource_name"], "region": region, "type": f["resource_type"]},
                title,
                [("inspector2:ListFindings", x["arn"],
                  f"{vid} severity {x['severity']}, inspector score {x['score']}")
                 for vid, hs in sorted(cves.items()) for x, _ in hs],
                {"summary": fix + " (and redeploy the image or function)."
                 if f["resource_type"] != "ec2_instance" else fix + "."},
                severity=_worst(list(sev_of.values())), qualifiers={"package": name},
                cve=block))
            r = per_resource.setdefault(rid, {"f": f, "cves": {}})
            r["cves"].update(sev_of)
            findings_n += 1
        for rid, r in sorted(per_resource.items()):
            hits = [(sev, r["f"]) for sev in r["cves"].values()]
            f = hits[0][1]
            fact, nodes = _vuln_node(
                ctx, rid, f["resource_type"], region, f["resource_name"], len(hits),
                _worst([s for s, _ in hits]),
                [("inspector2:ListFindings", rid, f"{len(hits)} active package vulnerabilities")])
            res.facts.append(fact)
            res.nodes += nodes
            cves_n += len(hits)
    res.stats = {"regions_enabled": enabled_regions, "findings": findings_n,
                 "cves": cves_n, "evaluated": enabled_regions > 0}
    return res


# ---------------------------------------------------------------- tier 2: Patch Manager
@check(CheckSpec(
    "cve.missing-patches", "Instance is missing patches (SSM Patch Manager)", "vulnerability",
    "medium", ("ssm.patch_states",), tier=2, references=("AWS FSBP SSM.2",),
    covers="Online SSM-managed instances whose last Patch Manager scan reports missing, "
           "failed, critical or security patches: high with critical, medium with security, "
           "low otherwise. An instance with no scan recorded is a gap.",
    does_not_cover="Which CVEs the patches fix (Patch Manager reports counts); instances "
                   "without an online SSM agent (srv.software-not-visible)."))
def missing_patches(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    scanned = 0
    for region, p in sorted(ctx.per_region("ssm.patch_states").items()):
        names = _names(ctx, region)
        for iid in p["managed"]:
            s = p["states"].get(iid)
            name = names.get(iid, iid)
            if s is None:
                res.gaps.append(ctx.gap(
                    f"patch state of {name} ({iid})", "no Patch Manager scan recorded; run "
                    "AWS-RunPatchBaseline with Operation=Scan, or set up a patch policy", [], region))
                continue
            scanned += 1
            if not (s["missing"] or s["failed"] or s["critical"] or s["security"]):
                continue
            sev = "high" if s["critical"] else "medium" if s["security"] else "low"
            detail = (f"missing {s['missing']}, failed {s['failed']}, critical non-compliant "
                      f"{s['critical']}, security non-compliant {s['security']} "
                      f"(baseline {s['baseline']}, scanned {s['scanned_at']})")
            ev = [("ssm:DescribeInstancePatchStates", iid, detail)]
            res.findings.append(ctx.finding(
                {"id": iid, "name": name, "region": region, "type": "ec2_instance"},
                f"{name} is missing {s['missing']} patch(es)"
                + (f", {s['critical']} critical" if s["critical"] else "")
                + (f", {s['security']} security" if s["security"] else ""), ev,
                {"summary": "Run AWS-RunPatchBaseline with Operation=Install (or a patch "
                            "policy / maintenance window).",
                 "cli": f"aws ssm send-command --region {region} --document-name "
                        f"AWS-RunPatchBaseline --instance-ids {iid} --parameters Operation=Install"},
                severity=sev))
            if s["critical"] or s["security"]:
                fact, nodes = _vuln_node(ctx, iid, "ec2_instance", region, name,
                                         s["critical"] + s["security"], sev, ev)
                res.facts.append(fact)
                res.nodes += nodes
    res.stats = {"instances_scanned": scanned}
    return res


# ---------------------------------------------------------------- tier 2: offline OSV
def _ord(s: str, i: int) -> int:
    if i >= len(s) or s[i].isdigit():
        return 0
    c = s[i]
    return ord(c) if c.isalpha() else -1 if c == "~" else ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    """dpkg's version-part comparison: `~` sorts before everything, letters before
    other symbols, digit runs numerically."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac, bc = _ord(a, i), _ord(b, j)
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            first = first or ord(a[i]) - ord(b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def _split(v: str):
    epoch, _, rest = v.partition(":") if re.match(r"^\d+:", v) else ("0", "", v)
    up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), up, rev


def vercmp(a: str, b: str) -> int:
    """<0, 0, >0. Debian ordering, close enough for rpm and apk versions (DESIGN limits)."""
    (ea, ua, ra), (eb, ub, rb) = _split(a), _split(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def affected(aff: dict, installed: str):
    """(is affected, fixed version or None) for one OSV `affected` entry."""
    hit = installed in aff.get("versions", [])
    fixed = None
    for r in aff.get("ranges", []):
        if r.get("type") != "ECOSYSTEM":
            continue
        inside = False
        for e in r.get("events", []):        # OSV: events are in version order
            if "introduced" in e and (e["introduced"] == "0" or vercmp(installed, e["introduced"]) >= 0):
                inside = True
            elif "fixed" in e and inside:
                if vercmp(installed, e["fixed"]) < 0:
                    return True, e["fixed"]
                inside = False
            elif "last_affected" in e and inside:
                if vercmp(installed, e["last_affected"]) <= 0:
                    return True, None
                inside = False
        if inside:
            return True, None
    return hit, fixed


_DB_CACHE: dict = {}


_NAME = re.compile(rb'"name"\s*:\s*"([^"]+)"')


_REC_KEYS = ("id", "aliases", "upstream", "severity", "database_specific")


def _slim(rec: dict, aff: dict, installed: set[str] | None) -> tuple[dict, dict]:
    """The fields the check reads. With the installed versions known, `versions` keeps only
    those: `affected()` asks whether the installed version is listed, nothing more."""
    r = {k: rec[k] for k in _REC_KEYS if k in rec}
    a = {k: aff[k] for k in ("package", "ranges", "ecosystem_specific") if k in aff}
    vs = aff.get("versions", [])
    a["versions"] = vs if installed is None else [v for v in vs if v in installed]
    return r, a


def load_osv(path: str, wanted: dict[tuple[str, str], set[str]] | set[tuple[str, str]] | None = None
             ) -> dict | None:
    """The offline OSV copy: ecosystem zips (`<Ecosystem>/all.zip`, as update-db writes
    them) and/or loose record files. Read in memory, never extracted. None if absent.

    `wanted` is the (ecosystem, package) pairs installed on the scanned hosts, optionally
    mapped to their installed versions; only those are indexed, a record naming none of
    the packages is never parsed, and each kept record is slimmed to what matching needs. Loading a whole
    copy (Ubuntu alone: 72,856 records, 793 MB) swapped an 8 GB machine (DESIGN, live lab).
    None means index everything (tests and small copies)."""
    root = Path(path).expanduser()
    if not root.is_dir():
        return None
    files = sorted(f for f in root.rglob("*") if f.is_file() and (
        f.suffix == ".zip" or (f.suffix == ".json" and f.name != "manifest.json")))
    if isinstance(wanted, dict):
        wkey = frozenset((k, frozenset(v)) for k, v in wanted.items())
    else:
        wkey = None if wanted is None else frozenset(wanted)
    key = (str(root), tuple((str(f), f.stat().st_size, f.stat().st_mtime_ns) for f in files), wkey)
    if key in _DB_CACHE:
        return _DB_CACHE[key]
    names = None if wanted is None else {n.encode() for _, n in wanted}
    index: dict[tuple, list] = {}
    ident, count = hashlib.sha256(), 0

    def take(raw: bytes):
        if names is not None and not names.intersection(_NAME.findall(raw)):
            return
        rec = json.loads(raw)
        for aff in rec.get("affected", []):
            pkg = aff.get("package") or {}
            k = (pkg.get("ecosystem"), pkg.get("name"))
            if wanted is None:
                index.setdefault(k, []).append((rec, aff))
            elif k in wanted:
                index.setdefault(k, []).append(
                    _slim(rec, aff, wanted[k] if isinstance(wanted, dict) else None))

    for f in files:
        if f.suffix == ".zip":
            with zipfile.ZipFile(f) as z:
                for info in sorted(z.infolist(), key=lambda i: i.filename):
                    if info.filename.endswith(".json"):
                        count += 1
                        ident.update(f"{info.filename}:{info.CRC}:{info.file_size};".encode())
                        take(z.read(info))
        else:
            raw = f.read_bytes()
            count += 1
            ident.update(f"{f.name}:{hashlib.sha256(raw).hexdigest()};".encode())
            take(raw)
    if not count:
        return None
    # The fingerprint names the copy (every record's name and checksum), not the subset
    # this scan needed, so two scans of different hosts report the same database.
    db = {"index": index, "records": count, "fingerprint": "sha256:" + ident.hexdigest()[:12]}
    _DB_CACHE.clear()
    _DB_CACHE[key] = db
    return db


def ecosystem(info: dict | None, mapping: list) -> str | None:
    if not info:
        return None
    for m in mapping:
        if re.search(m["platform"], info["platform_name"] or ""):
            v = re.search(m["version"], info["platform_version"] or "")
            if v:
                return m["ecosystem"].format(v=v.group(1))
    return None


def _installed(e: dict) -> str:
    v = e["version"]
    if e.get("release") and e["release"] not in v:
        v = f"{v}-{e['release']}"
    return f"{e['epoch']}:{v}" if e.get("epoch") not in (None, "", "0") and ":" not in v else v


def _osv_severity(rec: dict, aff: dict) -> str:
    words = {"critical": "critical", "high": "high", "important": "high", "medium": "medium",
             "moderate": "medium", "low": "low", "negligible": "low", "unimportant": "low"}
    cands = [s.get("score", "") for s in rec.get("severity", []) if not str(s.get("type", "")).startswith("CVSS")]
    cands += [(rec.get("database_specific") or {}).get("severity", ""),
              (aff.get("ecosystem_specific") or {}).get("urgency", "")]
    for c in cands:
        if str(c).lower() in words:
            return words[str(c).lower()]
    return "medium"


def osv_ids(rec: dict) -> list[str]:
    return [rec.get("id", "")] + list(rec.get("aliases", [])) + list(rec.get("upstream", []))


@check(CheckSpec(
    "cve.osv-packages", "Installed package has a known vulnerability (offline OSV)",
    "vulnerability", "medium", ("ssm.inventory_applications", "ssm.instance_information"),
    tier=2, config={"db_path": OSV_DEFAULT_DIR},
    covers="SSM Inventory AWS:Application packages on Ubuntu LTS, Debian, AlmaLinux, Rocky "
           "and Alpine, matched by name and version against an offline OSV copy "
           "(`cloudtools cve update-db`). No copy is a gap. Package lists never leave the "
           "machine. A CVE Inspector already reports on the same resource is dropped (R5.3).",
    does_not_cover="Amazon Linux and Windows (no OSV ecosystem mapped: use Inspector); "
                   "kernel packages (left to Inspector, a gap when it doesn't cover the host); "
                   "packages whose binary name differs from OSV's source-package name "
                   "(libssl3 vs openssl); language packages.",
    false_positives="Distribution backports: a vendor-patched build may compare older "
                    "than OSV's fixed version."))
def osv_packages(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    path = ctx.config.get("db_path", OSV_DEFAULT_DIR)
    data = data_file("osv_ecosystems.json")
    mapping = data["entries"]
    skip = re.compile("|".join(data["skip_packages"]["patterns"]))
    wanted: dict[tuple[str, str], set[str]] = {}
    for region, inv in ctx.per_region("ssm.inventory_applications").items():
        info = {i["id"]: i for i in ctx.per_region("ssm.instance_information").get(region) or []}
        for iid, x in inv.items():
            eco = None if x["denied"] else ecosystem(info.get(iid), mapping)
            if eco:
                for e in x["entries"]:
                    if not skip.search(e["name"]):
                        wanted.setdefault((eco, e["name"]), set()).add(_installed(e))
    db = load_osv(path, wanted)
    if db is None:
        res.gaps.append(ctx.gap(
            "offline OSV database", f"none found at {path}: package CVEs unseen, not clean. "
            "Download it with `cloudtools cve update-db` (the only network use; the scan "
            "never sends package lists anywhere)", []))
        res.stats = {"evaluated": False}
        return res
    seen_by_inspector = {(f["resource_id"], f["vuln_id"].upper())
                         for p in ctx.per_region("inspector2.findings").values()
                         for f in p.get("findings", [])}
    inspected = {i for i, _ in seen_by_inspector}
    dups, matched, packages, kernels, unmapped = 0, 0, 0, 0, {}
    for region, inv in sorted(ctx.per_region("ssm.inventory_applications").items()):
        info = {i["id"]: i for i in ctx.per_region("ssm.instance_information").get(region) or []}
        names = _names(ctx, region)
        for iid, x in sorted(inv.items()):
            if x["denied"]:
                res.gaps.append(ctx.gap(f"inventory of {iid}", x["denied"],
                                        ["ssm:ListInventoryEntries"], region))
                continue
            eco = ecosystem(info.get(iid), mapping)
            if not eco:
                i = info.get(iid) or {}
                label = f"{i.get('platform_name', '')} {i.get('platform_version', '')}".strip() or "unknown OS"
                unmapped.setdefault((region, label), []).append(iid)
                continue
            name = names.get(iid, iid)
            hits: dict[str, tuple] = {}
            skipped = [e["name"] for e in x["entries"] if skip.search(e["name"])]
            kernels += len(skipped)
            if skipped and iid not in inspected:
                res.gaps.append(ctx.gap(
                    f"kernel CVEs on {name} ({iid})",
                    f"{len(skipped)} kernel package(s) not matched offline: OSV keys kernels by "
                    "source package and SSM lists binary names, so name matching is wrong for "
                    "them (data/osv_ecosystems.json skip_packages). Inspector covers kernels; "
                    "it reported nothing for this host", ["inspector2:ListFindings"], region))
            for e in x["entries"]:
                if skip.search(e["name"]):
                    continue
                packages += 1
                inst = _installed(e)
                for rec, aff in db["index"].get((eco, e["name"]), []):
                    hit, fixed = affected(aff, inst)
                    if not hit:
                        continue
                    ids = [i.upper() for i in osv_ids(rec) if i]
                    vid = next((i for i in ids if i.startswith("CVE-")), ids[0])
                    if any((iid, i) in seen_by_inspector for i in ids):
                        dups += 1
                        continue
                    hits.setdefault(vid, (rec, aff, e, inst, fixed))
            for vid, (rec, aff, e, inst, fixed) in sorted(hits.items()):
                matched += 1
                sev = _osv_severity(rec, aff)
                res.findings.append(ctx.finding(
                    {"id": iid, "name": name, "region": region, "type": "ec2_instance"},
                    f"{vid} in {e['name']} {inst} on {name}",
                    [("ssm:ListInventoryEntries", iid, f"AWS:Application {e['name']} {inst}"),
                     ("osv (offline)", rec.get("id", ""),
                      f"{eco}: affected, fixed in {fixed or 'no release yet'}; db {db['fingerprint']}")],
                    {"summary": f"Update {e['name']} to {fixed} or later." if fixed
                     else f"No fixed {e['name']} release yet; mitigate or remove it."},
                    severity=sev, qualifiers={"cve": vid}, confidence=0.7,
                    cve=cve_block(vid, {"name": e["name"], "version": inst, "fixed": fixed},
                                  None, "osv")))
            if hits:
                worst = _worst([_osv_severity(r, a) for r, a, *_ in hits.values()])
                fact, nodes = _vuln_node(
                    ctx, iid, "ec2_instance", region, name, len(hits), worst,
                    [("ssm:ListInventoryEntries", iid, f"{len(hits)} OSV matches, db {db['fingerprint']}")],
                    ["matched by package name and version; a backported fix may already be installed"],
                    0.7)
                res.facts.append(fact)
                res.nodes += nodes
    for (region, label), ids in sorted(unmapped.items()):
        res.gaps.append(ctx.gap(f"OSV matching for {label} ({len(ids)} instance(s))",
                                "no OSV ecosystem mapped for this OS (data/osv_ecosystems.json); "
                                "use cve.inspector for it", [], region))
    res.stats = {"osv_db": db["fingerprint"], "osv_records": db["records"], "packages": packages,
                 "matches": matched, "duplicates_of_inspector": dups,
                 "kernel_packages_skipped": kernels}
    return res
