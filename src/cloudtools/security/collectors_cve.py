"""Tier 2 collectors: what software runs where, and what AWS already knows is vulnerable
(requirements tier 2, R5.2/R5.3). Read-only like every collector: Describe / List /
BatchGet calls through AwsEnv's guarded clients.

Package lists stay in the local snapshot. Nothing here, and nothing in the checks that
read it, sends a package list anywhere: OSV matching runs against an offline copy
(`cloudtools cve update-db`, the only network use, and explicit).
"""
from __future__ import annotations

from ..core.collect import collector
from .collectors import _pages, _try

PATCH_BATCH = 50                       # DescribeInstancePatchStates takes at most 50 ids


def _token_loop(call, key: str, **kw) -> list:
    """Manual NextToken paging, for operations boto3 has no paginator for."""
    out, token = [], None
    while True:
        page = call(**kw, **({"NextToken": token} if token else {}))
        out += page.get(key, [])
        token = page.get("NextToken")
        if not token:
            return out


def _instance_info(ssm) -> list[dict]:
    info = _pages(ssm, "describe_instance_information", "InstanceInformationList")
    return sorted(({"id": i["InstanceId"], "ping": i.get("PingStatus", ""),
                    "platform_type": i.get("PlatformType", ""),
                    "platform_name": i.get("PlatformName", ""),
                    "platform_version": i.get("PlatformVersion", ""),
                    "resource_type": i.get("ResourceType", "")} for i in info),
                  key=lambda x: x["id"])


@collector("ssm.instance_information", ["ssm:DescribeInstanceInformation"])
def instance_information(env, region):
    """Every SSM-registered instance with its OS name and version (any ping status: a
    lost connection still tells the last OS the agent reported)."""
    return _instance_info(env.client("ssm", region))


@collector("ssm.patch_states", ["ssm:DescribeInstanceInformation",
                                "ssm:DescribeInstancePatchStates"])
def patch_states(env, region):
    ssm = env.client("ssm", region)
    managed = [i["id"] for i in _instance_info(ssm) if i["ping"] == "Online"]
    states = {}
    for n in range(0, len(managed), PATCH_BATCH):
        for s in _token_loop(ssm.describe_instance_patch_states, "InstancePatchStates",
                             InstanceIds=managed[n:n + PATCH_BATCH]):
            states[s["InstanceId"]] = {
                "missing": s.get("MissingCount", 0), "failed": s.get("FailedCount", 0),
                "critical": s.get("CriticalNonCompliantCount", 0),
                "security": s.get("SecurityNonCompliantCount", 0),
                "pending_reboot": s.get("InstalledPendingRebootCount", 0),
                "baseline": s.get("BaselineId", ""), "operation": s.get("Operation", ""),
                "scanned_at": str(s.get("OperationEndTime", ""))}
    return {"managed": managed, "states": states}


@collector("ssm.inventory_applications", ["ssm:DescribeInstanceInformation",
                                          "ssm:ListInventoryEntries"])
def inventory_applications(env, region):
    """AWS:Application inventory per online instance: name, version, release, arch.
    One instance's denial is recorded on that instance, not fatal to the region."""
    ssm = env.client("ssm", region)
    out = {}
    for i in _instance_info(ssm):
        if i["ping"] != "Online":
            continue
        entries, why = _try(lambda: _token_loop(
            ssm.list_inventory_entries, "Entries", InstanceId=i["id"], TypeName="AWS:Application"))
        out[i["id"]] = {"denied": why, "entries": sorted(
            ({"name": e.get("Name", ""), "version": e.get("Version", ""),
              "release": e.get("Release", ""), "epoch": e.get("Epoch", ""),
              "arch": e.get("Architecture", ""), "type": e.get("ApplicationType", "")}
             for e in (entries or [])), key=lambda e: (e["name"], e["version"]))}
    return out


INSPECTOR_TYPES = {"AWS_EC2_INSTANCE": "ec2_instance", "AWS_ECR_CONTAINER_IMAGE": "ecr_image",
                   "AWS_LAMBDA_FUNCTION": "lambda_function"}
_ACTIVE_PACKAGE_VULNS = {
    "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
    "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]}


def _version(p: dict) -> str:
    v = p.get("version", "")
    rel = p.get("release")
    v = f"{v}-{rel}" if rel and rel not in v else v
    return f"{p['epoch']}:{v}" if p.get("epoch") not in (None, 0, "0", "") else v


def _resource_name(r: dict) -> str:
    d = r.get("details") or {}
    if "awsEcrContainerImage" in d:
        img = d["awsEcrContainerImage"]
        tags = img.get("imageTags") or []
        return f"{img.get('repositoryName', '')}:{tags[0] if tags else img.get('imageHash', '')[:19]}"
    if "awsLambdaFunction" in d:
        return d["awsLambdaFunction"].get("functionName", "")
    return r.get("id", "")


def normalise_inspector_finding(f: dict) -> dict | None:
    r = (f.get("resources") or [{}])[0]
    rtype = INSPECTOR_TYPES.get(r.get("type", ""))
    pv = f.get("packageVulnerabilityDetails") or {}
    if not rtype or not pv.get("vulnerabilityId"):
        return None
    cvss = [c.get("baseScore") for c in pv.get("cvss", []) if c.get("baseScore") is not None]
    fixed = lambda p: (p.get("fixedInVersion") if p.get("fixedInVersion")  # noqa: E731
                       not in (None, "", "NotAvailable") else None)
    return {"arn": f.get("findingArn", ""), "vuln_id": pv["vulnerabilityId"],
            "severity": f.get("severity", "UNTRIAGED"), "score": f.get("inspectorScore"),
            "cvss": max(cvss) if cvss else None, "title": f.get("title", ""),
            "resource_type": rtype, "resource_id": r.get("id", ""),
            "resource_name": _resource_name(r), "fix_available": f.get("fixAvailable", ""),
            "packages": [{"name": p.get("name", ""), "version": _version(p), "fixed": fixed(p)}
                         for p in pv.get("vulnerablePackages", [])]}


@collector("inspector2.findings", ["inspector2:BatchGetAccountStatus", "inspector2:ListFindings"])
def inspector_findings(env, region):
    """Account status per resource type, then active package-vulnerability findings.
    Off is recorded as off (the check turns it into a gap), never as an empty list."""
    insp = env.client("inspector2", region)
    accts = insp.batch_get_account_status().get("accounts", [])
    a = accts[0] if accts else {}
    rs = a.get("resourceState") or {}
    status = {"account": (a.get("state") or {}).get("status", "UNKNOWN"),
              **{k: (rs.get(k) or {}).get("status", "UNKNOWN") for k in ("ec2", "ecr", "lambda")}}
    findings = []
    if any(status[k] == "ENABLED" for k in ("ec2", "ecr", "lambda")):
        for f in _pages(insp, "list_findings", "findings", filterCriteria=_ACTIVE_PACKAGE_VULNS):
            n = normalise_inspector_finding(f)
            if n:
                findings.append(n)
    return {"status": status, "findings": sorted(findings, key=lambda x: (x["resource_id"], x["vuln_id"]))}


# Doctor probes (one cheap read each), found here by doctor.probe_for at run time. The
# inventory and patch collectors need an instance id for their own action, so they probe
# DescribeInstanceInformation, the first call each makes; a denied second action shows
# as a scan gap (DESIGN "Known limits": one probe per collector).
PROBES = {
    "ssm.instance_information": ("ssm", "describe_instance_information", {"MaxResults": 5}),
    "ssm.patch_states": ("ssm", "describe_instance_information", {"MaxResults": 5}),
    "ssm.inventory_applications": ("ssm", "describe_instance_information", {"MaxResults": 5}),
    "inspector2.findings": ("inspector2", "batch_get_account_status", {}),
}
