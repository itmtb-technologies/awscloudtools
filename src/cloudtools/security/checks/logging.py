"""log.*: logging and detection (requirements check catalogue, MVP)."""
from __future__ import annotations

from ...core.model import CheckResult
from . import CheckSpec, check


@check(CheckSpec(
    "log.cloudtrail-not-multiregion", "No multi-region CloudTrail trail is logging",
    "logging", "high", ("cloudtrail.trails",), references=("CIS 3.1",),
    covers="Whether at least one multi-region trail is logging (an organization trail counts)."))
def cloudtrail(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    trails = ctx.glob("cloudtrail.trails")
    if trails is None:
        return res
    for t in trails:
        if t["status_denied"]:
            res.gaps.append(ctx.gap(f"status of trail {t['name']}", t["status_denied"],
                                    ["cloudtrail:GetTrailStatus"], t["home"]))
    good = [t for t in trails if t["multi_region"] and t["logging"]]
    unknown = [t for t in trails if t["multi_region"] and t["logging"] is None]
    if not good and not unknown:
        res.findings.append(ctx.finding(
            {"id": f"arn:aws:cloudtrail:::account/{ctx.account}", "name": "CloudTrail",
             "type": "account"},
            "No multi-region CloudTrail trail is logging",
            [("cloudtrail:DescribeTrails", ctx.account,
              f"{len(trails)} trail(s), none multi-region and logging")],
            {"summary": "Create a multi-region trail (or an organization trail) with log file "
                        "validation, delivering to a locked-down bucket."}))
    for t in good:
        if not t["validation"]:
            res.findings.append(ctx.finding(
                {"id": t["arn"], "name": t["name"], "region": t["home"], "type": "cloudtrail_trail"},
                f"Trail {t['name']} has log file validation off",
                [("cloudtrail:DescribeTrails", t["arn"], "LogFileValidationEnabled=false")],
                {"summary": "Enable log file validation."}, severity="low",
                qualifiers={"aspect": "validation"}))
    return res


@check(CheckSpec(
    "log.guardduty-off", "GuardDuty is not enabled in a region", "logging", "medium",
    ("guardduty.detectors",), references=("AWS FSBP GuardDuty.1",),
    covers="Each scanned region: an ENABLED GuardDuty detector exists."))
def guardduty(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, dets in ctx.per_region("guardduty.detectors").items():
        if any(d["denied"] for d in dets):
            res.gaps.append(ctx.gap(f"GuardDuty detector status in {region}", "denied",
                                    ["guardduty:GetDetector"], region))
            continue
        if not any(d["status"] == "ENABLED" for d in dets):
            res.findings.append(ctx.finding(
                {"id": f"guardduty/{region}", "name": f"GuardDuty {region}", "region": region,
                 "type": "account"},
                f"GuardDuty is off in {region}",
                [("guardduty:ListDetectors", region, f"{len(dets)} detector(s), none enabled")],
                {"summary": "Enable GuardDuty in every region (it has a free trial, then costs "
                            "per event volume).",
                 "cli": f"aws guardduty create-detector --enable --region {region}"}))
    return res


@check(CheckSpec(
    "log.vpc-flow-logs-missing", "VPC has no flow logs", "logging", "low", ("ec2.vpcs",),
    references=("CIS 3.7",), covers="VPCs with no active flow log.",
    false_positives="Empty default VPCs: delete them or accept the risk."))
def flow_logs(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, p in ctx.per_region("ec2.vpcs").items():
        for v in p["vpcs"]:
            if not v["flow_logs"]:
                res.findings.append(ctx.finding(
                    {"id": v["id"], "name": v["tags"].get("Name", v["id"]), "region": region, "type": "vpc"},
                    f"VPC {v['id']} has no flow logs{' (default VPC)' if v['default'] else ''}",
                    [("ec2:DescribeFlowLogs", v["id"], "no active flow log")],
                    {"summary": "Enable VPC flow logs (REJECT at least) to CloudWatch or S3."},
                    tags=v["tags"]))
    return res


@check(CheckSpec(
    "log.config-not-recording", "AWS Config is not recording", "logging", "low",
    ("config.recorders",), references=("CIS 3.3",),
    covers="Each scanned region: a configuration recorder that is recording."))
def config_rec(ctx) -> CheckResult:
    res = CheckResult(gaps=ctx.gaps())
    for region, recs in ctx.per_region("config.recorders").items():
        if not any(r["recording"] for r in recs):
            res.findings.append(ctx.finding(
                {"id": f"config/{region}", "name": f"AWS Config {region}", "region": region,
                 "type": "account"},
                f"AWS Config is not recording in {region}",
                [("config:DescribeConfigurationRecorderStatus", region,
                  f"{len(recs)} recorder(s), none recording")],
                {"summary": "Enable a configuration recorder for all resources (costs per item "
                            "recorded)."}))
    return res
