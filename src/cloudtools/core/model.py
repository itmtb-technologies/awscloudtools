"""Facts, findings and gaps: the stable machine contract (requirements §Fact and edge
schema, §Findings model). Ids are deterministic so two runs, two machines or the two
variants produce the same id for the same thing (R6.1)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = "1"

SEVERITIES = ("info", "low", "medium", "high", "critical")
EDGE_TYPES = frozenset({
    "reaches", "runs_as", "exposes_credentials", "contains_credential", "authenticates_as",
    "can_assume", "can_read", "can_write", "can_execute_on", "can_escalate_to",
    "can_disable", "is_public", "has_vulnerability",
})
NODE_TYPES = frozenset({
    "internet", "external_principal", "leaked_credential", "iam_user", "iam_role",
    "iam_group", "ec2_instance", "lambda_function", "ecs_task", "eks_cluster",
    "load_balancer", "api_gateway", "s3_bucket", "rds_instance", "snapshot", "secret",
    "kms_key", "cloudtrail_trail", "admin_equivalent", "security_group", "sqs_queue",
    "sns_topic", "ebs_volume", "ami", "ecr_repository", "account",
})
INTERNET = "internet"
ADMIN = "admin_equivalent"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def stable_id(prefix: str, *parts: Any) -> str:
    return prefix + hashlib.sha256(canonical(parts).encode()).hexdigest()[:16]


def fingerprint(secret_value: str, salt: str) -> str:
    """Salted sha256 prefix of a secret (R5.1). The value itself is never stored; the
    salt is per installation so a fingerprint cannot be looked up in a rainbow table."""
    return "sha256:" + hashlib.sha256((salt + secret_value).encode()).hexdigest()[:12]


def redacted_preview(secret_value: str, keep: int = 4) -> str:
    return secret_value[:keep] + "****" if len(secret_value) > keep else "****"


@dataclass
class Evidence:
    source: str                 # "ec2:DescribeSecurityGroups"
    resource: str = ""
    detail: str = ""


@dataclass
class Node:
    id: str
    type: str
    account: str = ""
    region: str = ""
    name: str = ""              # untrusted input from the account (R6.4)
    tags: dict = field(default_factory=dict)
    labels: list = field(default_factory=list)   # entry_point | crown_jewel | protected
    attrs: dict = field(default_factory=dict)


@dataclass
class Fact:
    """A typed, directed edge carrying its own evidence (R6.2)."""
    src: str
    type: str
    dst: str
    emitted_by: str
    evidence: list[Evidence]
    qualifiers: dict = field(default_factory=dict)
    status: str = "confirmed"   # confirmed | possible (R6.3: never upgraded)
    confidence: float = 1.0
    conditions: list = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if self.type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type {self.type!r}")
        if not self.evidence:
            raise ValueError("a fact needs at least one piece of evidence (R6.2)")
        if self.conditions and self.status == "confirmed":
            self.status = "possible"

    @property
    def id(self) -> str:
        return stable_id("f-", self.src, self.type, self.dst, self.qualifiers)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["from"], d["to"] = d.pop("src"), d.pop("dst")
        return d


@dataclass
class Gap:
    """Something a check could not see. Never a pass (R8.1)."""
    check_id: str
    what: str                   # "security groups in eu-west-1"
    why: str                    # "AccessDenied on ec2:DescribeSecurityGroups"
    needs: list = field(default_factory=list)   # IAM actions that would close it
    region: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    check_id: str
    resource: dict              # {id, name, region, account, type}
    title: str
    severity: str
    evidence: list[Evidence]
    remediation: dict           # {summary, cli?, terraform?}
    qualifiers: dict = field(default_factory=dict)
    confidence: float = 1.0
    references: list = field(default_factory=list)
    status: str = "open"        # open | resolved | accepted
    accepted_reason: str = ""
    contextual_severity: str = ""
    on_paths: list = field(default_factory=list)
    diff: str = ""              # new | unchanged | regressed | resolved
    gaps: list = field(default_factory=list)
    cve: dict | None = None     # tier 2: {id, package, installed_version, fixed_version, cvss, source}
    secret: dict | None = None  # tier 1/creds: {detector, fingerprint, preview, location}; never a value

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity {self.severity!r}")

    @property
    def id(self) -> str:
        return stable_id("fd-", self.check_id, self.resource.get("id", ""), self.qualifiers)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        d["severity"] = {"base": self.severity,
                         "contextual": self.contextual_severity or self.severity}
        d.pop("contextual_severity")
        return d


ACCEPT_TAG = "scanner:accepted-risk"


def apply_accepted_risk(finding: Finding, tags: dict | None) -> Finding:
    """R8.2: a resource tagged scanner:accepted-risk=<reason> is reported as accepted."""
    reason = (tags or {}).get(ACCEPT_TAG)
    if reason:
        finding.status = "accepted"
        finding.accepted_reason = reason
    return finding


@dataclass
class CheckResult:
    findings: list[Finding] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    nodes: list[Node] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
