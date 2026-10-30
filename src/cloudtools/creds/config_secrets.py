"""Tier 1: secrets in AWS configuration (opt-in, `--tier 1`). Collectors and detection.

Six sources, each read through an AwsEnv built for tier >= 1 (the guard refuses these
reads at tier 0, `core/aws.py` TIER1_OPERATIONS):
  * EC2 user data (`DescribeInstanceAttribute userData`, base64, maybe gzip);
  * Lambda environment variables and code (`GetFunction`; the deployment zip is fetched
    from its presigned URL into memory, capped at CODE_MAX_BYTES, never written to disk);
  * ECS task definitions, latest active revision per family (`environment` only; the
    `secrets` list holds references, not values);
  * CloudFormation templates (`GetTemplate`) and the visible stack parameters;
  * CodeBuild project environment variables of type PLAINTEXT (the other types are refs);
  * SSM parameters of type String/StringList, every version (`GetParameterHistory`, never
    with decryption: the guard refuses WithDecryption at every tier, and SecureString
    parameters are not asked for).

No value leaves this module (R5.1). Each hit is reduced, where it is found, to a detector
name, a salted fingerprint, a masked preview (<= 12 characters) and a location; the
collector returns only those, so the snapshot, the report and the run log never see the
value. An AWS access key *id* is fingerprinted with the fixed KEY_ID_SALT (it is an
identifier, not a secret) so it compares equal to the IAM side, as in the repo scan.

Detection is a vendored subset of the gitleaks v8 default rules (rule ids kept) plus a
keyword-gated entropy check (see ENTROPY_MIN).
"""
from __future__ import annotations

import base64
import gzip
import io
import math
import re
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from ..core import tls
from ..core.aws import WriteRefused
from ..core.collect import collector
from ..core.model import fingerprint
from ..security.collectors import _pages
from .repo_secrets import key_id_fp

# ------------------------------------------------------------------ detection
# (gitleaks rule id, kind, pattern). Group 1, when present, is the secret.
RULES = [
    ("aws-access-token", "aws_access_key_id",
     r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"),
    ("private-key", "private_key",
     r"(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]{64,}?"
     r"-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)"),
    ("github-pat", "token", r"\b(ghp_[0-9a-zA-Z]{36})\b"),
    ("github-oauth", "token", r"\b(gho_[0-9a-zA-Z]{36})\b"),
    ("github-app-token", "token", r"\b((?:ghu|ghs)_[0-9a-zA-Z]{36})\b"),
    ("github-fine-grained-pat", "token", r"\b(github_pat_[0-9a-zA-Z_]{82})\b"),
    ("gitlab-pat", "token", r"\b(glpat-[0-9a-zA-Z_-]{20})\b"),
    ("slack-bot-token", "token", r"\b(xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z-]{10,250})\b"),
    ("slack-webhook-url", "token",
     r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{20,100})"),
    ("stripe-access-token", "api_key", r"\b((?:sk|rk)_(?:test|live|prod)_[0-9a-zA-Z]{10,99})\b"),
    ("gcp-api-key", "api_key", r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    ("sendgrid-api-token", "api_key", r"\b(SG\.[A-Za-z0-9=_.-]{66})\b"),
    ("npm-access-token", "token", r"\b(npm_[a-zA-Z0-9]{36})\b"),
    ("openai-api-key", "api_key", r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b"),
    ("anthropic-api-key", "api_key", r"\b(sk-ant-(?:api03|admin01)-[a-zA-Z0-9_-]{93}AA)\b"),
    ("jwt", "token", r"\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/_-]{17,}\.[a-zA-Z0-9/_-]{10,}={0,2})"),
    ("aws-secret-access-key", "aws_secret_access_key",
     r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"\s:=]+([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])"),
    # scheme://user:password@host: the password only.
    ("url-credentials", "password", r"\b[a-z][a-z0-9+.-]{1,20}://[^:/\s@\"']{1,64}:([^@\s/\"']{3,128})@[^\s/\"']+"),
]
_RULES = [(rid, kind, re.compile(p)) for rid, kind, p in RULES]

# The entropy check runs only on a value whose NAME says it is a secret (an env var, a
# parameter, a `key = value` assignment). Threshold: >= 8 characters and Shannon entropy
# >= 3.0 bits per character. gitleaks' free-text generic rule uses 3.5; a field named
# PASSWORD is stronger evidence than free text, and 3.0 still passes over words and
# repeated characters (`changeme` 2.75, `aaaaaaaaaa` 0) while catching `Hunter2!x` (3.17).
ENTROPY_MIN = 3.0
ENTROPY_MIN_LEN = 8
_NAMES = (r"password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
          r"credential|auth[_-]?key|client[_-]?secret|signing[_-]?key")
_SECRET_NAME = re.compile(rf"(?i)({_NAMES})")
# Names that hold a reference to a secret, not the secret.
_REF_NAME = re.compile(r"(?i)(_arn|_name|_id|_path|_url|_uri|_file|_region|_ttl|_timeout|_length|"
                       r"_header|_endpoint|_version|_type|_enabled|_key_id)$")
_ASSIGN = re.compile(rf"(?i)\b([\w.-]*(?:{_NAMES})[\w.-]*)\b[\"']?\s*(?:=|:|=>)\s*"
                     r"[\"']?([^\s\"'`;,)}\]]{8,})")
# gitleaks' global allowlist: AWS documentation examples and obvious placeholders.
_STOPWORDS = ("EXAMPLE", "example", "XXXXXXXX", "xxxxxxxx", "<", "${", "{{", "$(", "%(",
              "arn:aws", "resolve:", "/aws/reference/", "!Ref", "!Sub", "Fn::", "******")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def _placeholder(v: str) -> bool:
    return any(w in v for w in _STOPWORDS)


def mask(value: str, kind: str) -> str:
    """At most 12 characters. A key id keeps its first and last four (an identifier, and
    the last four is how IAM shows it); anything else its first four, and only if long."""
    if kind == "aws_access_key_id":
        return value[:4] + "****" + value[-4:]
    return value[:4] + "****" if len(value) >= 16 else "****"


def _hit(salt: str, detector: str, kind: str, value: str, location: str) -> dict:
    is_id = kind == "aws_access_key_id"
    return {"detector": detector, "kind": kind, "location": location[:512],
            "fingerprint": key_id_fp(value) if is_id else fingerprint(value, salt),
            "preview": mask(value, kind), "hint": value[-4:] if is_id else ""}


def scan_text(text: str, location: str, salt: str, code: bool = False) -> list[dict]:
    """Every rule over free text (user data, a template, a source file). Locations get
    `:<line>`. The value is dropped once fingerprinted. With `code=True` only the named
    rules run: in Lambda code on a live account (2026-10-28) the generic entropy rule fired 122
    times out of 122 on type expressions, build hashes and webpack names. The cost is a
    format-less secret hard-coded in source, which config scanning still catches."""
    out, seen = [], set()

    def add(detector, kind, value, start):
        if _placeholder(value):
            return
        line = text.count("\n", 0, start) + 1
        key = (detector, value, line)
        if key not in seen:
            seen.add(key)
            out.append(_hit(salt, detector, kind, value, f"{location}:{line}"))

    for rid, kind, rx in _RULES:
        for m in rx.finditer(text):
            add(rid, kind, m.group(1) if rx.groups else m.group(0), m.start())
    for m in (() if code else _ASSIGN.finditer(text)):
        name, value = m.group(1), m.group(2)
        if _generic(name, value) and not any(v == value for _, v, _ in seen):
            add("generic-secret-entropy", "password", value, m.start())
    return out


def _generic(name: str, value: str) -> bool:
    """Plus: the value mixes a lower-case letter with a digit or a capital. A phrase like
    `moved-to-secrets-manager` (3.5 bits/char) is a note, not a secret; the cost is missing
    an all-lower-case passphrase, which the named-field rules above still don't catch."""
    return (bool(_SECRET_NAME.search(name)) and not _REF_NAME.search(name)
            and len(value) >= ENTROPY_MIN_LEN and entropy(value) >= ENTROPY_MIN
            and bool(re.search(r"[a-z]", value)) and bool(re.search(r"[A-Z0-9]", value))
            and not _placeholder(value))


def scan_pair(name: str, value, location: str, salt: str) -> list[dict]:
    """A named value (env var, parameter). Rules first; failing those, the entropy check
    when the name says secret. An AWS secret key needs only the shape when named so."""
    value = "" if value is None else str(value)
    if not value:
        return []
    hits = scan_text(value, location, salt)
    for h in hits:                                   # a one-line value: no `:1` suffix
        h["location"] = location if h["location"] == f"{location}:1" else h["location"]
    if hits:
        return hits
    if (re.fullmatch(r"[A-Za-z0-9/+]{40}", value) and re.search(r"(?i)secret", name)
            and not _placeholder(value)):
        return [_hit(salt, "aws-secret-access-key", "aws_secret_access_key", value, location)]
    if _generic(name, value):
        return [_hit(salt, "generic-secret-entropy", "password", value, location)]
    return []


# ------------------------------------------------------------------ helpers
def _payload() -> dict:
    return {"items": 0, "hits": [], "skipped": []}


def _res(kind: str, id_: str, name: str, api: str) -> dict:
    return {"type": kind, "id": id_, "name": name, "api": api}


def _add(out: dict, res: dict, hits: list[dict]) -> None:
    out["hits"] += [{**h, "resource": res} for h in hits]


def _skip(out: dict, res: dict, why: str) -> None:
    out["skipped"].append({"resource": res, "why": why})


def _why(e: Exception) -> str:
    """An error code or type name only: an exception message is never kept, in case it
    quotes what was being read. A guard refusal is a bug and is re-raised, never a gap."""
    if isinstance(e, WriteRefused):
        raise e
    if isinstance(e, ClientError):
        return e.response.get("Error", {}).get("Code", "ClientError")
    return type(e).__name__


class NoSalt(RuntimeError):
    """Raised before any read: the collector becomes a gap (`NoSalt`), nothing is kept."""


def _salt(env) -> str:
    """The platform's salt, which the runner cannot hand a collector directly: collectors
    take (env, region). The runner sets `env.secret_salt` at tier >= 1; a missing salt is a bug, not a
    default, because an unsalted fingerprint of a short password is reversible."""
    salt = getattr(env, "secret_salt", None)
    if not salt:
        raise NoSalt("tier-1 collectors need env.secret_salt before collection")
    return salt


def _sorted(out: dict) -> dict:
    out["hits"].sort(key=lambda h: (h["resource"]["id"], h["location"], h["detector"], h["fingerprint"]))
    out["skipped"].sort(key=lambda s: (s["resource"]["id"], s["why"]))
    return out


# ------------------------------------------------------------------ EC2 user data
@collector("sec.ec2_user_data", ["ec2:DescribeInstances", "ec2:DescribeInstanceAttribute"])
def ec2_user_data(env, region):
    ec2, salt, out = env.client("ec2", region), _salt(env), _payload()
    for r in _pages(ec2, "describe_instances", "Reservations"):
        for i in r.get("Instances", []):
            if (i.get("State") or {}).get("Name") == "terminated":
                continue
            iid = i["InstanceId"]
            res = _res("ec2_instance", iid, iid, "ec2:DescribeInstanceAttribute")
            out["items"] += 1
            try:
                raw = (ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")
                       .get("UserData") or {}).get("Value")
                if not raw:
                    continue
                data = base64.b64decode(raw)
                if data[:2] == b"\x1f\x8b":                 # cloud-init accepts gzip
                    data = gzip.decompress(data)
                _add(out, res, scan_text(data.decode("utf-8", "replace"), f"ec2:{iid}/userData", salt))
            except Exception as e:                          # noqa: BLE001 (one item, one gap)
                _skip(out, res, _why(e))
    return _sorted(out)


# ------------------------------------------------------------------ Lambda
CODE_MAX_BYTES = 50 * 1024 * 1024           # zipped; Lambda's own direct-upload limit
MEMBER_MAX_BYTES = 2 * 1024 * 1024          # one file inside the zip, uncompressed
UNZIPPED_MAX_BYTES = 100 * 1024 * 1024      # all files read from one zip
# Vendored dependencies: large, and full of documented example keys.
SKIP_DIRS = ("node_modules", "site-packages", "__pycache__", "botocore", "boto3", ".git")


class TooLarge(Exception):
    pass


def _fetch(url: str, cap: int) -> bytes:
    """The presigned code URL, into memory, at most `cap` bytes. The URL carries a
    signature; it is never logged, stored or put in an error."""
    if not url.startswith("https://"):
        raise ValueError("code location is not https")
    buf = io.BytesIO()
    with urllib.request.urlopen(url, timeout=60, context=tls.context()) as resp:  # noqa: S310
        while chunk := resp.read(1024 * 1024):
            buf.write(chunk)
            if buf.tell() > cap:
                raise TooLarge()
    return buf.getvalue()


MINIFIED_LINE = 2000          # a line this long is generated/minified, not hand-written


def _bundled(z: zipfile.ZipFile) -> set[str]:
    """Top-level packages installed into the zip (Python Lambdas ship them at the root):
    the names in each *.dist-info / *.egg-info top_level.txt, else the first path parts
    of its RECORD. Their code is a library's, not the owner's; on a live account (2026-10-28)
    1,328 of 1,329 hits were inside them or in minified chunks."""
    names: set[str] = set()
    for n in z.namelist():
        meta, _, leaf = n.rpartition("/")
        if not meta.endswith((".dist-info", ".egg-info")) or "/" in meta:
            continue
        if leaf == "top_level.txt":
            names |= {x.strip() for x in z.read(n).decode("utf-8", "replace").splitlines() if x.strip()}
        elif leaf == "RECORD":
            names |= {line.split("/", 1)[0].split(",", 1)[0]
                      for line in z.read(n).decode("utf-8", "replace").splitlines() if line}
    return {x for x in names if x and not x.endswith((".dist-info", ".egg-info"))}


def scan_zip(data: bytes, location: str, salt: str) -> tuple[list[dict], bool]:
    """(hits, complete). The owner's text files only: binaries, bundled packages (see
    `_bundled`), vendored directories, minified files and files over MEMBER_MAX_BYTES
    are passed over; past UNZIPPED_MAX_BYTES the scan stops incomplete."""
    hits, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        bundled = _bundled(z)
        for info in sorted(z.infolist(), key=lambda i: i.filename):
            parts = info.filename.split("/")
            top = parts[0].removesuffix(".py")
            if info.is_dir() or top in bundled or any(
                    p in SKIP_DIRS or p.endswith((".dist-info", ".egg-info")) for p in parts[:-1]):
                continue
            if info.file_size > MEMBER_MAX_BYTES:
                continue
            total += info.file_size
            if total > UNZIPPED_MAX_BYTES:
                return hits, False
            body = z.read(info)
            if b"\x00" in body[:8192] or any(len(ln) > MINIFIED_LINE for ln in body.splitlines()):
                continue
            hits += scan_text(body.decode("utf-8", "replace"), f"{location}:{info.filename}", salt,
                              code=True)
    return hits, True


@collector("sec.lambda", ["lambda:ListFunctions", "lambda:GetFunction"])
def lambda_secrets(env, region):
    lam, salt, out = env.client("lambda", region), _salt(env), _payload()
    for f in _pages(lam, "list_functions", "Functions"):
        name, arn = f["FunctionName"], f["FunctionArn"]
        res = _res("lambda_function", arn, name, "lambda:GetFunction")
        out["items"] += 1
        try:
            g = lam.get_function(FunctionName=arn)
        except Exception as e:                              # noqa: BLE001
            _skip(out, res, _why(e))
            continue
        cfg = g.get("Configuration") or {}
        for k, v in sorted(((cfg.get("Environment") or {}).get("Variables") or {}).items()):
            _add(out, res, scan_pair(k, v, f"lambda:{name}/env:{k}", salt))
        code = g.get("Code") or {}
        if cfg.get("PackageType") == "Image" or code.get("RepositoryType") == "ECR":
            _skip(out, res, "container image: code not scanned (tier 2 covers images)")
            continue
        if (cfg.get("CodeSize") or 0) > CODE_MAX_BYTES:
            _skip(out, res, f"code larger than {CODE_MAX_BYTES // 2**20} MiB: not scanned")
            continue
        try:
            data = _fetch(code.get("Location") or "", CODE_MAX_BYTES)
            found, complete = scan_zip(data, f"lambda:{name}/code", salt)
            _add(out, res, found)
            if not complete:
                _skip(out, res, f"code over {UNZIPPED_MAX_BYTES // 2**20} MiB unzipped: scanned in part")
            if env.log:
                env.log.emit("code.fetch", function=name, region=region, bytes=len(data), outcome="ok")
        except TooLarge:
            _skip(out, res, f"code larger than {CODE_MAX_BYTES // 2**20} MiB: not scanned")
        except Exception as e:                              # noqa: BLE001
            _skip(out, res, f"code not read: {_why(e)}")
            if env.log:
                env.log.emit("code.fetch", function=name, region=region, outcome=_why(e))
    return _sorted(out)


# ------------------------------------------------------------------ ECS
@collector("sec.ecs_task_definitions", ["ecs:ListTaskDefinitionFamilies", "ecs:DescribeTaskDefinition"])
def ecs_task_definitions(env, region):
    """The latest ACTIVE revision of each family: what new tasks run. Older revisions
    may hold a since-moved value; that is a known limit."""
    ecs, salt, out = env.client("ecs", region), _salt(env), _payload()
    for fam in _pages(ecs, "list_task_definition_families", "families", status="ACTIVE"):
        try:
            td = ecs.describe_task_definition(taskDefinition=fam)["taskDefinition"]
        except Exception as e:                              # noqa: BLE001
            _skip(out, _res("ecs_task_definition", fam, fam, "ecs:DescribeTaskDefinition"), _why(e))
            continue
        arn, rev = td.get("taskDefinitionArn", fam), td.get("revision", 0)
        res = _res("ecs_task_definition", arn, f"{fam}:{rev}", "ecs:DescribeTaskDefinition")
        out["items"] += 1
        for c in td.get("containerDefinitions", []):
            for e in c.get("environment", []):
                _add(out, res, scan_pair(e.get("name", ""), e.get("value"),
                                         f"ecs:{fam}:{rev}/container:{c.get('name', '')}/env:{e.get('name', '')}", salt))
    return _sorted(out)


# ------------------------------------------------------------------ CloudFormation
@collector("sec.cloudformation", ["cloudformation:DescribeStacks", "cloudformation:GetTemplate"])
def cloudformation_templates(env, region):
    cf, salt, out = env.client("cloudformation", region), _salt(env), _payload()
    for s in _pages(cf, "describe_stacks", "Stacks"):
        name, sid = s["StackName"], s.get("StackId", s["StackName"])
        res = _res("cloudformation_stack", sid, name, "cloudformation:GetTemplate")
        out["items"] += 1
        for p in s.get("Parameters", []):                   # NoEcho ones read back as ****
            _add(out, res, scan_pair(p.get("ParameterKey", ""), p.get("ParameterValue"),
                                     f"cloudformation:{name}/parameter:{p.get('ParameterKey', '')}", salt))
        try:
            body = cf.get_template(StackName=sid, TemplateStage="Original").get("TemplateBody") or ""
        except Exception as e:                              # noqa: BLE001
            _skip(out, res, _why(e))
            continue
        if not isinstance(body, str):                       # boto3 parses a JSON template
            import json
            body = json.dumps(body, indent=1, sort_keys=True)
        _add(out, res, scan_text(body, f"cloudformation:{name}/template", salt))
    return _sorted(out)


# ------------------------------------------------------------------ CodeBuild
@collector("sec.codebuild", ["codebuild:ListProjects", "codebuild:BatchGetProjects"])
def codebuild_projects(env, region):
    cb, salt, out = env.client("codebuild", region), _salt(env), _payload()
    names = _pages(cb, "list_projects", "projects")
    for i in range(0, len(names), 100):
        for p in cb.batch_get_projects(names=names[i:i + 100]).get("projects", []):
            res = _res("codebuild_project", p.get("arn", p["name"]), p["name"], "codebuild:BatchGetProjects")
            out["items"] += 1
            for v in (p.get("environment") or {}).get("environmentVariables", []):
                if v.get("type", "PLAINTEXT") != "PLAINTEXT":   # PARAMETER_STORE / SECRETS_MANAGER: refs
                    continue
                _add(out, res, scan_pair(v.get("name", ""), v.get("value"),
                                         f"codebuild:{p['name']}/env:{v.get('name', '')}", salt))
    return _sorted(out)


# ------------------------------------------------------------------ SSM plain parameters
HISTORY_MAX = 50


@collector("sec.ssm_plain", ["ssm:DescribeParameters", "ssm:GetParameterHistory"])
def ssm_plain_parameters(env, region):
    """String and StringList parameters only, every version (up to HISTORY_MAX): a value
    overwritten in place is still in the history. SecureString is never asked for, and the
    guard refuses WithDecryption, so no SecureString value can be read here."""
    ssm, salt, out = env.client("ssm", region), _salt(env), _payload()
    params = _pages(ssm, "describe_parameters", "Parameters",
                    ParameterFilters=[{"Key": "Type", "Values": ["String", "StringList"]}])
    for p in sorted(params, key=lambda p: p["Name"]):
        if p.get("Type") not in ("String", "StringList"):
            continue
        name = p["Name"]
        res = _res("ssm_parameter", p.get("ARN") or name, name, "ssm:GetParameterHistory")
        out["items"] += 1
        try:
            hist = ssm.get_parameter_history(Name=name, MaxResults=HISTORY_MAX).get("Parameters", [])
        except Exception as e:                              # noqa: BLE001
            _skip(out, res, _why(e))
            continue
        for h in hist:
            if h.get("Type") not in ("String", "StringList"):  # was a SecureString then: skip
                continue
            _add(out, res, scan_pair(name.rsplit("/", 1)[-1], h.get("Value"),
                                     f"ssm:{name}/v{h.get('Version', 0)}", salt))
    # One finding per value, not per version that repeats it.
    seen, uniq = set(), []
    for h in out["hits"]:
        k = (h["resource"]["id"], h["fingerprint"])
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    out["hits"] = uniq
    return _sorted(out)


SOURCES = ("sec.ec2_user_data", "sec.lambda", "sec.ecs_task_definitions", "sec.cloudformation",
           "sec.codebuild", "sec.ssm_plain")

# Doctor probes: one cheap list call per collector. They prove the listing, not the
# content read (GetFunction etc. need a resource name); a denied content read shows up as
# a per-resource gap in the scan, the same limit the other multi-action collectors have.
PROBES = {
    "sec.ec2_user_data": ("ec2", "describe_instances", {"MaxResults": 5}),
    "sec.lambda": ("lambda", "list_functions", {"MaxItems": 1}),
    "sec.ecs_task_definitions": ("ecs", "list_task_definition_families", {"maxResults": 1}),
    "sec.cloudformation": ("cloudformation", "describe_stacks", {}),
    "sec.codebuild": ("codebuild", "list_projects", {}),
    "sec.ssm_plain": ("ssm", "describe_parameters", {"MaxResults": 1}),
}
