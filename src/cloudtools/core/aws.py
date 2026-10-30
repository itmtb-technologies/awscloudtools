"""AWS session and client factory with the read-only guarantee in code.

Ported from aws-cost-sentinel `finops/aws.py` (AwsEnv, is_access_denied) and extended:
  * every client refuses, before the request leaves the process, any operation outside
    the read-only allowlist (requirements §Non-functional "Safety");
  * data-reading operations are refused even though they are named Get* (R4.2);
  * a distinctive user-agent `cloudtools/<ver> run/<run_id>` on every call (R10.2);
  * every call is recorded as an `api.call` event (service, action, region, outcome,
    latency, retries); never parameters or bodies (R10.1).
"""
from __future__ import annotations

import functools
import time
from dataclasses import dataclass

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

from .. import __version__

# "Generate*" and "Head*" are deliberately not prefixes: most Generate* calls mint keys
# or data, and HeadObject touches objects. The few needed are named in EXTRA_ALLOWED.
READ_PREFIXES = ("Describe", "List", "Get", "Lookup", "BatchGet", "Search")
# Get*/Generate* operations that read data or secrets, or create anything: never.
DENIED_OPERATIONS = frozenset({
    "GetObject", "GetObjectAcl", "GetObjectTorrent", "GetSecretValue", "BatchGetSecretValue",
    "GetParameter", "GetParameters", "GetParametersByPath", "GetFunction",
    "GetFunctionConcurrency", "Decrypt", "GenerateDataKey", "GenerateDataKeyPair",
    "GenerateDataKeyWithoutPlaintext", "GenerateDataKeyPairWithoutPlaintext",
    "GenerateRandom", "GenerateMac", "GetPasswordData", "GetConsoleOutput",
    "GetConsoleScreenshot", "GetAuthorizationToken", "GetSessionToken",
    "GetFederationToken", "GenerateServiceLastAccessedDetails",
    "GenerateOrganizationsAccessReport", "GetLaunchTemplateData",
    # Named like reads, but they mint credentials or create an identity...
    "GetId", "GetCredentialsForIdentity", "GetOpenIdToken", "GetOpenIdTokenForDeveloperIdentity",
    "GetClusterCredentials", "GetClusterCredentialsWithIAM", "GetRoleCredentials",
    "GetInstanceAccessDetails",
    # ... or return data rather than configuration (review 2026-10-30).
    "GetItem", "BatchGetItem", "GetRecords", "GetLogEvents", "GetQueryResults", "GetJobOutput",
    "GetMedia", "GetBlob", "GetFile", "BatchGetImage", "GetDownloadUrlForLayer",
})
# Operations outside READ_PREFIXES that are read-only and needed.
EXTRA_ALLOWED = frozenset({
    "GenerateCredentialReport",   # IAM: asks AWS to build the report; changes nothing
    "HeadBucket",
})
# The second gate (CT-6, review 2026-10-30): a read-looking name is not enough. The
# operation must be one some collector declares (`collect.COLLECTORS`, by IAM action name),
# or one of these, which the scanner itself calls or whose IAM name differs from the API's.
# Checked against every operation the collectors and doctor can name (a test).
EXTRA_OPERATIONS = frozenset({
    "GetCallerIdentity", "DescribeRegions",          # AwsEnv itself: who, which regions
    "GetMacieSession", "DescribeHub",                # doctor: is Macie / Security Hub on
    # IAM apigateway:GET. GetResources, GetRoutes and GetIntegrations run only when an
    # account has REST or HTTP APIs, so 0.1.5's recording (whose sandbox had none) missed
    # them and the first production scan died (2026-10-30). tests/test_core.py now reads
    # every operation the code can call from the source, not only the ones that ran.
    "GetRestApis", "GetResources", "GetApis", "GetRoutes", "GetIntegrations",
    "ListBuckets", "HeadBucket",                     # IAM s3:ListAllMyBuckets, s3:ListBucket
    "GetPublicAccessBlock",                          # IAM s3:Get{Bucket,Account}PublicAccessBlock
})


def declared_operations() -> frozenset:
    from .collect import COLLECTORS                  # late: collect imports this module
    return frozenset(a.split(":", 1)[1] for c in COLLECTORS.values() for a in c.actions) \
        | EXTRA_OPERATIONS


# STS AssumeRole is used only by the platform object (hosted / multi-account), never by a
# collector, through `assume_role_env` below, which builds its own client.

_BOTO_RETRIES = {"max_attempts": 6, "mode": "adaptive"}


class AwsAccessError(RuntimeError):
    """Credentials missing or a call denied, with a hint."""


class WriteRefused(RuntimeError):
    """A non-read-only AWS operation was attempted. This is a bug, never a fallback."""


class UndeclaredRead(WriteRefused):
    """A read no check declares. Still refused, and still a bug, but it costs only the
    collector that made it (a gap), not the whole scan: 0.1.5's first production run died on
    one (apigateway:GetResources, 2026-10-30). A true write stays WriteRefused and stops all."""

    def __init__(self, operation: str):
        super().__init__(f"{operation} is read-only but no check declares it, so cloudtools "
                         "refuses it")
        self.operation = operation


# Reads that are refused for one service only, where the same name elsewhere is fine
# (IAM ListUsers lists your staff; Cognito ListUsers lists your customers' end users,
# with their emails and phone numbers). Those are counted, never listed.
DENIED_BY_SERVICE = {
    "cognito-idp": frozenset({"ListUsers", "ListUsersInGroup", "AdminGetUser",
                              "AdminListGroupsForUser", "AdminListDevices",
                              "AdminListUserAuthEvents"}),
}


# Tier 1 (opt-in, `--tier 1`): reads that return configuration content, where secrets are
# looked for. Refused unless the AwsEnv was built for tier >= 1; each value found is
# reduced to a salted fingerprint inside the collector (creds/config_secrets.py). Keyed by
# service, because the same name elsewhere reads data (AppSync/CloudFront GetFunction).
# Never in here: GetSecretValue, GetParameter(s)(ByPath), Decrypt, GetObject (tested).
TIER1_OPERATIONS = {
    "lambda": frozenset({"GetFunction"}),                 # env + a presigned code URL
    "ec2": frozenset({"DescribeInstanceAttribute"}),      # userData
    "ecs": frozenset({"DescribeTaskDefinition"}),         # container environment
    "cloudformation": frozenset({"GetTemplate"}),
    "codebuild": frozenset({"BatchGetProjects"}),         # PLAINTEXT environment variables
    "ssm": frozenset({"GetParameterHistory"}),            # String values; never decrypted
}
TIER1_ACTIONS = tuple(sorted(f"{s}:{op}" for s, ops in TIER1_OPERATIONS.items() for op in ops))


def is_read_only(operation: str, service: str = "", tier: int = 0,
                 params: dict | None = None) -> bool:
    if (params or {}).get("WithDecryption"):              # at every tier
        return False
    if operation in TIER1_OPERATIONS.get(service, ()):
        return tier >= 1
    if operation in DENIED_OPERATIONS or operation in DENIED_BY_SERVICE.get(service, ()):
        return False
    return operation in EXTRA_ALLOWED or operation.startswith(READ_PREFIXES)


def is_access_denied(err: ClientError) -> bool:
    code = err.response.get("Error", {}).get("Code", "")
    return code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                    "AuthFailure", "AuthorizationError", "AccessDeniedFault"}


def is_throttle(err: ClientError) -> bool:
    code = err.response.get("Error", {}).get("Code", "")
    return "Throttl" in code or code in {"RequestLimitExceeded", "TooManyRequestsException"}


@dataclass
class AwsScope:
    account_id: str
    caller_arn: str
    region: str
    profile: str | None = None


class AwsEnv:
    """Wraps a boto3 Session; hands out cached, guarded, retry-configured clients."""

    def __init__(self, profile: str | None = None, region: str | None = None,
                 run_id: str = "adhoc", log=None, session: boto3.Session | None = None,
                 max_tier: int = 0):
        try:
            self._session = session or boto3.Session(profile_name=profile, region_name=region)
        except ProfileNotFound as e:
            raise AwsAccessError(str(e)) from e
        self.profile = profile
        self.region = region or self._session.region_name or "us-east-1"
        self.run_id = run_id
        self.log = log
        self.max_tier = max_tier        # the profile's tier; gates TIER1_OPERATIONS
        self.secret_salt: str | None = None   # tier 1: set by the runner from the platform
        self._config = Config(retries=_BOTO_RETRIES,
                              user_agent_extra=f"cloudtools/{__version__} run/{run_id}")

    @functools.lru_cache(maxsize=None)
    def client(self, service: str, region: str | None = None):
        c = self._session.client(service, region_name=region or self.region,
                                 config=self._config)
        ev = c.meta.events
        ev.register("before-parameter-build.*.*", self._guard_params)
        ev.register("before-call.*.*", self._guard)
        ev.register("after-call.*.*", self._record)
        ev.register("after-call-error.*.*", self._record_error)
        return c

    # -- hooks --------------------------------------------------------------------
    def _refuse_unless(self, model, params=None):
        tier = getattr(self, "max_tier", 0)          # an env never told a tier is tier 0
        if not is_read_only(model.name, model.service_model.endpoint_prefix, tier, params):
            raise WriteRefused(f"{model.service_model.service_name}:{model.name} is not "
                               f"read-only at tier {tier} and is refused by cloudtools")
        if model.name not in declared_operations():
            raise UndeclaredRead(f"{model.service_model.service_name}:{model.name}")

    def _guard_params(self, model, params, **_):
        """Before the request is built: the only hook that sees the caller's parameters
        (WithDecryption) unserialised."""
        self._refuse_unless(model, params)

    def _guard(self, model, context, **_):
        self._refuse_unless(model)
        context["cloudtools_t0"] = time.monotonic()

    def _emit(self, model, context, outcome: str, retries: int = 0):
        if self.log is None:
            return
        t0 = context.get("cloudtools_t0")
        self.log.emit("api.call", service=model.service_model.service_name,
                      action=model.name, region=context.get("client_region"),
                      outcome=outcome, retries=retries,
                      latency_ms=int((time.monotonic() - t0) * 1000) if t0 else None)

    def _record(self, http_response, parsed, model, context, **_):
        meta = (parsed or {}).get("ResponseMetadata", {})
        err = (parsed or {}).get("Error", {}).get("Code")
        outcome = "ok"
        if err:
            fake = ClientError({"Error": {"Code": err}}, model.name)
            outcome = ("denied" if is_access_denied(fake)
                       else "throttled" if is_throttle(fake) else "error")
        self._emit(model, context, outcome, meta.get("RetryAttempts", 0))

    def _record_error(self, model, context, exception=None, **_):
        self._emit(model, context, "error")

    # -- identity -----------------------------------------------------------------
    def resolve_scope(self) -> AwsScope:
        try:
            ident = self.client("sts").get_caller_identity()
        except NoCredentialsError as e:
            raise AwsAccessError("No AWS credentials found. Run `aws sso login`, set a "
                                 "profile with --profile, or set AWS_* env vars.") from e
        except ClientError as e:
            raise AwsAccessError(f"sts:GetCallerIdentity failed: {e}") from e
        return AwsScope(account_id=ident["Account"], caller_arn=ident["Arn"],
                        region=self.region, profile=self.profile)

    def enabled_regions(self) -> list[str]:
        try:
            resp = self.client("ec2").describe_regions(AllRegions=False)
            return sorted(r["RegionName"] for r in resp["Regions"])
        except ClientError:
            return [self.region]


def assume_role_session(role_arn: str, external_id: str, session_name: str,
                        base: boto3.Session | None = None,
                        duration: int = 3600) -> boto3.Session:
    """STS AssumeRole for the hosted variant and multi-account mode. The only place an
    sts:AssumeRole call is made; it creates no resource in the target account."""
    sts = (base or boto3.Session()).client("sts")
    creds = sts.assume_role(RoleArn=role_arn, ExternalId=external_id,
                            RoleSessionName=session_name[:64],
                            DurationSeconds=duration)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                         aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"])
