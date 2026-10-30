"""AWS side of the credential inventory: every IAM user's access keys, read-only.

Ported from credscan `collectors/aws_iam.py`. The credential report (already a security
collector) has key ages and last use by slot but no key ids; ListAccessKeys gives the
ids, which are what a key found in a repo is matched against. Only the id's
fingerprint and its last four characters are stored.
"""
from __future__ import annotations

from ..core.collect import GLOBAL, collector
from ..security.collectors import _pages, _tags
from .repo_secrets import key_id_fp


def _iso(d) -> str | None:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


@collector("iam.access_keys", ["iam:ListUsers", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"],
           scope=GLOBAL)
def access_keys(env, region):
    iam = env.client("iam")
    out = []
    for page in iam.get_paginator("list_users").paginate():
        for u in page["Users"]:
            for k in iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]:
                kid = k["AccessKeyId"]
                used = iam.get_access_key_last_used(AccessKeyId=kid).get("AccessKeyLastUsed", {})
                out.append({"user": u["UserName"], "user_arn": u["Arn"],
                            "key_fp": key_id_fp(kid), "hint": kid[-4:],
                            "status": k["Status"], "created": _iso(k.get("CreateDate")),
                            "last_used": _iso(used.get("LastUsedDate")),
                            "last_service": used.get("ServiceName")})
    return sorted(out, key=lambda r: (r["user_arn"], r["key_fp"]))


# ------------------------------------------------- users outside IAM (read-only APIs only)
# What AWS can list without logging in anywhere. OS accounts on hosts and users created
# inside a database need a command on the host or a database login: not here.

def _iso_any(d) -> str | None:
    return d if isinstance(d, str) or d is None else _iso(d)


@collector("identitycenter.users", ["sso:ListInstances", "identitystore:ListUsers"])
def identity_center_users(env, region):
    """Workforce users. Identity Center lives in one region, so the others return none.
    Names only: emails and phone numbers are not kept."""
    out = []
    for inst in _pages(env.client("sso-admin", region), "list_instances", "Instances"):
        store = inst.get("IdentityStoreId")
        users = _pages(env.client("identitystore", region), "list_users", "Users",
                       IdentityStoreId=store)
        out.append({"instance_arn": inst.get("InstanceArn"), "store_id": store,
                    "users": sorted(({"id": u["UserId"], "user_name": u.get("UserName", ""),
                                      "display_name": u.get("DisplayName", "")} for u in users),
                                    key=lambda u: u["user_name"])})
    return out


@collector("rds.db_users", ["rds:DescribeDBInstances", "rds:DescribeDBClusters"])
def rds_db_users(env, region):
    """Master users of RDS instances and of clusters (Aurora, DocumentDB, Neptune). The
    password is never readable; `managed` says whether Secrets Manager rotates it."""
    r = env.client("rds", region)
    out = []
    for c in _pages(r, "describe_db_clusters", "DBClusters"):
        out.append({"kind": "cluster", "id": c["DBClusterIdentifier"], "arn": c.get("DBClusterArn", ""),
                    "engine": c.get("Engine"), "master_user": c.get("MasterUsername", ""),
                    "iam_auth": c.get("IAMDatabaseAuthenticationEnabled", False),
                    "managed": bool(c.get("MasterUserSecret")), "tags": _tags(c.get("TagList"))})
    for d in _pages(r, "describe_db_instances", "DBInstances"):
        if d.get("DBClusterIdentifier"):
            continue                                   # its users belong to the cluster
        out.append({"kind": "instance", "id": d["DBInstanceIdentifier"], "arn": d.get("DBInstanceArn", ""),
                    "engine": d.get("Engine"), "master_user": d.get("MasterUsername", ""),
                    "iam_auth": d.get("IAMDatabaseAuthenticationEnabled", False),
                    "managed": bool(d.get("MasterUserSecret")), "tags": _tags(d.get("TagList"))})
    return sorted(out, key=lambda x: x["arn"])


@collector("redshift.clusters", ["redshift:DescribeClusters"])
def redshift_clusters(env, region):
    return sorted(({"id": c["ClusterIdentifier"], "master_user": c.get("MasterUsername", ""),
                    "managed": bool(c.get("MasterPasswordSecretArn"))}
                   for c in _pages(env.client("redshift", region), "describe_clusters", "Clusters")),
                  key=lambda c: c["id"])


@collector("elasticache.users", ["elasticache:DescribeUsers"])
def elasticache_users(env, region):
    return sorted(({"id": u["UserId"], "user_name": u.get("UserName", ""), "arn": u.get("ARN", ""),
                    "engine": u.get("Engine"), "status": u.get("Status"),
                    "access": u.get("AccessString", ""),
                    "auth": (u.get("Authentication") or {}).get("Type", "")}
                   for u in _pages(env.client("elasticache", region), "describe_users", "Users")),
                  key=lambda u: u["id"])


@collector("mq.users", ["mq:ListBrokers", "mq:ListUsers"])
def mq_users(env, region):
    mq = env.client("mq", region)
    out = []
    for b in _pages(mq, "list_brokers", "BrokerSummaries"):
        users = mq.list_users(BrokerId=b["BrokerId"]).get("Users", [])
        out.append({"broker": b.get("BrokerName", b["BrokerId"]), "arn": b.get("BrokerArn", ""),
                    "users": sorted(u["Username"] for u in users)})
    return sorted(out, key=lambda b: b["arn"])


@collector("transfer.users", ["transfer:ListServers", "transfer:ListUsers"])
def transfer_users(env, region):
    tr = env.client("transfer", region)
    out = []
    for s in _pages(tr, "list_servers", "Servers"):
        users = _pages(tr, "list_users", "Users", ServerId=s["ServerId"])
        out.append({"server": s["ServerId"], "arn": s.get("Arn", ""),
                    "identity_provider": s.get("IdentityProviderType", ""),
                    "users": sorted(({"user_name": u.get("UserName", ""), "role": u.get("Role", ""),
                                      "ssh_keys": u.get("SshPublicKeyCount", 0)} for u in users),
                                    key=lambda u: u["user_name"])})
    return sorted(out, key=lambda s: s["arn"])


@collector("cognito.pools", ["cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool"])
def cognito_pools(env, region):
    """Counts only. A user pool holds a customer's end users; listing them is refused by
    the read-only guard (`DENIED_BY_SERVICE`)."""
    c = env.client("cognito-idp", region)
    out = []
    for p in _pages(c, "list_user_pools", "UserPools", MaxResults=60):
        d = c.describe_user_pool(UserPoolId=p["Id"])["UserPool"]
        out.append({"id": p["Id"], "name": p.get("Name", ""), "arn": d.get("Arn", ""),
                    "estimated_users": d.get("EstimatedNumberOfUsers", 0),
                    "mfa": d.get("MfaConfiguration", "OFF")})
    return sorted(out, key=lambda p: p["id"])


@collector("ec2.key_pairs", ["ec2:DescribeKeyPairs"])
def key_pairs(env, region):
    return sorted(({"name": k.get("KeyName", ""), "id": k.get("KeyPairId", ""),
                    "fingerprint": k.get("KeyFingerprint", ""), "type": k.get("KeyType", ""),
                    "created": _iso_any(k.get("CreateTime"))}
                   for k in env.client("ec2", region).describe_key_pairs().get("KeyPairs", [])),
                  key=lambda k: k["name"])


@collector("secretsmanager.secrets", ["secretsmanager:ListSecrets"])
def secrets(env, region):
    """Names and dates only; GetSecretValue is refused by the read-only guard."""
    return sorted(({"name": s.get("Name", ""), "arn": s["ARN"],
                    "rotation": s.get("RotationEnabled", False),
                    "last_rotated": _iso_any(s.get("LastRotatedDate")),
                    "last_changed": _iso_any(s.get("LastChangedDate")),
                    "last_accessed": _iso_any(s.get("LastAccessedDate")),
                    "created": _iso_any(s.get("CreatedDate")),
                    "owning_service": s.get("OwningService", ""), "tags": _tags(s.get("Tags"))}
                   for s in _pages(env.client("secretsmanager", region), "list_secrets", "SecretList")),
                  key=lambda s: s["arn"])


@collector("ssm.parameters", ["ssm:DescribeParameters"])
def parameters(env, region):
    """Names, types and who last changed them; GetParameter* is refused by the guard."""
    return sorted(({"name": p.get("Name", ""), "type": p.get("Type", ""),
                    "last_modified": _iso_any(p.get("LastModifiedDate")),
                    "last_modified_by": p.get("LastModifiedUser", ""), "tier": p.get("Tier", "")}
                   for p in _pages(env.client("ssm", region), "describe_parameters", "Parameters")),
                  key=lambda p: p["name"])
