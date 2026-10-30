"""Every account AWS can list, read-only: one moto account with a database, a cache user,
key pairs, secrets, parameters and a Cognito pool, through the scan and the view."""
import json

import boto3
from moto import mock_aws

from cloudtools.cli import main

R = "eu-west-1"
PASSWORD = "Sup3r-S3cret-DB-Pass"        # canary: never stored
END_USER = "jane.customer@example.com"  # canary: a customer's end user, never listed


def build():
    boto3.client("rds", R).create_db_instance(
        DBInstanceIdentifier="orders", DBInstanceClass="db.t3.micro", Engine="postgres",
        MasterUsername="orders_admin", MasterUserPassword=PASSWORD, AllocatedStorage=20)
    boto3.client("secretsmanager", R).create_secret(Name="prod/stripe", SecretString=PASSWORD)
    boto3.client("ssm", R).put_parameter(Name="/app/db_password", Value=PASSWORD, Type="SecureString")
    boto3.client("ec2", R).create_key_pair(KeyName="deploy-2021")
    boto3.client("elasticache", R).create_user(UserId="app-user", UserName="app", Engine="redis",
                                               AccessString="on ~* +@all", Passwords=[PASSWORD * 2])
    cog = boto3.client("cognito-idp", R)
    pool = cog.create_user_pool(PoolName="customers")["UserPool"]["Id"]
    cog.admin_create_user(UserPoolId=pool, Username=END_USER)


def test_accounts_view_lists_users_and_names_never_values(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", R)
    with mock_aws():
        build()
        out = tmp_path / "out"
        main(["security", "scan", "--region", R, "--regions", R, "--out", str(out), "-q"])
    capsys.readouterr()
    main(["call", "cred.accounts", "--out", str(out)])
    v = json.loads(capsys.readouterr().out)
    who = {(r["source"], r["who"]) for r in v["rows"]}
    assert ("rds", "orders_admin") in who
    assert ("secretsmanager", "prod/stripe") in who and ("ssm", "/app/db_password") in who
    assert ("ec2", "deploy-2021") in who and ("elasticache", "app") in who
    cog = [r for r in v["rows"] if r["source"] == "cognito"]
    assert cog and cog[0]["who"] == "1 end users"
    rid = json.loads((out / "runs/latest-security.json").read_text())["run_id"]
    for f in (out / "runs" / rid).iterdir():
        text = f.read_text()
        assert PASSWORD not in text, f"a secret value reached {f.name}"
        assert END_USER not in text, f"a Cognito end user reached {f.name}"
    rep = json.loads((out / f"runs/{rid}/report.json").read_text())
    stats = next(c["stats"] for c in rep["checks"] if c["id"] == "cred.accounts")
    assert stats["database_master_users"] == 1 and stats["cognito_end_users"] == 1
    assert any(f["check_id"] == "cred.db-static-master-password" for f in rep["findings"])
