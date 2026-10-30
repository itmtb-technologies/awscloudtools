"""End-to-end over a moto 'lab': known misconfigurations must be found, hardened twins
must not be, and what cannot be seen must be a gap (never a pass)."""
import json

import boto3
import pytest
from moto import mock_aws

from cloudtools.core.aws import AwsEnv
from cloudtools.core.collect import Snapshot
from cloudtools.core.report import validate
from cloudtools.security import scan
from cloudtools.security.checks import CHECKS

R = "eu-west-1"
PROFILE = {**scan.QUICK}
PASSROLE = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]}
TRUST_EC2 = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
TRUST_EXT = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
     "Action": "sts:AssumeRole"}]}
TRUST_EXT_OK = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
     "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": "x"}}}]}


def build_lab():
    ec2 = boto3.client("ec2", region_name=R)
    iam = boto3.client("iam")
    vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
    sub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=sub)
    bad_sg = ec2.create_security_group(GroupName="lab-open", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=bad_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    good_sg = ec2.create_security_group(GroupName="lab-closed", Description="x", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=good_sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])
    iam.create_role(RoleName="lab-escalator", AssumeRolePolicyDocument=json.dumps(TRUST_EC2))
    iam.put_role_policy(RoleName="lab-escalator", PolicyName="p", PolicyDocument=json.dumps(PASSROLE))
    iam.create_instance_profile(InstanceProfileName="lab-ip")
    iam.add_role_to_instance_profile(InstanceProfileName="lab-ip", RoleName="lab-escalator")
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    bad = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                            NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": sub, "Groups": [bad_sg],
                                                "AssociatePublicIpAddress": True}],
                            IamInstanceProfile={"Name": "lab-ip"},
                            MetadataOptions={"HttpTokens": "optional"},
                            TagSpecifications=[{"ResourceType": "instance",
                                                "Tags": [{"Key": "Name", "Value": "lab-bad"}]}]
                            )["Instances"][0]["InstanceId"]
    good = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                             NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": sub, "Groups": [good_sg],
                                                 "AssociatePublicIpAddress": False}],
                             MetadataOptions={"HttpTokens": "required"},
                             TagSpecifications=[{"ResourceType": "instance",
                                                 "Tags": [{"Key": "Name", "Value": "lab-good"}]}]
                             )["Instances"][0]["InstanceId"]
    # Twin: same open SG and a public IP, but its subnet has no route to the IGW.
    priv = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.2.0/24")["Subnet"]["SubnetId"]
    priv_rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.associate_route_table(RouteTableId=priv_rt, SubnetId=priv)
    noroute = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1,
                                NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": priv,
                                                    "Groups": [bad_sg],
                                                    "AssociatePublicIpAddress": True}],
                                MetadataOptions={"HttpTokens": "required"})["Instances"][0]["InstanceId"]
    iam.create_user(UserName="lab-nomfa")
    iam.create_login_profile(UserName="lab-nomfa", Password="Lab-Passw0rd-not-real!")
    iam.create_role(RoleName="lab-ext-trust", AssumeRolePolicyDocument=json.dumps(TRUST_EXT))
    iam.create_role(RoleName="lab-ext-trust-ok", AssumeRolePolicyDocument=json.dumps(TRUST_EXT_OK))
    sqs = boto3.client("sqs", region_name=R)
    q = sqs.create_queue(QueueName="lab-open-q")["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=q, Attributes={"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": arn}]})})
    q2 = sqs.create_queue(QueueName="lab-scoped-q")["QueueUrl"]
    arn2 = sqs.get_queue_attributes(QueueUrl=q2, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=q2, Attributes={"Policy": json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": arn2,
         "Condition": {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:eu-west-1:123456789012:t"}}}]})})
    vol_bad = ec2.create_volume(AvailabilityZone=f"{R}a", Size=1, Encrypted=False)["VolumeId"]
    vol_ok = ec2.create_volume(AvailabilityZone=f"{R}a", Size=1, Encrypted=True)["VolumeId"]
    s3 = boto3.client("s3", region_name=R)
    s3.create_bucket(Bucket="lab-public-bucket", CreateBucketConfiguration={"LocationConstraint": R})
    s3.put_bucket_policy(Bucket="lab-public-bucket", Policy=json.dumps({"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::lab-public-bucket/*"}]}))
    s3.create_bucket(Bucket="lab-private-bucket", CreateBucketConfiguration={"LocationConstraint": R})
    return {"bad": bad, "good": good, "noroute": noroute, "bad_sg": bad_sg, "good_sg": good_sg, "queue": arn, "queue_ok": arn2,
            "vol_bad": vol_bad, "vol_ok": vol_ok}


@pytest.fixture
def lab_report():
    with mock_aws():
        ids = build_lab()
        env = AwsEnv(region=R, run_id="r-lab")
        checks = scan.select(max_tier=0, mvp_only=True)
        snap = scan.collect_snapshot(env, [R], checks)
        results, rows = scan.evaluate(snap, PROFILE)
        rep = scan.build_report(snap, results, rows, PROFILE, {
            "run_id": "r-lab", "tool_version": "t", "started_at": "", "ended_at": "",
            "platform": "standalone", "initiator": "test", "caller": snap.meta["caller"],
            "profile": "quick"})
        yield rep, ids, snap


def _hits(rep, check_id):
    return [f for f in rep["findings"] if f["check_id"] == check_id]


def test_report_matches_frozen_contract(lab_report):
    rep, _, _ = lab_report
    assert validate(rep) == []
    assert {r["status"] for r in rep["checks"]} <= {"ran", "partial", "error"}
    assert not [r for r in rep["checks"] if r["status"] == "error"], rep["checks"]


def test_open_ssh_found_on_bad_sg_only(lab_report):
    rep, ids, _ = lab_report
    hits = _hits(rep, "net.open-admin-ports")
    assert [f["resource"]["id"] for f in hits] == [ids["bad_sg"]]
    assert hits[0]["severity"]["base"] == "high"          # attached instance is reachable
    reach = [f for f in rep["facts"] if f["type"] == "reaches" and f["to"] == ids["bad"]]
    assert reach and reach[0]["from"] == "internet" and reach[0]["status"] == "confirmed"


def test_no_igw_route_means_not_reachable(lab_report):
    rep, ids, _ = lab_report
    assert not [f for f in rep["facts"] if f["type"] == "reaches" and f["to"] == ids["noroute"]]


def test_unreadable_route_tables_make_reach_possible_not_absent(lab_report):
    _, ids, snap = lab_report
    from cloudtools.core.collect import Miss
    blind = Snapshot.from_json(snap.to_json())
    blind.data.pop("ec2.route_tables")
    blind.misses.append(Miss("ec2.route_tables", R, "AccessDenied", True,
                             ("ec2:DescribeRouteTables",)))
    results, _ = scan.evaluate(blind, PROFILE)
    r = results["net.open-admin-ports"]
    facts = [f for f in r.facts if f.dst == ids["bad"]]
    assert facts and facts[0].status == "possible" and "route table not readable" in facts[0].conditions
    assert r.gaps


def test_imdsv1_with_role_is_high_and_exposes_credentials(lab_report):
    rep, ids, _ = lab_report
    hits = _hits(rep, "srv.imdsv1-enabled")
    assert [f["resource"]["id"] for f in hits] == [ids["bad"]]
    assert hits[0]["severity"]["base"] == "high"
    ex = [f for f in rep["facts"] if f["type"] == "exposes_credentials"]
    assert ex and ex[0]["status"] == "possible"           # heuristic, never confirmed
    assert any(f["type"] == "runs_as" and f["from"] == ids["bad"] for f in rep["facts"])


def test_escalation_trust_and_mfa(lab_report):
    rep, _, _ = lab_report
    pe = _hits(rep, "iam.privilege-escalation")
    assert [f["resource"]["name"] for f in pe] == ["lab-escalator"]
    tr = _hits(rep, "iam.trust-without-external-id")
    assert [f["resource"]["name"] for f in tr] == ["lab-ext-trust"]   # not the -ok twin
    nm = _hits(rep, "iam.user-no-mfa")
    assert [f["resource"]["name"] for f in nm] == ["lab-nomfa"]


def test_public_queue_and_bucket_but_not_twins(lab_report):
    rep, ids, _ = lab_report
    assert [f["resource"]["id"] for f in _hits(rep, "data.sqs-policy-public")] == [ids["queue"]]
    s3 = [f["resource"]["name"] for f in _hits(rep, "data.s3-public-bucket")]
    assert "lab-private-bucket" not in s3
    assert "lab-public-bucket" in s3 or any(g["check_id"] == "data.s3-public-bucket"
                                            for g in rep["gaps"])


def test_unencrypted_volume_flagged_encrypted_twin_not(lab_report):
    rep, ids, _ = lab_report
    vols = {f["resource"]["id"] for f in _hits(rep, "data.ebs-unencrypted")
            if f["resource"]["type"] == "ebs_volume"}
    # moto gives each lab instance an unencrypted root volume too, so more than one hit
    # is correct; the point is the created bad volume is in and the encrypted one is out.
    assert ids["vol_bad"] in vols and ids["vol_ok"] not in vols


def test_evaluate_on_reloaded_snapshot_is_identical(lab_report):
    rep, _, snap = lab_report
    again = Snapshot.from_json(snap.to_json())
    results, rows = scan.evaluate(again, PROFILE)
    ids1 = sorted(f["id"] for f in rep["findings"])
    ids2 = sorted(f.id for r in results.values() for f in r.findings if f.status != "accepted")
    assert ids1 == ids2


def test_denied_collector_becomes_gap_not_pass(lab_report):
    _, _, snap = lab_report
    blind = Snapshot.from_json(snap.to_json())
    blind.data.pop("ec2.security_groups")
    from cloudtools.core.collect import Miss
    blind.misses.append(Miss("ec2.security_groups", R, "AccessDenied", True,
                             ("ec2:DescribeSecurityGroups",)))
    results, rows = scan.evaluate(blind, PROFILE)
    r = results["net.open-admin-ports"]
    assert not r.findings and r.gaps
    assert {x["id"]: x["status"] for x in rows}["net.open-admin-ports"] == "partial"


def test_every_check_documents_itself():
    for cid, c in CHECKS.items():
        assert c.spec.covers, f"{cid} must say what it covers (R5.5)"
        # cred.repo-secrets reads local repos only (--repo), so it has no AWS collector.
        assert c.spec.collectors or cid == "cred.repo-secrets"
