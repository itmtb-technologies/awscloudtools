"""The lab scorer (tools/lab_score.py) and the lab's three files agreeing with each other:
the stack's outputs, expected.yaml and the check catalogue."""
import importlib.util
from pathlib import Path

import yaml

from cloudtools.security.checks import CHECKS, load_all

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("lab_score", ROOT / "tools/lab_score.py")
lab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab)
EXPECTED = yaml.safe_load((ROOT / "tests/lab/expected.yaml").read_text(encoding="utf-8"))


class _CfnLoader(yaml.SafeLoader):
    """Reads a CloudFormation template; intrinsic tags (!Ref, !Sub, ...) become plain values."""


_CfnLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def _template():
    return yaml.load((ROOT / "infra/lab/scanner-lab.yaml").read_text(encoding="utf-8"),
                     Loader=_CfnLoader)


OUTPUTS = {"BadSg": "sg-bad", "GoodSg": "sg-good", "BadInstance": "i-bad",
           "GoodInstance": "i-good", "BadFunction": "lab-open-fn", "GoodFunction": "lab-iam-fn",
           "LeakedKeyUser": "lab-leaked-key", "ExtTrustRole": "lab-ext-trust",
           "ExtTrustOkRole": "lab-ext-trust-ok"}
FN = "arn:aws:lambda:eu-west-1:123456789012:function:"


def _f(n, check, rid, name=None, status="open"):
    return {"id": f"fd-{n:016x}", "check_id": check, "status": status,
            "resource": {"id": rid, **({"name": name} if name else {})}}


def _expected(*required, twins=("GoodSg", "GoodInstance", "ExtTrustOkRole"), allowed=None):
    return {"required": list(required), "twins": list(twins), "allowed_on_twins": allowed or {}}


def test_every_lab_resource_is_a_stack_output():
    assert lab.referenced(EXPECTED) <= set(_template()["Outputs"])


def test_every_expected_check_exists_at_its_tier():
    load_all()
    for req in EXPECTED["required"]:
        assert req["check"] in CHECKS, req
        assert CHECKS[req["check"]].spec.tier == int(req.get("tier", 0)), req
    for checks in EXPECTED["allowed_on_twins"].values():
        assert set(checks) <= set(CHECKS)


def test_template_holds_no_literal_secret():
    """No literal secret sits in the template: secrets come in as NoEcho parameters."""
    params = _template()["Parameters"]
    for name in ("FakeOpenAiKey", "FakeGithubToken", "ConsolePassword"):
        assert params[name]["NoEcho"] is True and "Default" not in params[name]


def test_found_and_twin_clean_passes():
    rep = {"run": {"max_tier": 0}, "findings": [_f(1, "net.open-admin-ports", "sg-bad")]}
    r = lab.score(rep, OUTPUTS, _expected({"resource": "BadSg", "check": "net.open-admin-ports"}))
    assert r["pass"] and r["recall"] == "1/1" and not r["false_hits"]


def test_missing_required_fails():
    rep = {"run": {"max_tier": 0}, "findings": []}
    r = lab.score(rep, OUTPUTS, _expected({"resource": "BadSg", "check": "net.open-admin-ports"}))
    assert not r["pass"] and r["missed"] == ["net.open-admin-ports on BadSg"]


def test_same_check_on_the_wrong_resource_does_not_count():
    rep = {"run": {"max_tier": 0}, "findings": [_f(1, "net.open-admin-ports", "sg-other")]}
    r = lab.score(rep, OUTPUTS, _expected({"resource": "BadSg", "check": "net.open-admin-ports"}))
    assert r["missed"] and r["outside_lab"] == 1


def test_finding_on_a_twin_is_a_false_hit():
    rep = {"run": {"max_tier": 0}, "findings": [
        _f(1, "net.open-admin-ports", "sg-bad"), _f(2, "net.open-admin-ports", "sg-good")]}
    r = lab.score(rep, OUTPUTS, _expected({"resource": "BadSg", "check": "net.open-admin-ports"}))
    assert not r["pass"] and r["false_hits"] == ["net.open-admin-ports on GoodSg"]


def test_allowed_check_on_a_twin_is_not_a_false_hit():
    rep = {"run": {"max_tier": 2}, "findings": [
        _f(1, "net.open-admin-ports", "sg-bad"), _f(2, "cve.inspector", "i-good")]}
    r = lab.score(rep, OUTPUTS, _expected({"resource": "BadSg", "check": "net.open-admin-ports"},
                                          allowed={"GoodInstance": ["cve.inspector"]}))
    assert r["pass"]


def test_name_prefix_is_not_a_match():
    """ext-trust must not claim ext-trust-ok's finding, or a twin's false hit would hide."""
    rep = {"run": {"max_tier": 0}, "findings": [
        _f(1, "iam.trust-without-external-id", "arn:aws:iam::123456789012:role/lab-ext-trust-ok",
           "lab-ext-trust-ok")]}
    r = lab.score(rep, OUTPUTS, _expected(
        {"resource": "ExtTrustRole", "check": "iam.trust-without-external-id"}))
    assert r["missed"] and r["false_hits"] == ["iam.trust-without-external-id on ExtTrustOkRole"]


def test_arn_suffix_and_any_of_resources_match():
    rep = {"run": {"max_tier": 1}, "findings": [
        _f(1, "sec.leaked-aws-key", FN + "lab-open-fn", "lab-open-fn")]}
    r = lab.score(rep, OUTPUTS, _expected(
        {"resource": ["BadFunction", "LeakedKeyUser"], "check": "sec.leaked-aws-key", "tier": 1}))
    assert r["pass"]


def test_above_tier_is_skipped_not_missed_and_nothing_scored_fails():
    rep = {"run": {"max_tier": 0}, "findings": []}
    r = lab.score(rep, OUTPUTS, _expected(
        {"resource": "BadInstance", "check": "cve.inspector", "tier": 2}))
    assert r["skipped"] and not r["missed"] and not r["pass"]     # 0 scored is not a pass


def test_unless_context_skips():
    rep = {"run": {"max_tier": 0}, "findings": [_f(1, "net.open-admin-ports", "sg-bad")]}
    r = lab.score(rep, OUTPUTS, _expected(
        {"resource": "BadSg", "check": "net.open-admin-ports"},
        {"resource": "BadInstance", "check": "data.ebs-unencrypted", "unless": "ebs_encryption_by_default"}),
        {"ebs_encryption_by_default": True})
    assert r["pass"] and len(r["skipped"]) == 1


def test_resolved_findings_are_ignored():
    rep = {"run": {"max_tier": 0}, "findings": [_f(1, "net.open-admin-ports", "sg-bad", status="resolved")]}
    r = lab.score(rep, OUTPUTS, _expected({"resource": "BadSg", "check": "net.open-admin-ports"}))
    assert r["missed"]
