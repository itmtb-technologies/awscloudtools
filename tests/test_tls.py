"""Every HTTPS download verifies with botocore's CA bundle, not the system one: python.org
builds of Python have no system bundle, so a default context fails on a clean Mac
(Lambda code download 2026-10-28; OSV update-db 2026-10-29, found by the live lab)."""
import ssl

import pytest

from cloudtools import cve_cli
from cloudtools.creds import config_secrets


class _Resp:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return b""


@pytest.fixture
def seen(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None, context=None):
        calls.append(context)
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    return calls


def _uses_botocore_bundle(ctx):
    from botocore.httpsession import get_cert_path
    assert isinstance(ctx, ssl.SSLContext), "no SSL context: the system bundle would be used"
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    ours = ssl.create_default_context(cafile=get_cert_path(True))
    assert ctx.cert_store_stats()["x509_ca"] == ours.cert_store_stats()["x509_ca"] > 0


def test_osv_download_uses_botocore_bundle(seen):
    cve_cli._fetch("https://example.invalid/Ubuntu/all.zip")
    _uses_botocore_bundle(seen[0])


def test_lambda_code_download_uses_botocore_bundle(seen):
    config_secrets._fetch("https://example.invalid/code.zip", 1024)
    _uses_botocore_bundle(seen[0])


def test_aws_ca_bundle_wins(monkeypatch, tmp_path):
    from botocore.httpsession import get_cert_path
    from cloudtools.core.tls import context
    custom = tmp_path / "ca.pem"
    custom.write_text(open(get_cert_path(True), encoding="utf-8").read().split("-----END CERTIFICATE-----")[0]
                      + "-----END CERTIFICATE-----\n", encoding="utf-8")
    monkeypatch.setenv("AWS_CA_BUNDLE", str(custom))
    assert context().cert_store_stats()["x509_ca"] == 1
