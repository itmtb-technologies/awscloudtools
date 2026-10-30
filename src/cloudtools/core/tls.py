"""The TLS context for every HTTPS download the tool makes outside botocore."""
from __future__ import annotations

import os
import ssl


def context() -> ssl.SSLContext:
    """Verify with the bundle botocore uses (AWS_CA_BUNDLE, else certifi), not the system
    one: python.org builds have none, and downloads failed there (Lambda code 2026-10-28,
    OSV update-db 2026-10-29)."""
    from botocore.httpsession import get_cert_path
    return ssl.create_default_context(cafile=os.environ.get("AWS_CA_BUNDLE") or get_cert_path(True))
