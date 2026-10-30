"""`cloudtools cve update-db`: download the OSV ecosystem zips cve.osv-packages reads.

This is the ONLY network use of tier 2, and it is explicit: the scan never calls OSV,
and never sends a package list anywhere. It downloads whole public ecosystem archives
(`<base>/<Ecosystem>/all.zip`) into `~/.cache/cloudtools/osv/<Ecosystem>/all.zip` and
records what it fetched in `manifest.json`. Archives are read in memory, never extracted.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .core import tls
from .security.checks.vuln import OSV_DEFAULT_DIR, data_file

TIMEOUT_S = 120
MAX_BYTES = 2 * 1024 ** 3                  # refuse a runaway download


def _fetch(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError(f"refusing a non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "cloudtools cve update-db"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=tls.context()) as r:        # noqa: S310 (https only)
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"{url}: larger than {MAX_BYTES} bytes")
    return body


def default_ecosystems() -> list[str]:
    return sorted({e["download"] for e in data_file("osv_ecosystems.json")["entries"]})


def update_db(directory: str = OSV_DEFAULT_DIR, ecosystems: list[str] | None = None,
              fetch=_fetch, out=sys.stdout) -> dict:
    """Download each ecosystem zip; keep the old copy of any that fails. Returns the manifest."""
    mapping = data_file("osv_ecosystems.json")
    root = Path(directory).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    mpath = root / "manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8")) if mpath.exists() else {"ecosystems": {}}
    failed = []
    for eco in ecosystems or default_ecosystems():
        url = f"{mapping['base_url']}/{urllib.parse.quote(eco)}/all.zip"
        try:
            body = fetch(url)
            with zipfile.ZipFile(io.BytesIO(body)) as z:      # a valid archive, or nothing
                n = sum(1 for x in z.namelist() if x.endswith(".json"))
        except Exception as e:                                 # network, size, bad zip
            failed.append(eco)
            print(f"  {eco}: FAILED ({type(e).__name__}: {e}); kept the previous copy", file=out)
            continue
        dest = root / eco / "all.zip"
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".zip.part")
        tmp.write_bytes(body)
        os.replace(tmp, dest)
        manifest["ecosystems"][eco] = {
            "url": url, "records": n, "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "downloaded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        print(f"  {eco}: {n} records, {len(body) // 1024} KiB", file=out)
    manifest["failed"] = failed
    mpath.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    """Entry point for `cloudtools cve ...` (wired into cli.py at merge)."""
    p = argparse.ArgumentParser(prog="cloudtools cve")
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("update-db", help="download the offline OSV database (explicit network use)")
    u.add_argument("--dir", default=OSV_DEFAULT_DIR, help=f"where to keep it (default {OSV_DEFAULT_DIR})")
    u.add_argument("--ecosystem", action="append",
                   help="OSV ecosystem to fetch (repeatable; default: every mapped one)")
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    print(f"Downloading OSV ecosystem archives into {a.dir} "
          "(public data only; nothing about your account is sent)")
    m = update_db(a.dir, a.ecosystem)
    return 1 if m["failed"] else 0


if __name__ == "__main__":                 # pragma: no cover
    sys.exit(main())
