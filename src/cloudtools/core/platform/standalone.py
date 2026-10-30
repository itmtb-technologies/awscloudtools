"""The GitHub variant: the user's own AWS credentials, local files or their own S3,
no hosted service contacted or configured."""
from __future__ import annotations

import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path

from ..aws import AwsEnv
from ..capability import Manifest
from ..runlog import file_sink, redact, stderr_sink
from .base import Principal, Refused


def _retry_busy(fn, tries: int = 50, wait_s: float = 0.01):
    """Windows refuses to open a file for a moment while os.replace swaps it, and to
    replace one a reader has open: PermissionError both ways (CI, windows-latest,
    2026-10-29). Both clear in milliseconds, so retry briefly; anything longer is raised."""
    for i in range(tries):
        try:
            return fn()
        except PermissionError:
            if i == tries - 1:
                raise
            time.sleep(wait_s)


class LocalStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        """Keys stay inside the root: a run id reaches them from an HTTP query, and
        `runs/../../x` read outside it (review 2026-10-30). The rule TcStore applies."""
        parts = key.replace("\\", "/").split("/")
        if not key or key.startswith("/") or any(p in ("", ".", "..") for p in parts) \
                or Path(key).is_absolute():
            raise ValueError(f"bad store key {key!r}")
        return self.root / key

    def put(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Atomic: write a sibling temp file, then rename over. A reader polling status.json
        # while a scan rewrites it would otherwise see an empty file (os.replace is atomic on
        # POSIX and Windows).
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=f".{p.name}.")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            _retry_busy(lambda: os.replace(tmp, p))
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        return str(p)

    def get(self, key: str) -> bytes | None:
        p = self._path(key)
        return _retry_busy(p.read_bytes) if p.exists() else None

    def list(self, prefix: str) -> list[str]:
        base = self._path(prefix.rstrip("/"))
        if not base.exists():
            return []
        return sorted(str(p.relative_to(self.root)) for p in base.rglob("*") if p.is_file())


class S3Store:
    """R2.2: output to the user's own bucket. Writes go through a plain boto3 client
    built here, never through AwsEnv (whose clients are read-only by construction): the
    destination is the user's chosen output, not the scanned account's resources.

    Every call names the bucket's owner (CT-19, review 2026-10-30), so AWS refuses a
    bucket in any other account: a typo, or a name someone else registered, would
    otherwise receive the full report. The owner is the caller's account, or
    CLOUDTOOLS_S3_BUCKET_OWNER for a central bucket in another account."""

    def __init__(self, uri: str, profile: str | None = None):
        import boto3
        bucket, _, prefix = uri[len("s3://"):].partition("/")
        self.bucket, self.prefix = bucket, prefix.rstrip("/")
        session = boto3.Session(profile_name=profile)
        self._s3 = session.client("s3")
        self.owner = (os.environ.get("CLOUDTOOLS_S3_BUCKET_OWNER")
                      or session.client("sts").get_caller_identity()["Account"])

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}" if self.prefix else key

    def put(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        self._s3.put_object(Bucket=self.bucket, Key=self._k(key), Body=data,
                            ContentType=content_type, ServerSideEncryption="AES256",
                            ExpectedBucketOwner=self.owner)
        return f"s3://{self.bucket}/{self._k(key)}"

    def get(self, key: str) -> bytes | None:
        try:
            return self._s3.get_object(Bucket=self.bucket, Key=self._k(key),
                                       ExpectedBucketOwner=self.owner)["Body"].read()
        except self._s3.exceptions.NoSuchKey:
            return None

    def list(self, prefix: str) -> list[str]:
        out, cut = [], len(self.prefix) + 1 if self.prefix else 0
        for page in self._s3.get_paginator("list_objects_v2").paginate(
                Bucket=self.bucket, Prefix=self._k(prefix), ExpectedBucketOwner=self.owner):
            out += [o["Key"][cut:] for o in page.get("Contents", [])]
        return sorted(out)


def _store_sink(store, key: str, every: int = 200):
    """The run log for an output with no local folder (S3): kept in memory and written whole
    at run.end, and every `every` events so a crash still leaves most of it (CT-10: 0.1.4
    kept no run log at all for s3:// output)."""
    lines: list[str] = []

    def write(event: dict) -> None:
        lines.append(redact(json.dumps(event, default=str)))
        if event.get("event") == "run.end" or len(lines) % every == 0:
            store.put(key, ("\n".join(lines) + "\n").encode(), "application/x-ndjson")
    return write


class StandalonePlatform:
    name = "standalone"

    def __init__(self, profile: str | None = None, region: str | None = None,
                 output: str = "./reports", initiator: str = "cli", log_to_stderr=False):
        self.profile, self.region, self.output = profile, region, output
        self.initiator = initiator
        self.log_to_stderr = log_to_stderr
        self._principal: Principal | None = None
        self._threads: list = []
        self._store = S3Store(output, profile) if output.startswith("s3://") else LocalStore(output)

    @property
    def store(self):
        return self._store

    def aws_env(self, run_id: str, log=None, region: str | None = None) -> AwsEnv:
        return AwsEnv(profile=self.profile, region=region or self.region,
                      run_id=run_id, log=log)

    def principal(self) -> Principal:
        if self._principal is None:
            scope = AwsEnv(self.profile, self.region).resolve_scope()
            self._principal = Principal(id=scope.caller_arn, initiator=self.initiator)
        return self._principal

    def authorize(self, manifest: Manifest, confirm: bool = False) -> None:
        # Your own credentials: AWS IAM is the authority. Only a mutating capability
        # needs an explicit confirmation from the person running it.
        if manifest.mutating and not confirm:
            raise Refused(f"{manifest.id} changes resources; re-run with --confirm",
                          "CONFIRMATION_REQUIRED")

    def submit(self, job) -> None:
        """Run a job in the background. A non-daemon thread: even a one-shot CLI process
        finishes the scan before it exits. A hosted platform queues a job instead."""
        th = threading.Thread(target=self._guarded, args=(job,), daemon=False)
        self._threads.append(th)
        th.start()

    @staticmethod
    def _guarded(job) -> None:
        try:
            job()
        except Exception:                # the job records its own failure in status.json
            pass

    def join(self) -> None:
        for th in self._threads:
            th.join()

    def secret_salt(self) -> str:
        """Per installation (R5.1): CLOUDTOOLS_SALT, else ~/.config/cloudtools/salt, made
        once with mode 0600. Stable, so a secret keeps one fingerprint across runs."""
        if os.environ.get("CLOUDTOOLS_SALT"):
            return os.environ["CLOUDTOOLS_SALT"]
        path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "cloudtools" / "salt"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(secrets.token_hex(16))
        return path.read_text(encoding="utf-8").strip()

    def log_sinks(self, run_id: str) -> list:
        sinks = []
        if isinstance(self._store, LocalStore):
            path = self._store.root / "runs" / run_id / "run.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            sinks.append(file_sink(path))
        else:
            sinks.append(_store_sink(self._store, f"runs/{run_id}/run.jsonl"))
        if self.log_to_stderr:
            sinks.append(stderr_sink)
        return sinks
