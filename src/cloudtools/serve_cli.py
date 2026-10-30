"""`cloudtools serve`: the HTTP API on this machine, over the user's own AWS credentials.

It binds 127.0.0.1 only, by construction: there is no --host. Loopback alone is not a
boundary, though: any web page the user visits can send requests to 127.0.0.1, and after
DNS rebinding read the answers (shown on 0.1.3, review 2026-10-30). So every request must
name this server in its Host header and, except /health, carry this launch's token
(`Authorization: Bearer <token>`), printed at start or taken from CLOUDTOOLS_SERVE_TOKEN.
A page can do neither.

Wired into `cli.py` as a subcommand at merge (`serve_cli.add_parser(sub)`); runnable
alone as `python -m cloudtools.serve_cli`."""
from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timezone

HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def add_parser(sub) -> argparse.ArgumentParser:
    p = sub.add_parser("serve", help=f"serve the HTTP API on http://{HOST} (this machine only)")
    _args(p)
    return p


def _args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    p.add_argument("--aws-profile", help="AWS named profile (default: the standard credential chain)")
    p.add_argument("--region", help="home region for global calls (default: from the profile)")
    p.add_argument("--out", default="./reports", help="output dir or s3:// URI (default ./reports)")
    p.add_argument("--verbose", "-v", action="store_true", help="stream run logs to stderr")
    p.set_defaults(fn=cmd_serve)


class LocalOnly:
    """ASGI guard in front of the app: this server's Host, and this launch's token."""

    def __init__(self, app, token: str, port: int, sinks=()):
        self.app = app
        self.auth = f"Bearer {token}".encode()
        self.hosts = {f"{HOST}:{port}".encode(), f"localhost:{port}".encode()}
        self.sinks = list(sinks)

    def _record(self, scope, status: int, outcome: str) -> None:
        """One line per request (CT-10): method, path, status, outcome. Never the query
        string or a header, so neither ids nor the token reach the log."""
        event = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                 "event": "http.request", "method": scope.get("method"),
                 "path": scope.get("path"), "status": status, "outcome": outcome}
        for sink in self.sinks:
            try:
                sink(event)
            except Exception:                    # an audit line must never fail a request
                pass

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers") or [])
        if headers.get(b"host", b"").lower() not in self.hosts:
            self._record(scope, 403, "foreign_host")
            return await _deny(send, 403, "FORBIDDEN", "this server answers only "
                               f"http://{HOST} and http://localhost on its own port")
        if scope["path"] != "/health" and not hmac.compare_digest(
                headers.get(b"authorization", b""), self.auth):
            self._record(scope, 401, "no_token")
            return await _deny(send, 401, "UNAUTHENTICATED",
                               "send the token cloudtools serve printed: "
                               "Authorization: Bearer <token>")
        seen = {}

        async def watch(message):
            if message["type"] == "http.response.start":
                seen["status"] = message["status"]
            await send(message)
        try:
            await self.app(scope, receive, watch)
        finally:
            st = seen.get("status", 500)
            self._record(scope, st, "ok" if st < 400 else "error")


async def _deny(send, status: int, code: str, detail: str) -> None:
    body = json.dumps({"detail": detail, "error_code": code}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]})
    await send({"type": "http.response.body", "body": body})


def build_app(a, token: str):
    from .core.platform.standalone import StandalonePlatform
    from .http_app import create_app
    plat = StandalonePlatform(profile=a.aws_profile, region=a.region, output=a.out,
                              initiator="http", log_to_stderr=a.verbose)
    sinks: list = []

    def audit(event):                    # the log folder is made on the first request
        if not sinks:
            sinks.extend(plat.log_sinks("http"))
        for sink in sinks:
            sink(event)
    return LocalOnly(create_app(lambda _request: plat), token, a.port, [audit])


def cmd_serve(a) -> int:
    import uvicorn
    if not 1 <= a.port <= 65535:
        print(f"cloudtools: --port must be 1-65535, not {a.port}", file=sys.stderr)
        return 64
    token = os.environ.get("CLOUDTOOLS_SERVE_TOKEN") or secrets.token_urlsafe(32)
    print(f"cloudtools: serving on http://{HOST}:{a.port} (this machine only)", file=sys.stderr)
    if not os.environ.get("CLOUDTOOLS_SERVE_TOKEN"):
        print(f"cloudtools: send every request with: Authorization: Bearer {token}", file=sys.stderr)
    uvicorn.run(build_app(a, token), host=HOST, port=a.port, log_level="warning")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="cloudtools serve", description=__doc__.splitlines()[0])
    _args(p)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
