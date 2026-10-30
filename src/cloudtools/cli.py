"""The CLI (GitHub variant). Friendly subcommands for the main flows, plus a generic
`cloudtools call <capability> key=value ...` generated from the manifests, so every
registered capability is runnable here with no extra code."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core.capability import all_capabilities, get, load_builtin
from .core.platform.standalone import StandalonePlatform


def _platform(a, initiator="cli") -> StandalonePlatform:
    return StandalonePlatform(profile=a.aws_profile, region=a.region, output=a.out,
                              initiator=initiator, log_to_stderr=a.verbose)


def _common(p):
    p.add_argument("--aws-profile", help="AWS named profile (default: the standard credential chain)")
    p.add_argument("--region", help="home region for global calls (default: from the profile)")
    p.add_argument("--out", default="./reports", help="output dir or s3:// URI (default ./reports)")
    p.add_argument("--verbose", "-v", action="store_true", help="stream the run log to stderr")


def _print_scan(report: dict, quiet: bool) -> int:
    from .core import publish
    if not quiet:
        print(publish.terminal(report))
        for k, v in sorted((report["run"].get("outputs") or {}).items()):
            print(f"  {k}: {v}")
    return report["run"].get("exit_code", 0)


def cmd_scan(a) -> int:
    rep = get("security.scan").fn(_platform(a), profile=a.profile, regions=a.regions or "", full=True,
                                  repos=a.repo, tier=a.tier)
    return _print_scan(rep, a.quiet)


def cmd_run(a) -> int:
    rep = get("security.run_check").fn(_platform(a), check_id=a.check_id, regions=a.regions or "",
                                       full=True, tier=a.tier)
    return _print_scan(rep, a.quiet)


def cmd_evaluate(a) -> int:
    rep = get("security.evaluate").fn(_platform(a), snapshot=a.snapshot, profile=a.profile, full=True)
    return _print_scan(rep, a.quiet)


def cmd_doctor(a) -> int:
    from .security import doctor
    d = get("security.doctor").fn(_platform(a), profile=a.profile, regions=a.regions or "")
    print(json.dumps(d, indent=2, default=str) if a.json else doctor.to_text(d))
    return 0 if d["summary"]["blocked"] == 0 else 1


def cmd_policy(a) -> int:
    from .security import doctor
    pol = get("security.generate_policy").fn(_platform(a), profile=a.profile, tier=a.tier)
    if not a.write:
        print(json.dumps(pol, indent=2))
        return 0
    out = Path(a.write)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cloudtools-policy.json").write_text(json.dumps(pol, indent=2), encoding="utf-8")
    actions = pol["Statement"][0]["Action"]
    (out / "ask-your-admin.txt").write_text(doctor.ask_admin_message(actions), encoding="utf-8")
    print(f"wrote {out / 'cloudtools-policy.json'} and {out / 'ask-your-admin.txt'}")
    return 0


def cmd_checks(a) -> int:
    for c in get("security.list_checks").fn(None, category=a.category or "")["checks"]:
        print(f"{c['id']:<36} {c['category']:<9} {c['default_severity']:<8} {c['title']}")
    return 0


def _coerce(manifest, key, raw):
    t = manifest.input_schema.get("properties", {}).get(key, {}).get("type")
    return int(raw) if t == "integer" else float(raw) if t == "number" else \
        raw.lower() in ("1", "true", "yes") if t == "boolean" else raw


def cmd_call(a) -> int:
    cap = get(a.capability)
    kwargs = {}
    for kv in a.args:
        k, _, v = kv.partition("=")
        if k not in cap.manifest.input_schema.get("properties", {}):
            sys.exit(f"{a.capability} has no input {k!r}; inputs: "
                     f"{sorted(cap.manifest.input_schema.get('properties', {}))}")
        kwargs[k] = _coerce(cap.manifest, k, v)
    plat = _platform(a)
    plat.authorize(cap.manifest, confirm=a.confirm)
    print(json.dumps(cap.fn(plat, **kwargs), indent=2, default=str))
    return 0


def _cve(rest: list[str]) -> int:
    from . import cve_cli
    return cve_cli.main(rest)


def cmd_capabilities(a) -> int:
    for c in all_capabilities():
        m = c.manifest
        flags = ",".join(x for x, on in (("job", m.kind == "job"), ("agent", m.agent_visible),
                                         ("hosted", m.hosted), ("MUTATES", m.mutating)) if on)
        print(f"{m.id:<28} {flags:<22} {m.title}")
    return 0


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 64 (EX_USAGE), not argparse's 2, which here means 'new medium'."""

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="cloudtools", description="Read-only AWS security, "
                                "credential and cost tools. Uses your existing AWS credentials.")
    p.add_argument("--version", action="version", version=f"cloudtools {__version__}")
    sub = p.add_subparsers(dest="tool", required=True, parser_class=_Parser)

    sec = sub.add_parser("security", help="AWS security scanner")
    ss = sec.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, profile=True, regions=True):
        q = ss.add_parser(name, help=help_)
        _common(q)
        if profile:
            q.add_argument("--profile", default="quick", help="quick | full | ci | path to a YAML profile")
        if regions:
            q.add_argument("--regions", help="comma-separated (default: all enabled)")
        q.set_defaults(fn=fn)
        return q

    def tier(q):
        q.add_argument("--tier", type=int, choices=(0, 1, 2), default=0,
                       help="opt in to tier-N checks (1: secrets in AWS configuration, which reads "
                            "Lambda code, user data and templates; default 0)")

    q = add("scan", cmd_scan, "scan the account and write a report")
    q.add_argument("--quiet", "-q", action="store_true")
    q.add_argument("--repo", action="append", metavar="PATH",
                   help="also scan this local git repo for secrets (repeatable; needs gitleaks)")
    tier(q)
    q = add("run", cmd_run, "run one check", profile=False)
    q.add_argument("check_id")
    tier(q)
    q.add_argument("--quiet", "-q", action="store_true")
    q = add("evaluate", cmd_evaluate, "re-run checks on a saved snapshot (no AWS calls)", regions=False)
    q.add_argument("--snapshot", required=True)
    q.add_argument("--quiet", "-q", action="store_true")
    q = add("doctor", cmd_doctor, "what can this identity read, and how to get the rest")
    q.add_argument("--json", action="store_true")
    q = add("policy", cmd_policy, "print or write the least-privilege policy", regions=False)
    q.add_argument("--write", metavar="DIR", help="write the policy and an ask-your-admin message")
    tier(q)
    q = add("checks", cmd_checks, "list the checks", profile=False, regions=False)
    q.add_argument("--category")

    c = sub.add_parser("call", help="run any capability by id: cloudtools call <id> key=value ...")
    _common(c)
    c.add_argument("capability")
    c.add_argument("args", nargs="*")
    c.add_argument("--confirm", action="store_true", help="required for capabilities that change resources")
    c.set_defaults(fn=cmd_call)
    from . import serve_cli
    serve_cli.add_parser(sub).set_defaults(fn=serve_cli.cmd_serve)
    v = sub.add_parser("cve", help="vulnerability data: cloudtools cve update-db")
    v.add_argument("rest", nargs=argparse.REMAINDER)
    v.set_defaults(fn=lambda a: _cve(a.rest))
    k = sub.add_parser("capabilities", help="list every capability and where it is exposed")
    k.set_defaults(fn=cmd_capabilities)
    return p


def _safe_stdout() -> None:
    """A redirected stdout on Windows is cp1252, which has no '→'. Never crash on output:
    write UTF-8 where the stream allows it, and replace what it can't encode otherwise."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None) -> int:
    _safe_stdout()
    load_builtin()
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except (LookupError, ValueError) as e:
        print(f"cloudtools: {e}", file=sys.stderr)
        return 64
    except Exception as e:  # credentials and access problems read as advice, not a trace
        from .core.aws import AwsAccessError
        if isinstance(e, AwsAccessError):
            print(f"cloudtools: {e}", file=sys.stderr)
            return 65
        raise


if __name__ == "__main__":
    sys.exit(main())
