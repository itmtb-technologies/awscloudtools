"""The HTTP front door: one route per capability, generated from the manifests, so a newly
registered capability is served with no extra code.

  * a `job` is `POST /v1/<tool>/<name>` with a JSON body, and answers 202 with a run id at
    once; the platform's `submit` port runs it (standalone: a thread; hosted: a queued job);
  * a `view` is `GET /v1/<tool>/<name>` with query parameters, and answers 200.

The same app serves `cloudtools serve` (standalone, 127.0.0.1 only) and a hosted
deployment, which wraps it in its own authentication. The platform object is the only
thing that differs. FastAPI is imported only by
`create_app`, so the worker can use `run_job` without a web framework."""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from typing import Any, Callable

import jsonschema

from .core.capability import Capability, Manifest, all_capabilities, get, load_builtin
from .core.platform.base import CapabilityJob, Refused

PREFIX = "/v1"
STATUS_CAPABILITY = "security.get_run_status"
# One error shape for every client: {detail, error_code}.
VALIDATION, NOT_FOUND, FORBIDDEN, INTERNAL = "VALIDATION", "NOT_FOUND", "FORBIDDEN", "INTERNAL"
TRY_AGAIN = "That didn't go through. Please try again in a moment."


class BadRequest(ValueError):
    pass


def route_for(manifest: Manifest) -> tuple[str, str]:
    """(method, path) of a capability: `security.list_findings` → GET /v1/security/list_findings."""
    tool, _, name = manifest.id.partition(".")
    return ("POST" if manifest.kind == "job" else "GET"), f"{PREFIX}/{tool}/{name.replace('.', '/')}"


def job_inputs(manifest: Manifest) -> dict:
    """The input schema a job route accepts. `wait` is dropped: over HTTP a job is always
    asynchronous (the 202 is the contract), so the job body itself runs to completion."""
    s = manifest.input_schema
    props = {k: v for k, v in s.get("properties", {}).items() if k != "wait"}
    out = {**s, "properties": props}
    if "required" in s:
        out["required"] = [k for k in s["required"] if k in props]
    return out


def requested_tier(manifest: Manifest, inputs: dict) -> int:
    """The highest tier this call would reach: the capability's own tier, an explicit
    `tier` input, or a built-in profile's `max_tier`. Authorize sees this, never less."""
    tier = manifest.tier
    if isinstance(inputs.get("tier"), int):
        tier = max(tier, inputs["tier"])
    prof = inputs.get("profile")
    if isinstance(prof, str):
        from .security import profiles
        tier = max(tier, profiles.BUILTIN.get(prof, {}).get("max_tier", 0))
    return tier


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_job(platform, job: CapabilityJob) -> Any:
    """Run a submitted job to completion, recording it in `runs/<run_id>/status.json` (the
    file `security.get_run_status` reads): running → succeeded (with the result) | failed.
    Used by the standalone thread and by a hosted worker alike."""
    from .security import runner
    cap = get(job.capability)
    inputs = dict(job.inputs)
    if "wait" in cap.manifest.input_schema.get("properties", {}):
        inputs["wait"] = True
    store = platform.store
    runner.set_status(store, job.run_id, state="running", stage="started",
                      capability=job.capability, started_at=_now())
    try:
        out = cap.fn(platform, **inputs)
    except Exception as e:
        runner.set_status(store, job.run_id, state="failed", ended_at=_now(),
                          error=f"{type(e).__name__}: {str(e)[:300]}")
        raise
    runner.set_status(store, job.run_id, state="succeeded", stage="done", ended_at=_now(),
                      result=out)
    return out


def _coerce_query(manifest: Manifest, query: dict) -> dict:
    props = manifest.input_schema.get("properties", {})
    out = {}
    for k, raw in query.items():
        t = props.get(k, {}).get("type")
        try:
            out[k] = (int(raw) if t == "integer" else float(raw) if t == "number" else
                      raw.lower() in ("1", "true", "yes") if t == "boolean" else raw)
        except ValueError:
            raise BadRequest(f"{k} must be {t}") from None
    return out


def _validate(schema: dict, inputs: dict) -> None:
    try:
        jsonschema.validate(inputs, schema)
    except jsonschema.ValidationError as e:
        where = ".".join(str(p) for p in e.absolute_path)
        raise BadRequest(f"{where + ': ' if where else ''}{e.message}"[:300]) from None


def _context_schema(platform) -> dict:
    """Fields a platform needs on every job besides the capability's own inputs (hosted: the
    connection id). Standalone has none, so its job bodies stay exactly the manifest's."""
    return dict(getattr(platform, "job_context", {}) or {})


def _error(status: int, code: str, detail: str):
    from fastapi.responses import JSONResponse
    return JSONResponse({"detail": detail, "error_code": code}, status_code=status,
                        headers={"cache-control": "no-store"})


def _hosted_profile(body: dict) -> None:
    """Hosted, `profile` is a built-in name only: the loader also takes a file path, which
    on a worker would read its disk (review 2026-10-30)."""
    from .security import profiles
    prof = body.get("profile")
    if prof is not None and prof not in profiles.BUILTIN:
        raise BadRequest(f"profile must be one of {', '.join(profiles.BUILTIN)}")


def _endpoint(cap: Capability, platform_for: Callable, hosted_only: bool = False):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool
    from fastapi.responses import JSONResponse
    m = cap.manifest

    async def endpoint(request):
        try:
            plat = platform_for(request)
            if m.kind == "job":
                raw = await request.body()
                try:
                    body = json.loads(raw) if raw.strip() else {}
                except ValueError:
                    raise BadRequest("the body must be JSON") from None
                if not isinstance(body, dict):
                    raise BadRequest("the body must be a JSON object")
                ctx_schema = _context_schema(plat)
                context = {k: body.pop(k) for k in list(body) if k in ctx_schema}
                _validate({"type": "object", "properties": ctx_schema,
                           "required": sorted(ctx_schema), "additionalProperties": False},
                          context)
                _validate(job_inputs(m), body)
            else:
                body = _coerce_query(m, dict(request.query_params))
                _validate(m.input_schema, body)
            if hosted_only:
                _hosted_profile(body)
            tier = requested_tier(m, body)
            # Authorize the call as it would really run: a profile or input that reaches a
            # higher tier is checked at that tier.
            plat.authorize(dataclasses.replace(m, tier=tier) if tier != m.tier else m)
            if m.kind == "view":
                return JSONResponse(json.loads(json.dumps(
                    await run_in_threadpool(cap.fn, plat, **body), default=str)))
            return JSONResponse(await run_in_threadpool(_start, plat, m, body, tier, context),
                                status_code=202)
        except Refused as e:
            return _error(403, FORBIDDEN, str(e))
        except BadRequest as e:
            return _error(400, VALIDATION, str(e))
        except LookupError as e:
            return _error(404, NOT_FOUND, str(e.args[0]) if e.args else "not found")
        except Exception as e:
            status = getattr(e, "http_status", None)
            if status:      # a platform port that answers with its own status (hosted submit)
                return _error(status, getattr(e, "code", INTERNAL), str(e))
            if isinstance(e, ValueError):
                return _error(400, VALIDATION, str(e)[:300])
            _log_failure(plat if "plat" in locals() else None, m, e)
            return _error(500, INTERNAL, TRY_AGAIN)   # 5xx text goes to the log, never out

    endpoint.__name__ = m.id.replace(".", "_")
    # The real class, not the string `from __future__` would leave: FastAPI resolves
    # annotations against module globals, and fastapi is imported only in here.
    endpoint.__annotations__ = {"request": Request}
    return endpoint


def _start(plat, m: Manifest, inputs: dict, tier: int, context: dict) -> dict:
    from .security import runner, scan
    rid = scan.new_run_id()
    job = CapabilityJob(m.id, inputs, rid, tier=tier,
                        initiator=getattr(plat, "initiator", "http"), context=context)
    job.run = lambda: run_job(plat, job)
    runner.set_status(plat.store, rid, state="queued", capability=m.id, queued_at=_now())
    try:
        plat.submit(job)
    except Exception as e:
        runner.set_status(plat.store, rid, state="failed", ended_at=_now(),
                          error=f"not submitted: {type(e).__name__}")
        raise
    method, path = route_for(get(STATUS_CAPABILITY).manifest)
    return {"run_id": rid, "state": "queued", "poll": STATUS_CAPABILITY,
            "status_url": f"{path}?run_id={rid}"}


def _log_failure(plat, m: Manifest, e: Exception) -> None:
    import sys
    for sink in (plat.log_sinks("http") if plat is not None else []):
        try:
            sink({"event": "http.error", "capability": m.id, "error": type(e).__name__})
        except Exception:
            pass
    print(f"cloudtools http: {m.id}: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr)


def create_app(platform_for: Callable, *, hosted_only: bool = False,
               service: str = "cloudtools", version: str = ""):
    """The FastAPI app. `platform_for(request)` returns the platform for one request
    (standalone: one shared object; hosted: one per verified caller). `hosted_only` leaves out
    every capability whose manifest says `hosted: false`; a hosted authorize refuses those
    too, so a route added by mistake still can't run one."""
    from fastapi import FastAPI
    from . import __version__
    load_builtin()
    app = FastAPI(title=service, version=version or __version__,
                  docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "service": service, "version": version or __version__}

    for cap in all_capabilities():
        if hosted_only and not cap.manifest.hosted:
            continue
        method, path = route_for(cap.manifest)
        app.add_api_route(path, _endpoint(cap, platform_for, hosted_only), methods=[method],
                          name=cap.manifest.id)
    return app


def routes(app) -> set[tuple[str, str]]:
    """{(method, path)} the app serves (the generated agent declaration is tested against it)."""
    out = set()
    for r in app.routes:
        for meth in getattr(r, "methods", None) or ():
            if meth != "HEAD":
                out.add((meth, r.path))
    return out
