"""Report renderers: terminal, JSON, self-contained HTML, SARIF 2.1.0, CSV
(requirements §Findings model and outputs). All output is marked sensitive (R8.5)."""
from __future__ import annotations

import csv
import html
import io
import json

from .model import SEVERITIES

SENSITIVE = ("SENSITIVE: this report describes weak points of an AWS account. Store and "
             "share it like a credential.")


def to_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, sort_keys=True, default=str).encode()


# A cell starting with one of these is a formula to a spreadsheet, and account data reaches
# the cells: AWS accepts a security group named `=HYPERLINK(...)` (review 2026-10-30).
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _cell(v):
    return "'" + v if isinstance(v, str) and v.startswith(_FORMULA_START) else v


def to_csv(report: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "severity", "contextual_severity", "diff", "status", "check_id",
                "title", "resource_id", "resource_name", "region", "account", "on_paths",
                "fix"])
    for f in report["findings"] + report["accepted"]:
        r = f["resource"]
        w.writerow([_cell(v) for v in [f["id"], f["severity"]["base"], f["severity"]["contextual"], f.get("diff", ""),
                    f["status"], f["check_id"], f["title"], r.get("id", ""), r.get("name", ""),
                    r.get("region", ""), r.get("account", ""), len(f.get("on_paths", [])),
                    f["remediation"].get("summary", "")]])
    return buf.getvalue().encode()


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_sarif(report: dict, catalogue: list[dict]) -> bytes:
    by_id = {c["id"]: c for c in catalogue}
    used = sorted({f["check_id"] for f in report["findings"]})
    rules = [{"id": cid, "name": cid, "shortDescription": {"text": by_id.get(cid, {}).get("title", cid)},
              "fullDescription": {"text": by_id.get(cid, {}).get("covers", "")},
              "properties": {"tags": ["security", by_id.get(cid, {}).get("category", "")]}}
             for cid in used]
    results = []
    for f in report["findings"]:
        r = f["resource"]
        results.append({
            "ruleId": f["check_id"], "level": _SARIF_LEVEL[f["severity"]["contextual"]],
            "message": {"text": f"{f['title']}. Fix: {f['remediation'].get('summary', '')}"},
            "partialFingerprints": {"cloudtoolsFindingId": f["id"]},
            # SARIF wants a location; for cloud resources a logical location is the honest one.
            "locations": [{"logicalLocations": [{"fullyQualifiedName": r.get("id", ""),
                                                 "name": r.get("name") or r.get("id", ""),
                                                 "kind": r.get("type", "resource")}]}],
            "properties": {"severity": f["severity"], "diff": f.get("diff"),
                           "account": r.get("account"), "region": r.get("region")}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "cloudtools-security",
                                         "version": report["run"]["tool_version"],
                                         "informationUri": "https://github.com/", "rules": rules}},
                     "results": results,
                     "properties": {"run_id": report["run"]["run_id"], "notice": SENSITIVE}}]}
    return json.dumps(doc, indent=2).encode()


# C0 and C1 control characters, DEL included. Names in a report come from the scanned
# account, and an escape sequence in one would drive the reader's terminal (CT-17).
_CONTROL = {c: None for c in [*range(0, 32), *range(127, 160)] if c != 10}


def terminal(report: dict, top: int = 10) -> str:
    return _terminal(report, top).translate(_CONTROL)


def _terminal(report: dict, top: int) -> str:
    s = report["summary"]
    run = report["run"]
    lines = [f"cloudtools security · account {run['account']} · {len(run['regions'])} region(s) · "
             f"run {run['run_id']}",
             "  " + "  ".join(f"{k}: {s['by_severity'][k]}" for k in reversed(SEVERITIES)),
             f"  open {s['open']} · accepted {s['accepted']} · gaps {s['gaps']} · "
             f"new {s['diff']['new']} · regressed {s['diff']['regressed']} · "
             f"resolved {len(report.get('resolved', []))}"
             + (f" · not re-checked {len(report['not_rechecked'])}" if report.get("not_rechecked") else "")]
    if report["chokepoints"]:
        lines.append(f"\nTop fixes ({len(report['paths'])} attack path(s)):")
        lines += [f"  · {c['headline']}: {c['fix']}" for c in report["chokepoints"][:5]]
    new = [f for f in report["findings"] if f.get("diff") in ("new", "regressed")][:top]
    if new:
        lines.append("\nNew findings:")
        lines += [f"  [{f['severity']['contextual']:>8}] {f['title']}" for f in new]
    if report["gaps"]:
        lines.append(f"\nCould not see ({len(report['gaps'])} gap(s), never counted as a pass): "
                     "run `cloudtools security doctor` for what to grant.")
    lines.append("\n" + SENSITIVE)
    return "\n".join(lines)


def to_html(report: dict) -> bytes:
    e = html.escape
    s = report["summary"]
    run = report["run"]

    def frow(f):
        r = f["resource"]
        ev = "<br>".join(e(f"{x['source']} {x.get('resource', '')}: {x.get('detail', '')}")
                         for x in f["evidence"])
        return (f"<tr class='sev-{e(f['severity']['contextual'])}'><td>{e(f['severity']['contextual'])}"
                f"{'' if f['severity']['contextual'] == f['severity']['base'] else ' (base ' + e(f['severity']['base']) + ')'}"
                f"</td><td>{e(f.get('diff', ''))}</td><td>{e(f['title'])}<div class='m'>{e(f['check_id'])} · "
                f"{e(r.get('id', ''))} · {e(r.get('region', ''))}</div></td><td class='m'>{ev}</td>"
                f"<td>{e(f['remediation'].get('summary', ''))}</td></tr>")

    paths = "".join(
        f"<details><summary>{e(p['summary'])} · {e(p['status'])} · confidence {p['confidence']}</summary><ol>"
        + "".join(f"<li>{e(st['text'])}</li>" for st in p["steps"]) + "</ol></details>"
        for p in report["paths"][:50])
    chokes = "".join(f"<li><b>{e(c['headline'])}</b>: {e(c['fix'])}</li>" for c in report["chokepoints"])
    gaps = "".join(f"<li>{e(g['check_id'])}: {e(g['what'])}: {e(g['why'])}"
                   f"{' (needs ' + e(', '.join(g['needs'])) + ')' if g['needs'] else ''}</li>"
                   for g in report["gaps"])
    sev = " · ".join(f"{k} {s['by_severity'][k]}" for k in reversed(SEVERITIES))
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Security report</title>
<style>
:root{{--bg:#fff;--fg:#1b1f24;--mute:#5b6570;--line:#d9dee3;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#2563eb}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111418;--fg:#e6e9ec;--mute:#9aa4ae;--line:#2a3138}}}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0;padding:16px;max-width:1200px}}
.warn{{border:2px solid var(--crit);padding:8px 12px;font-weight:600}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid var(--line);padding:6px;vertical-align:top;text-align:left}}
.m{{color:var(--mute);font-size:12px;word-break:break-all}}
.sev-critical td:first-child{{color:var(--crit);font-weight:700}}.sev-high td:first-child{{color:var(--high);font-weight:700}}
.sev-medium td:first-child{{color:var(--med)}}.sev-low td:first-child{{color:var(--low)}}
.wrap{{overflow-x:auto}}
</style></head><body>
<p class="warn">{e(SENSITIVE)}</p>
<h1>Security report</h1>
<p class="m">Account {e(run['account'])} · regions {e(', '.join(run['regions']))} · run {e(run['run_id'])} ·
collected {e(str(run.get('collected_at')))} · profile {e(str(run.get('profile')))} · config {e(run['config_hash'])}</p>
<p><b>{sev}</b><br>open {s['open']} · accepted {s['accepted']} · gaps {s['gaps']} · new {s['diff']['new']} ·
regressed {s['diff']['regressed']} · resolved {len(report.get('resolved', []))} · not re-checked {len(report.get('not_rechecked', []))}</p>
<h2>Top fixes</h2><ul>{chokes or '<li>No attack paths found.</li>'}</ul>
<h2>Attack paths ({len(report['paths'])})</h2>{paths or '<p>None found.</p>'}
<h2>Findings</h2><div class="wrap"><table><tr><th>Severity</th><th>Diff</th><th>Finding</th><th>Evidence</th><th>Fix</th></tr>
{''.join(frow(f) for f in report['findings'])}</table></div>
<h2>Accepted risks ({len(report['accepted'])})</h2><ul>{''.join(f"<li>{e(f['title'])}: {e(f.get('accepted_reason', ''))}</li>" for f in report['accepted'])}</ul>
<h2>What could not be seen ({len(report['gaps'])})</h2><p class="m">A gap is never a pass.</p><ul>{gaps}</ul>
</body></html>"""
    return doc.encode()
