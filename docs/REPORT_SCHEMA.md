# Report schema v1 (frozen 2026-10-27)

`report.json` is the contract between the scanner and everything that reads it: the CLI views,
agents, web pages and CI. The machine-readable schema is `cloudtools.core.report.SCHEMA`.
Every test report is validated against it (`report.validate`).

**Changing it:** a breaking change bumps `schema_version`. A new finding field is also a
change: finding objects are closed (`additionalProperties: false`), so it has to be added
here and in `FINDING` together.

## Top level
| Key | Meaning |
|---|---|
| `schema_version` | `"1"` |
| `tool` | `"security"` |
| `run` | `run_id`, `tool_version`, `started_at`, `ended_at`, `platform` (`standalone`, or a hosted platform's name), `initiator` (`cli`/`mcp`/`agent`), `caller`, `account`, `regions`, `profile`, `config_hash`, `max_tier`, `collected_at`, `baseline`, `exit_code`, `outputs` |
| `summary` | `by_severity`, `open`, `accepted`, `gaps`, `diff` (counts of new/unchanged/regressed/resolved), `highest_new`, `resolved`, `not_rechecked` |
| `findings` / `accepted` | finding objects (below); `accepted` = tagged `scanner:accepted-risk`, kept out of totals |
| `resolved` / `not_rechecked` | findings from the previous run that are gone: fixed, or not checked this time |
| `gaps` | what could not be seen: `check_id`, `what`, `why`, `needs` (IAM actions), `region` |
| `facts` | graph edges: `id`, `from`, `type`, `to`, `status` (`confirmed`/`possible`), `confidence`, `conditions`, `evidence`, `emitted_by`, `qualifiers` |
| `nodes` | graph nodes: `id`, `type`, `name`, `region`, `account`, `labels`, `tags`, `attrs` |
| `paths` | `id`, `entry`, `target`, `nodes`, `edges`, `length`, `status`, `confidence`, `steps` (narrated, with evidence and conditions), `summary` |
| `chokepoints` | `check_id`, `fix`, `findings`, `edges`, `paths_broken`, `paths`, `headline` |
| `checks` | one row per check run: `id`, `status` (`ran`/`partial`/`error`), `findings`, `gaps`, `duration_ms`, optional `stats` (`evaluated: false` = no input) |

## Finding (closed)
| Field | Type | Notes |
|---|---|---|
| `id` | `fd-` + 16 hex | deterministic: check, resource, qualifiers |
| `check_id`, `title` | string | |
| `resource` | object | `id` (required), `name`, `type`, `region`, `account` |
| `severity` | `{base, contextual}` | info/low/medium/high/critical; contextual is raised on a path, lowered when off every path |
| `confidence` | 0–1 | |
| `status` | open/resolved/accepted | `accepted_reason` when accepted |
| `diff` | new/unchanged/regressed/resolved/not_rechecked | |
| `evidence` | list | `source` (the API call or detector), `resource`, `detail` |
| `gaps`, `on_paths`, `qualifiers`, `references` | | `on_paths` = path ids |
| `remediation` | object | `summary` (required), `cli`, `terraform` |
| `cve` | null or object | tier 2: `id` (CVE-…, GHSA-…, ALAS…), `package`, `installed_version`, `fixed_version`, `cvss` (0–10 or null), `source` (inspector/osv/ssm-patch/ecr), and `ids` when one finding covers several CVEs in one package (`cve.inspector`, since 0.1.2): every id, with `id` the worst, `cvss` the highest and `fixed_version` the version that clears all fixed ones |
| `secret` | null or object | tier 1 / repos: `detector`, `fingerprint` (`sha256:` + 12 hex, salted), `preview` (≤ 12 chars, masked), `location`. **A value can't validate here**, by design (R5.1) |

All outputs are sensitive: they describe an account's weak points.
