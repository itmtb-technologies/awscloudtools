# Changelog

## 0.1.5 (2026-10-30)

### Security (detailed review 2026-10-30)
- **A scanned repo could hide its own secrets.** gitleaks obeyed a `.gitleaks.toml`,
  `.gitleaksignore` or `gitleaks:allow` comment inside the repo (a committed allowlist turned
  1 found secret into 0). The repo scan now uses gitleaks' default rules, ignores the repo's
  own suppressions, reads history from a mirror clone, and reports any suppression it found
  as an info finding.
- **No secret value touches disk during a repo scan.** gitleaks' report now comes back on
  stdout instead of a temp file.
- **The read-only guard allows only operations a check declares.** A read-looking name is no
  longer enough; an undeclared call is refused before it leaves the process.
- **Terminal output strips control characters**, so a resource name from the scanned account
  can't drive your terminal.
- **S3 output names the bucket owner on every call**: your own account, or
  `CLOUDTOOLS_S3_BUCKET_OWNER`. A mistyped or someone else's bucket is refused by AWS.
- **`run.jsonl` is created 0600** like every other output.
- **The `serve` extra requires `starlette>=1.3.1`** (older versions have published advisories;
  none affected the features cloudtools uses).
- **CI runs only pinned code:** actions by commit, gitleaks by checksum.

### Fixed
- **No run log was kept for `s3://` output.** It is now written to the bucket with the report.
- **`cloudtools serve` records every request**, allowed or refused, without the token.
- **CloudTrail log validation was reported twice** (once per check); now once.
- **Amplify-hosted domains were reported as dangling DNS.** Their CloudFront names are now
  read from Amplify (`amplify:ListApps`, `amplify:ListDomainAssociations`).

## 0.1.4 (2026-10-30)

### Added
- **`DISCLAIMER.md`**, summarised at the top of the README: the checks are not a complete
  security assessment, and responsibility for complete checks stays with you.

### Changed
- `CLOUDTOOLS_PLATFORM` takes `standalone` (the default) or `<module>:<Class>` for a platform
  supplied from outside this package.
- Removed two install extras used only by a hosted deployment, and code comments about it.

### Fixed
- **`security doctor` pointed at a CloudFormation template that doesn't exist.** Its fixes
  are now: managed policies, the generated least-privilege policy, or a message for your
  AWS admin.

### Security (review 2026-10-30)
- **`cloudtools serve` could be driven by a web page.** A page you visited could start a scan
  with your AWS credentials and, by DNS rebinding, read every finding. It now answers only
  its own Host and only requests carrying the token it prints at start (or
  `CLOUDTOOLS_SERVE_TOKEN`). **Breaking for HTTP clients:** send `Authorization: Bearer <token>`.
- A run id with `..` could read a `status.json` or `report.json` outside the output folder.
  Store keys are now confined to it.
- CSV export: a cell starting with `= + - @` (e.g. a security group named like a formula)
  is prefixed with `'`, so a spreadsheet shows it rather than running it.
- The read-only guard now refuses, by name, calls that look like reads but mint
  credentials or read data (`cognito-identity:GetId`, `dynamodb:GetItem`, …). No check called one.
- Hosted: `profile` must be a built-in name, not a file path.

## 0.1.3 (2026-10-29)

### Added
- `cloudtools --version`.
- README: install straight from the public repository with `pipx` or `pip`.

## 0.1.2 (2026-10-29)

### Verified
- **Live lab** in a sandbox account (`infra/lab/`, scored by `tools/lab_score.py`):
  - tier 0: 11/11 known misconfigurations found;
  - tier 1: 14/14;
  - tier 2: 17/17;
  - 0 findings on any hardened twin;
  - run logs show reads only;
  - no planted secret value in any output;
  - after teardown, a re-scan resolved every lab finding (Inspector's came back
    `not_rechecked`, since Inspector was off).

### Fixed
- **`cve update-db` failed TLS** on python.org builds of Python. All downloads now use
  botocore's CA bundle (`core/tls.py`).
- **Tier 2 hung on a large OSV copy.** The loader now parses only the records for installed
  packages and keeps only the installed versions: 3.9 GB → 180 MB on the lab.
- **Kernel false positives in offline CVE matching:**
  - SSM's binary names (`linux-aws`) collided with an unrelated OSV kernel source package;
  - kernels are now left to Inspector, with a gap where Inspector doesn't cover the host;
  - 2,466 false CVEs removed from one host.
- **0.1.1 installs were missing their data files** (`security/data/*.json`), so `srv.os-end-of-life`
  and offline CVE matching failed outside a source checkout. They're now packaged, and a
  test builds a wheel to check.
- **Deleted IAM users were still reported** (`iam.user-no-mfa`, `iam.access-key-age`,
  `iam.unused-user-live-keys`). AWS serves a credential report up to 4 hours old; rows for
  users no longer in the account are now dropped.
- **On Windows, reading a scan's status while it was rewritten could fail** with
  `PermissionError` (the file is briefly locked during the swap). Reads and writes
  now retry for up to half a second.
- **`summary.diff.resolved` was always 0;** it now matches `summary.resolved`.
- **`infra/lab/down.sh` reported deleted resources as left over,** trusting the tagging
  index; it now confirms each one with EC2.

### Changed
- **Inspector findings are grouped by package.** `cve.inspector` now makes one finding per
  package on each resource, not one per CVE: the lab's old host went from 4,222 findings to
  152. The finding carries every CVE id (`cve.ids`, a new optional report field), the worst
  CVE's severity and CVSS, and the version that clears the fixed ones. Finding ids change,
  so the first scan after upgrading shows the old per-CVE findings as resolved and the
  grouped ones as new.
- **No local MCP server.** The unused `mcp` extra is gone.

## 0.1.1 (2026-10-28)

Verified on Windows. No new features.

### Verified
- **CI is green on Windows, Ubuntu and macOS, each with Python 3.11 and 3.12:** 331 passed
  and 9 skipped per job, plus a clean secret scan of the full history (run 40642932742 on
  `93152f4`).
- **The 9 skipped tests are skipped on every platform:** gitleaks and other optional
  dependencies aren't installed on CI. They pass locally.

### Fixed
- **Windows: the run log could tear.** Collectors log from a thread pool, and Windows doesn't
  make small file appends atomic, so `run.jsonl` could get a broken line. `RunLog.emit` is now
  serialised with a lock.
- **CI installs the `serve` extra.** The HTTP tests need FastAPI. Without it every job
  stopped at collection, so the first CI run tested nothing.
- **`tools/check_public.py` no longer flags its own source,** whose patterns spell what they
  look for.
- **Test harness: the import-isolation test's subprocess keeps `SYSTEMROOT`/`WINDIR`.** Without
  them, Windows can't load asyncio's socket layer (`WinError 10106`).

### Still not verified
- **Live AWS from a Windows machine:** CI runs offline, with moto and recorded data.
- **Tier 2 against live data,** and **lab precision/recall** (as in 0.1.0).

## 0.1.0 (2026-10-28)

First release. It scans an AWS account read-only, with your own credentials.

### What it does
- **61 checks**, in three opt-in tiers:
  - **tier 0 (posture):** network reachability, servers, IAM, public data, encryption, logging;
  - **tier 1 (`--tier 1`):** secrets in AWS configuration (Lambda env and code, EC2 user data,
    ECS, CloudFormation, CodeBuild, plain SSM parameters);
  - **tier 2 (`--tier 2`):** vulnerable software (Inspector, SSM patch compliance, SSM
    inventory against an offline OSV copy, OS end-of-life).
- **Attack graph:** paths from entry points (the internet, outside accounts, leaked keys) to
  admin and sensitive data. Severity is raised on a path and lowered off every path. The
  fixes are ranked by the paths each breaks, and there's a what-if.
- **Credentials:** IAM keys, every account AWS can list (Identity Center, database master
  users, cache, MQ and SFTP users, key pairs, secret and parameter names; Cognito counted,
  never listed), and an optional local repo scan (`--repo`, needs gitleaks).
- **Outputs:** terminal, HTML, JSON (schema v1, `docs/REPORT_SCHEMA.md`), SARIF, CSV. Each
  run is compared with the last: new, unchanged, regressed, resolved, not re-checked.
- **Front doors:** the CLI, `cloudtools call <capability>`, a local HTTP API
  (`cloudtools serve`), and async scans with `get_run_status`.

### Safety
- **Reads only.** A guard refuses every non-read AWS call, and secret values are never
  read at any tier (`GetSecretValue`, decrypted parameters, `kms:Decrypt`, `s3:GetObject`).
- **No secret value is stored or logged.** Secrets are kept as salted fingerprints with a
  masked preview.

### Verified
- **Tests:** 397; deliberate breaks of each part caught.
- **Live, read-only, on one production account (17 regions, tiers 0+1+2):**
  - 2,251 calls, all reads;
  - 43 of 43 Lambda code packages scanned;
  - no secret value in any output.
- **Clean install** from a fresh clone; every README command run.
- **Tested with:** Python 3.12.10 on macOS; boto3 1.43.120, networkx 3.7, PyYAML 6.0.3,
  jsonschema 4.26.0, fastapi 0.162.0 / starlette 1.10.0, moto 5.2.5, pytest 9.2.0.

### Not yet verified
- **Windows and Python 3.11:** the CI matrix (ubuntu/macos/windows × 3.11/3.12) is written but
  has not run, since there's no remote yet.
- **Tier 2 against live data:** tested on recorded Inspector/SSM data only. The live account
  had both services off and reported them as gaps.
- **Precision/recall on a seeded lab account:** needs a sandbox account.

### Known limits
In short (the README lists them all):
- **IAM:** permission boundaries and SCPs aren't evaluated.
- **Tier-1 code scanning:** uses named secret formats only. A format-less secret
  hard-coded in source is missed.
- **Not built yet:** tier 2b (snapshot scanning), tier 3 (data sampling), external probing,
  multi-account.
- **Not planned:** a local MCP server.
