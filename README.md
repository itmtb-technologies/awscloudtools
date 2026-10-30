# cloudtools

Read-only security scanning for an AWS account, run with your own credentials.

It finds misconfigurations, then works out which ones chain together into a real attack
path, for example *internet → public function → its role → full account control*. It
ranks the fixes that break the most paths. It also lists who and what can sign in:
IAM keys, database master users, cache users, SSH key pairs, and the names of stored
secrets. Optionally it scans your local git repos for committed secrets and tells you
which leaked AWS keys are still live.

> **Not a complete security assessment.** Results cover only the checks this tool runs, as
> far as your credentials can see, at the time of the scan. A clean result does not mean the
> account is secure, and you remain responsible for complete security checks. See
> [DISCLAIMER.md](DISCLAIMER.md).

**It never changes anything in your account.** Every AWS call passes through a guard
that refuses anything except reads, and it never reads data or secret values.

## Install

Needs Python 3.11 or newer and AWS credentials (a profile, SSO, or environment variables).

```bash
pipx install "git+https://github.com/itmtb-technologies/awscloudtools.git@v0.1.6"
cloudtools --version
```

No pipx? A venv does the same:

```bash
python3 -m venv ~/.cloudtools
~/.cloudtools/bin/pip install "git+https://github.com/itmtb-technologies/awscloudtools.git@v0.1.6"
```

From a clone (to change the code): `pip install .` in a venv, or `pip install '.[dev]'` for the tests.

Optional: `brew install gitleaks` (or see [gitleaks](https://github.com/gitleaks/gitleaks)),
only if you want to scan local repos for secrets.

## First run (about 2 minutes)

```bash
aws sso login --profile my-profile          # or however you normally sign in

# 1. Can the scanner see everything it needs? (under 60 s, read-only)
cloudtools security doctor --aws-profile my-profile --region ap-south-1

# 2. Scan one region
cloudtools security scan --aws-profile my-profile --region ap-south-1 --regions ap-south-1

# 3. Open the report: the scan prints its path (html: reports/runs/<run_id>/report.html)
open reports/runs/<run_id>/report.html      # macOS; or open it in any browser
```

Leave out `--regions` to scan every enabled region (around a minute and a half for 17 regions).

The terminal prints a summary, the top fixes and the new findings. Everything is also
written to disk:

```
reports/
  runs/<run_id>/
    report.html      read this first
    report.json      everything, machine-readable
    snapshot.json    the raw read-only data the checks ran on
    run.jsonl        every AWS call made, with outcome and timing
    report.sarif     with --profile full or ci
    findings.csv     with --profile full
  runs/latest-security.json
```

> **Reports are sensitive.** They describe the weak points of an account. Keep them like a
> credential, and don't commit them (`reports/` is in `.gitignore`).

## What you get

- **Findings.** 61 checks across network, server, identity, data, logging, secrets and
  vulnerabilities, in three opt-in tiers (below).
  Each finding carries evidence (the API call and resource) and a fix.
- **Attack paths.** Findings joined into chains from an entry point (the internet, a
  leaked key) to something that matters (admin access, a sensitive data store). A
  finding on a path is raised one severity level.
- **Top fixes.** The fixes ranked by how many paths each one breaks.
- **Accounts.** Who and what can sign in, as far as AWS APIs show (see below).
- **Gaps.** Anything the scanner couldn't read is listed as a gap, never as a pass.
- **Diff.** Each run is compared with the previous one: `new`, `unchanged`, `regressed`,
  `resolved`. A finding counts as resolved only if its check ran fully again;
  otherwise it is reported as `not re-checked`.

## Commands

```bash
cloudtools security scan      # full scan; see the options below
cloudtools security run net.open-admin-ports   # one check, e.g. after a fix
cloudtools security evaluate --snapshot reports/runs/<id>/snapshot.json  # re-run checks, zero AWS calls
cloudtools security doctor    # what's readable, what's blocked, what to grant
cloudtools security policy --write ./policy    # least-privilege IAM policy + a note for your admin
cloudtools security checks    # list all checks (--category network|server|identity|data|logging|secrets)
cloudtools capabilities       # every capability below
cloudtools serve              # the same capabilities as a local HTTP API (needs: pip install '.[serve]')
```

`cloudtools serve` prints a token at start. Send it on every request, as
`Authorization: Bearer <token>`, to `http://127.0.0.1:8765` or `http://localhost:8765`; it
answers nothing else, so a web page you visit can't use it. Set `CLOUDTOOLS_SERVE_TOKEN` to
choose the token yourself. Every request, allowed or refused, is recorded (method, path,
status; never the token or query string) in `runs/http/run.jsonl` under the output folder.

Common options:

| Option | Meaning |
|---|---|
| `--aws-profile NAME` | AWS profile (default: the normal credential chain) |
| `--region R` | home region for global services (default: the profile's) |
| `--regions a,b` | regions to scan (default: all enabled) |
| `--profile quick\|full\|ci\|file.yaml` | which checks and outputs (default `quick`) |
| `--out DIR` or `s3://bucket/prefix` | where reports go (default `./reports`). For S3 the bucket must be in your own account; for a central bucket in another account set `CLOUDTOOLS_S3_BUCKET_OWNER=<account id>` |
| `--tier 0\|1\|2` | how deep it looks (default 0; see Tiers) |
| `--repo PATH` | also scan this git repo for secrets; repeat for more repos (needs gitleaks) |
| `-q` / `-v` | quiet / stream the run log to stderr |

### Asking questions of a stored run

Every capability can be called directly; `run_id` defaults to the latest run.

```bash
cloudtools call security.list_findings min_severity=high
cloudtools call security.explain_finding finding_id=fd-...
cloudtools call security.list_paths
cloudtools call security.chokepoints
cloudtools call security.what_if finding_ids=fd-...,fd-...   # which paths a fix removes
cloudtools call security.why_reachable resource=<arn or id>    # every path to one resource
cloudtools call security.find_paths entry=internet target=admin_equivalent
cloudtools call security.scan wait=false                       # start a scan, return at once
cloudtools call security.get_run_status run_id=r-...           # then poll it
cloudtools call cred.accounts                                 # everyone who can sign in
cloudtools call cred.accounts source=rds
cloudtools call cred.inventory leaked_only=true                # keys found in your repos
```

## Tiers: how deep it looks

| Tier | Flag | What it adds | What it reads |
|---|---|---|---|
| 0 | (default) | posture: ports, reachability, IAM, public data, encryption, logging, the attack graph | configuration metadata only |
| 1 | `--tier 1` | secrets sitting in AWS configuration: Lambda env vars and code, EC2 user data, ECS task definitions, CloudFormation templates, CodeBuild, plain SSM parameters | **those contents.** Each secret is kept only as a fingerprint and a masked preview (`sk-p****`). A live AWS key found there becomes an attack-path entry point |
| 2 | `--tier 2` | vulnerable software: Inspector findings, SSM patch compliance, SSM inventory matched against an offline OSV copy, OS end-of-life. A CVE on a host an attack path reaches is raised | Inspector and SSM data; it needs those services on, and says so when they aren't |

`--tier 2` includes tier 1. `security policy --tier N` generates the matching IAM policy.
Secret values (`GetSecretValue`, decrypted parameters, `kms:Decrypt`, `s3:GetObject`) stay
denied at every tier.

For the offline vulnerability database (only the public OSV data is downloaded; nothing about
your account is sent):

```bash
cloudtools cve update-db
```

## Scanning repos for secrets

```bash
cloudtools security scan --aws-profile my-profile --regions ap-south-1 \
  --repo ~/code/api --repo ~/code/web
```

- **What it scans:** each repo's full git history and its working tree, which
  includes `.env` files that git ignores.
- **What it keeps:** for each secret, a salted fingerprint and its location, never
  the value. The salt is created once in `~/.config/cloudtools/salt`.
- **What it reports:**
  - Any AWS access key id it finds is matched against the account's live IAM keys.
    A match that is still active is reported, and becomes an entry point in the
    attack graph.
  - Other secrets are reported per repo.

Large repos can take minutes. A repo that times out is reported as a gap.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing new at or above the profile's `fail_on` (default `high`) |
| 2 / 3 / 4 | the highest **new** finding is medium / high / critical |
| 64 | usage error |
| 65 | no usable AWS credentials |

Use `--profile ci` in a pipeline: JSON and SARIF outputs, and the exit code fails the build.

## Permissions

Run `cloudtools security policy --write ./policy`. You get:

- **An IAM policy** with exactly the read actions the selected checks need.
- **An explicit Deny** on reading data and secrets (`s3:GetObject`,
  `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, …).
- **A short message** to send your AWS admin.

AWS's managed `SecurityAudit` plus `ViewOnlyAccess` cover nearly all of it.
`cloudtools security doctor` shows anything still missing.

## What it can't see

- **OS accounts on servers** (including `authorized_keys`) and **users created inside a
  database**. Both need a command on the host or a database login, which this tool won't do.
- **Cognito user pools:** counted, never listed. They are your customers' end users.
- **IAM permission boundaries, SCPs and session policies** aren't evaluated. Permission
  findings say "possible" for that reason.

## Develop

```bash
pip install '.[dev]'
pytest tests            # offline: moto and recorded snapshots, no AWS account needed
```

To measure the scanner on real AWS, `infra/lab/` deploys a stack of known misconfigurations
with hardened twins into a **sandbox account** (`up.sh`), and `tools/lab_score.py` scores a
scan against `tests/lab/expected.yaml`. `down.sh` removes it and checks nothing is left.

## License

Apache-2.0; see [`LICENSE`](LICENSE).
