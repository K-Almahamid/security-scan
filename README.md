# Security Scan

Security Scan is a local, read-only security scanning workflow for application
repositories. It profiles a target, runs the checks that apply, and writes
normalized findings and reports.

It is for developers and reviewers who want a repeatable baseline from the
command line or from Cursor. A standard scan uses deterministic tools. An
optional source-level audit is a separate Cursor workflow: an agent investigates
the source, and the CLI only validates and attaches the artifact that agent
produces.

The scan reads application code and writes its report into the target
repository. It does not change application source, install the target's
dependencies, start the target, or apply fixes.

A finished scan is a record of the checks that ran. It is not a statement that
every vulnerability was found.

## Architecture

```text
User
  → Cursor Skill (workflow instructions)
    → Security Scan CLI (deterministic orchestration)
      → Trivy, Semgrep CE, and applicable Dart checks
        → normalized findings and reports in the target repository
```

- The [Cursor Skills](#cursor-skills) tell Cursor when to run a workflow and how
  to read the result. They do not replace the CLI.
- The CLI profiles the repository, plans checks, runs adapters, and writes the
  report. `security-scan scan --mode standard` is the only scan mode
  implemented.
- Trivy and Semgrep CE run in separate containers. `dart analyze` runs on the
  host only when a Dart workspace is already resolved.
- Reports are written into the target repository, under `security-reports/` by
  default.
- [GitHub](https://github.com/K-Almahamid/security-scan) hosts this source
  repository and its [verification workflow](.github/workflows/verify.yml). A
  push does not scan your application. Scans run on the machine where you
  invoke the CLI.

The optional source audit is outside that chain. Cursor runs the upstream
Cloudflare hunting methodology. The CLI validates, imports, and attaches the
resulting `findings.json`. It does not launch those agents.

## Requirements

- Node.js 20 or newer (the CLI is built from this repository)
- Docker with Compose v2 (`docker compose version` must succeed)
- Optional: a Dart SDK on `PATH` when you want `dart analyze`

The verification workflow runs on Ubuntu with Node.js 22. This repository does
not publish platform-specific binaries.

Trivy and Semgrep images are pinned in
[compose/security-scan.compose.yml](compose/security-scan.compose.yml). The
first scan needs network access to pull those images and, unless you pass
`--offline`, to refresh Trivy data and Semgrep registry rules.

## Quick start

This package is `"private": true` and is not published to npm. The package name
is `@local/security-scan`. Do not use `npx security-scan`.

Clone the repository, install its dependencies, build `dist/cli.js`, and link
that local binary onto your `PATH`. The Cursor skill expects a `security-scan`
command.

```bash
git clone https://github.com/K-Almahamid/security-scan.git
cd security-scan
npm ci
npm run build
npm link
security-scan --help
```

`npm link` points `security-scan` at this clone's `dist/cli.js`. It is a local
link, not a registry install. After you pull or edit CLI source, run
`npm run build` again. The existing link keeps using `dist/cli.js`.

Without linking, the same binary is:

```bash
node dist/cli.js --help
```

Profile a target, then run a standard scan. Both commands take an absolute
repository path. The CLI resolves that path and refuses a path that is not a
directory.

```bash
security-scan profile --repo /absolute/path/to/repository
security-scan scan --repo /absolute/path/to/repository --mode standard
```

`profile` prints the repository profile and scan plan as JSON. It does not
write a report. `scan` writes the report directory and prints a short JSON
summary, including the `report.md` path.

### Development setup

Use the same clone, install, and build as above. Development checks are
separate from installing the CLI:

```bash
npm run verify
npm run test:containers
```

`npm run verify` runs the test suite, the vendored Cloudflare validator tests,
the type checker, the linter, and the build. `npm run test:containers` rebuilds
and runs a standard scan of **this** repository. It is an opt-in Docker and
network smoke test.

Individual scripts are `npm test`, `npm run test:cloudflare-validators`,
`npm run typecheck`, `npm run lint`, and `npm run build`.

## Cursor Skills

Both skills live in this repository and set `disable-model-invocation: true`.
Cursor does not start them on its own. Invoke the skill when you want that
workflow. Neither skill edits the target or remediates findings.

| Skill | File |
| --- | --- |
| `security-scan` | [skill/security-scan/SKILL.md](skill/security-scan/SKILL.md) |
| `security-scan-source-audit` | [skill/security-scan-source-audit/SKILL.md](skill/security-scan-source-audit/SKILL.md) |

### `security-scan`

Manual standard-scan workflow.

- **Use it** at the end of development, when you want the deterministic baseline.
- **It invokes** `security-scan scan --repo "<absolute-repository-path>" --mode standard`,
  plus safe options you asked for (`--offline`, `--fail-on`, `--reports-dir`).
- **Prerequisites:** `security-scan` on `PATH`, plus the [scan requirements](#requirements).
  If the command is missing, the skill stops.
- **Output:** the skill reads `scan-manifest.json`, `findings.json`, and
  `report.md`, preserves the CLI exit code, and summarizes status, coverage,
  findings, and failures.
- **Limitations:** it does not launch the Cloudflare audit, request a remote
  target, run DAST, install dependencies, or change application code.

### `security-scan-source-audit`

Optional, separate source-level audit. The agent follows the upstream
[Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill).
The CLI does not run those hunting agents.

- **Use it** when you explicitly want a full source audit, trust-boundary
  mapping, coverage-led investigation, or the Cloudflare methodology. Routine
  baselines stay on `security-scan`.
- **What runs where:**
  1. Cursor performs the source-level audit and writes a Cloudflare-format
     `findings.json`.
  2. `security-scan audit validate` checks that file.
  3. `security-scan audit attach` merges importable records into an existing
     scan report.
- **Prerequisites:** the upstream `security-audit` skill, and `security-scan`
  on `PATH`. A standard scan first is recommended so you have a report
  directory to attach to.
- **Output:** a validated `findings.json` from the agent, then an updated scan
  report. `attach` writes `source-audit-records.json` and refreshes
  `findings.json`, `scan-manifest.json`, and `report.md`.
- **Limitations:** the audit is agentic, not a reproducible scanner run.
  Attachment does not execute repository code and is not a sandbox. Completing
  a hunt is not comprehensive coverage. The skill does not scan production or
  external targets and does not auto-remediate.

Verdicts on each audit record:

- `confirmed` — imported into the normalized findings.
- `needs_validation` — imported as an unconfirmed candidate. Severity is
  `unknown`, and the evidence records that decisive validation was not
  established.
- `rejected` — counted and stored in `source-audit-records.json`. Rejected
  records are not promoted into `findings.json`.

`audit attach` fails if Cloudflare schema validation fails. Paths that escape
the repository, including symlink escapes, are rejected.

### Install this repository's skills

[scripts/sync-cursor-skills.sh](scripts/sync-cursor-skills.sh) **copies** the
two `SKILL.md` files. It does not symlink them, watch for edits, or install the
Cloudflare skill.

```bash
./scripts/sync-cursor-skills.sh
```

Copies land at:

- `~/.cursor/skills/security-scan/SKILL.md`
- `~/.cursor/skills/security-scan-source-audit/SKILL.md`

After you edit the copies under `skill/`, run the script again. It overwrites
the installed files. The script does not restart Cursor.

### Install the upstream Cloudflare skill

Install this separately from the sync script. The upstream repository is the
source of hunting prompts and safety rules:

```bash
npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
```

Validators vendored for `security-scan audit validate` live in
[third-party/cloudflare-security-audit/](third-party/cloudflare-security-audit/NOTICE.md)
(MIT, commit pinned in
[UPSTREAM_COMMIT](third-party/cloudflare-security-audit/UPSTREAM_COMMIT)).
Those files do not perform the hunt.

## Commands

```bash
security-scan --help
security-scan version

security-scan profile --repo /absolute/path/to/repository
security-scan validate-config --repo /absolute/path/to/repository
security-scan scan --repo /absolute/path/to/repository --mode standard

security-scan audit validate --repo /absolute/path/to/repository --findings /path/to/findings.json
security-scan audit import --repo /absolute/path/to/repository --findings /path/to/findings.json
security-scan audit attach --repo /absolute/path/to/repository --scan-dir security-reports/<scan-id> --findings /path/to/findings.json
```

`profile` prints `{ profile, plan }` as JSON. `--json` is accepted and does not
change that output.

`validate-config` loads `.security-scan.json`, or `--config`, and prints that
the configuration is valid. It does not scan.

`scan` accepts only `--mode standard`. Any other mode exits `3`.

`audit validate` checks `findings.json` against the vendored Cloudflare report
schema. `audit import` validates, then prints importable findings, rejected
records, and verdict counts. It does not write a report. `audit attach` requires
an existing report directory. `--scan-dir` may be absolute or relative to
`--repo`. Audit paths that contain `..` or start with `~` are rejected.

### Scan options

```text
--config <path>         Explicit JSON configuration file
--reports-dir <path>    Report directory inside the target repository
--offline               Cached Trivy data; no Semgrep registry packs
--jobs <n>              Concurrent adapters (default 2, clamped to 8)
--timeout <20m>         Per-adapter timeout (default 20m; also 30s, 5000ms, or milliseconds)
--keep-raw              Copy redacted raw output into the report directory
--fail-on <severity>    Finding threshold for exit code 1
```

`--fail-on` is `critical`, `high`, `medium`, `low`, or `info`. The default is
`high`.

`--offline` passes `--skip-db-update` and `--offline-scan` to Trivy. Semgrep
does not load `p/default` or `p/security-audit` in offline mode. A Semgrep
adapter that is not using the bundled Flutter rules fails its prerequisite with
"Semgrep registry rules are unavailable in offline mode".

### Exit codes

- `0`: complete, and no finding is at or above the severity threshold
- `1`: complete, with at least one finding at or above the threshold
- `2`: incomplete because a required scanner failed or timed out
- `3`: invalid configuration, unsafe path, unknown command, or scope error
- `4`: internal orchestration error

Semgrep's process exit code `1` means the tool found results. Security Scan
treats that, together with a valid results document, as a completed tool run.
It does not treat it as a scanner failure. Exit codes `2` and above, a timeout,
or a JSON document that is not the scanner's result document fail the tool. A
failed tool does not contribute findings and cannot make the scan exit `0`.

`policy.allowFailedTools` must be `false`. Setting it to `true` is a
configuration error. Incomplete execution is never reported as a successful
scan.

`audit attach` exits `0` after a successful attachment. Validation and scope
failures still use `3` (or `4` for an unexpected orchestration error).

## Configuration

Configuration is optional. Place `.security-scan.json` in the target root.
The schema is [schemas/config.schema.json](schemas/config.schema.json). `$schema`
is optional; the example uses a placeholder path to that file.

```json
{
  "$schema": "/absolute/path/to/security-scan/schemas/config.schema.json",
  "version": 1,
  "reportsDir": "security-reports",
  "exclude": [
    "**/node_modules/**",
    "**/.venv/**",
    "**/.next/**",
    "**/dist/**"
  ],
  "tools": {
    "trivy": { "enabled": true, "offline": false },
    "semgrep": { "enabled": true },
    "dartAnalyze": { "enabled": "auto" }
  },
  "policy": {
    "failOn": "high",
    "allowFailedTools": false
  }
}
```

`reportsDir` must stay inside the target repository. `enabled` is `true`,
`false`, or `"auto"`. An explicit `exclude` array replaces the default
(`**/node_modules/**`, `**/.venv/**`, `**/.next/**`, `**/dist/**`). Optional
`components` entries are repository-relative paths and cannot contain `..`.

Credential-like configuration keys are rejected (`password`, `secret`, `token`,
`apiKey`, `credential`, `authorization`, and similar names). The scanner does
not read an application `.env` file into its process environment. Host
environment variables passed to tool processes are allowlisted (`PATH`, `HOME`,
`USER`, `TMPDIR`, `DOCKER_HOST`, `DOCKER_CONTEXT`, `XDG_CONFIG_HOME`,
`XDG_CACHE_HOME`).

## Reports

A standard scan writes:

```text
<target>/security-reports/<scan-id>/
├── report.md
├── findings.json
├── scan-manifest.json
├── profile.json
└── scan-plan.json
```

`<scan-id>` is a timestamp plus the short Git revision, or `nogit` when that
revision cannot be read.

`audit attach` also writes `source-audit-records.json` in that directory: the
audit records as submitted, including rejected ones. It rewrites
`findings.json`, `scan-manifest.json`, and `report.md`.

| File | Role |
| --- | --- |
| `report.md` | Human-readable summary: status, counts, findings, skipped checks, and limitations |
| `findings.json` | Normalized findings. Schema: [schemas/finding.schema.json](schemas/finding.schema.json) |
| `scan-manifest.json` | Scan identity, tool runs, execution, coverage, and report paths. Schema: [schemas/manifest.schema.json](schemas/manifest.schema.json) |
| `profile.json` | Repository profile used to build the plan |
| `scan-plan.json` | Planned tools, supported checks, out-of-scope checks, and unsupported combinations |
| `source-audit-records.json` | Original Cloudflare audit records, only after `audit attach` |

Normalized reports are the files above. Raw scanner output stays outside Git:

```text
~/.cache/security-scan/<repository-hash>/<scan-id>/raw/
```

`--keep-raw` copies a redacted form of that output to
`<report-directory>/raw/`. Raw artifacts can contain source evidence. Treat
them as confidential.

Normalized evidence is redacted and truncated before it is stored. Redaction
covers common token shapes and assignment-style secrets. It does not remove
every sensitive path, package version, endpoint, or internal name. Review a
report before committing it. This repository ignores `security-reports/` in
[.gitignore](.gitignore). A target repository is not modified to add that
ignore rule. If a report is too sensitive to commit, keep `security-reports/`
out of Git and share it through a channel you trust.

### Report semantics

Manifest schema version 2 keeps the version 1 `coverageGaps` field and adds
`execution` and `coverage`:

- `execution` records planned, completed, failed, skipped, and unsupported tool
  runs separately from finding severity.
- `coverage.plannedStatus` states whether every planned check completed.
- `coverage.supportedChecks`, `outOfScope`, and `unsupported` describe the
  baseline boundary. `coverage.comprehensive` is always `false` in standard
  mode.

Canonical findings keep per-tool severity, confidence, location, and sanitized
evidence on each source record. Exact cross-tool duplicates may be
consolidated. Related sink-level findings share `relatedGroupId` and stay
separate. Dependency findings confirm package presence and set reachability to
`not_analyzed`. Advisory text from the scanner is not treated as an independent
check against the publisher (`publisherVerification` is `not_performed`).

## Isolation and credential handling

- The repository is mounted read-only at `/src` in the Trivy and Semgrep
  containers.
- Only the raw output directory is writable inside those containers.
- Scanner containers receive no Docker socket and are not privileged.
- Capabilities are dropped and `no-new-privileges` is set.
- Tool images are pinned by version and digest.
- `dart analyze` runs only when `.dart_tool/package_config.json` already exists.
  The scanner never runs `dart pub get`, Flutter builds, or build runners.

Standard mode accepts no remote target. Future ZAP or Strix adapters would need
a separate authorization and scope gate. They are not implemented. Source-audit
commands validate and attach records. They do not execute the target.

Symlinks whose targets resolve outside the repository fail the scan before a
tool starts. The profiler does not follow symlinks. Directories ignored while
profiling (`.git`, `node_modules`, `.next`, `.venv`, `dist`, `build`,
`coverage`, `security-reports`) are not walked again for that symlink check.
Scanner skip rules do not guarantee that a tool will refuse every link inside
those directories.

## Coverage limitations

Standard mode runs the checks it can plan:

- repository dependency, secret, and misconfiguration analysis (Trivy)
- Semgrep CE for Dart, Python, TypeScript, JavaScript, Go, Java, and Kotlin,
  plus bundled Flutter rules when Dart is present
- `dart analyze` when a resolved Dart workspace and the Dart SDK are already
  available

The same mode records these as out of scope:

- DAST and arbitrary remote-target scanning
- active exploitation
- authenticated runtime testing against local, staging, or production
- comprehensive mobile testing such as MobSF or a full MASVS review
- built container-image and runtime OS package scanning

Flutter coverage here is static. It does not replace MobSF or a MASVS review.
A language with no configured Semgrep coverage is recorded as unsupported, not
as a pass.

Failed, skipped, and unsupported checks are recorded separately and are never
treated as passing. An empty `coverageGaps` or `coverage.unsupported` array is
not evidence of comprehensive coverage. `coverage.comprehensive` is always
`false` in standard mode.

Pinned Trivy `0.67.2` flagged `USER root` as `DS002` and a synthetic `ghp_`
canary as `github-pat` in the project's detection tests. The same probe did not
emit a misconfiguration for `privileged: true` in `docker-compose.yml`. Compose
files are still planned and scanned; that specific control is not claimed as
detected.

## Validation

`npm run verify` runs the deterministic test suite, the vendored Cloudflare
validator tests, the type checker, the linter, and the build. Scanner detection
tests call the pinned Trivy and Semgrep images when Docker Compose is
available. Set `SECURITY_SCAN_REQUIRE_DOCKER=1` to fail instead of skipping
those tests. They need network access the first time the images or Trivy's
misconfiguration bundle are downloaded. Dart analyzer detection runs only when
`dart` is already on `PATH`. The test harness may run `dart pub get`. The
scanner still does not.

What those tests prove:

- **Scanner detection:** pinned Semgrep with the bundled Flutter rules and with
  repository fixture rules; pinned Trivy secret and Dockerfile misconfiguration
  rules; `dart analyze` machine output when a resolved workspace already exists.
- **Adapter parsing:** canned Trivy, Semgrep, and Dart documents, including a
  Semgrep exit code of `1`.
- **These are not vulnerability-database tests.** Dependency CVE detection is
  covered by parsing a fixed Trivy document. Advisory contents change and are
  not treated as a deterministic oracle.
- **A fixture rule match is not Semgrep registry coverage.** `p/default` and
  `p/security-audit` require network and upstream rule updates, so the
  deterministic source tests use local rules.
- **Clean fixtures** assert the targeted rule identity and path. They do not
  assert that a scanner's entire rule pack is silent. Trivy may still report
  other Dockerfile checks, such as a missing `HEALTHCHECK`.

GitHub Actions runs `npm run verify` on Ubuntu with Node.js 22 and
`SECURITY_SCAN_REQUIRE_DOCKER=1`. See
[.github/workflows/verify.yml](.github/workflows/verify.yml).

## License

[Apache License 2.0](LICENSE).

The vendored Cloudflare validators are MIT. See
[third-party/cloudflare-security-audit/NOTICE.md](third-party/cloudflare-security-audit/NOTICE.md)
and the upstream
[security-audit-skill](https://github.com/cloudflare/security-audit-skill)
repository.
