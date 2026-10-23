# Security Scan

Local, reusable security scan orchestration for Cursor and command-line use.

The standard scan profiles a repository, selects applicable checks, runs Trivy
and Semgrep CE in separate constrained containers, optionally runs `dart
analyze` against an already-resolved Dart workspace, and writes normalized,
deduplicated reports into the target repository.

It does **not** start the target application, install its dependencies, run
package lifecycle scripts, or attack remote systems.

## Requirements

- Node.js 20+
- Docker with Docker Compose
- Optional: Dart SDK for `dart analyze`

## Development

```bash
npm install
npm run verify
npm run test:containers # opt-in Docker/network smoke test
npm run build
npm link
```

## Commands

```bash
security-scan profile --repo /absolute/path/to/repository
security-scan validate-config --repo /absolute/path/to/repository
security-scan scan --repo /absolute/path/to/repository --mode standard
```

### Optional source-level audit (agentic, not CLI hunting)

The deterministic CLI validates and imports Cloudflare-format `findings.json`
from a Cursor agent run. Install the upstream hunting skill separately:

```bash
npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
```

```bash
security-scan audit validate --repo /absolute/path --findings /path/to/findings.json
security-scan audit import --repo /absolute/path --findings /path/to/findings.json
security-scan audit attach --repo /absolute/path --scan-dir security-reports/<scan-id> --findings /path/to/findings.json
```

See `skill/security-scan-source-audit/SKILL.md` for the Cursor workflow. Vendored
validators live under `third-party/cloudflare-security-audit/` (MIT, pinned commit).

Useful scan options:

```text
--config <path>         Explicit JSON configuration
--reports-dir <path>    Repository-relative report directory
--offline               Require cached scanner data/rules
--jobs <n>              Concurrent adapters (default 2, maximum 8)
--timeout <20m>         Per-adapter timeout
--keep-raw              Copy redacted raw output into the report directory
--fail-on <severity>    Finding threshold for exit code 1
```

Exit codes:

- `0`: complete below the configured severity threshold
- `1`: complete with findings at or above the threshold
- `2`: incomplete because a required scanner failed or timed out
- `3`: invalid configuration or unsafe arguments
- `4`: internal orchestration error

## Configuration

Configuration is optional. Place `.security-scan.json` in the target root:

```json
{
  "$schema": "/path/to/security-scan/schemas/config.schema.json",
  "version": 1,
  "reportsDir": "security-reports",
  "exclude": ["**/node_modules/**", "**/.venv/**"],
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

Credential-like configuration keys are rejected. The scanner never reads an
application `.env` file into its process environment.

## Reports

By default:

```text
<target>/security-reports/<scan-id>/
├── report.md
├── findings.json
├── scan-manifest.json
├── profile.json
└── scan-plan.json
```

Raw scanner artifacts stay outside Git under
`~/.cache/security-scan/<repository-hash>/<scan-id>/raw/`. They may contain
sensitive source evidence and should be handled as confidential. `--keep-raw`
copies a redacted form into the report.

Teams should decide whether normalized reports are committed. If reports may
identify sensitive paths, endpoints, or internal package versions, ignore
`security-reports/` and distribute them through an approved secure channel.

### Report semantics

Manifest schema version 2 retains the version 1 `coverageGaps` field for
consumers that have not migrated, and adds explicit `execution` and `coverage`
objects:

- `execution` records planned, completed, failed, skipped, and unsupported tool
  runs independently from finding severity.
- `coverage.plannedStatus` states whether every planned check completed.
- `coverage.supportedChecks`, `outOfScope`, and `unsupported` describe the
  baseline boundary. `coverage.comprehensive` is always `false` in standard
  mode.

Canonical findings retain per-tool severity, confidence, location, and
sanitized evidence in each source record. Exact cross-tool duplicates may be
consolidated, while related sink-level findings use `relatedGroupId` and remain
separate. Dependency findings confirm package presence but report reachability
as `not_analyzed`; scanner advisory data is not represented as independently
verified against the publisher.

## Isolation

- The repository is mounted read-only at `/src`.
- Only the raw output directory is writable.
- Scanner containers receive no Docker socket and are not privileged.
- Capabilities are dropped and `no-new-privileges` is enabled.
- Tool images are pinned by version and multi-architecture digest.
- Host environment variables are allowlisted.
- `dart analyze` runs only if `.dart_tool/package_config.json` already exists;
  the scanner never runs `dart pub get`, Flutter builds, or build runners.

Standard mode accepts no remote target. Future ZAP or Strix adapters must add a
separate explicit authorization and scope gate.

## Coverage limitations

No automated tool provides complete security assurance. Standard mode
explicitly excludes DAST, active exploitation, authenticated runtime testing,
comprehensive mobile testing, and built-image scanning. Flutter coverage is
static and does not replace MobSF or a MASVS review. Failed, skipped, and
unsupported checks are recorded separately and are never treated as passing.

## Cursor skills

```bash
./scripts/sync-cursor-skills.sh
```

Syncs `security-scan` and `security-scan-source-audit` into `~/.cursor/skills/`.
