---
name: security-scan
description: Runs a repository-wide, multi-tool security baseline with Trivy, Semgrep CE, and applicable Dart checks, then summarizes normalized findings, execution completeness, and bounded coverage. Use only when the user manually invokes Security Scan at the end of development.
disable-model-invocation: true
---

# Security Scan

Run the local Security Scan CLI against the repository the user names or the
current Git repository.

## Workflow

1. Resolve the target to an absolute repository path. Never assume the CLI
   installation directory is the target.
2. Confirm `security-scan` is available on `PATH`. If it is missing, stop and
   report that the local engine is not installed.
3. Run:

   ```bash
   security-scan scan --repo "<absolute-repository-path>" --mode standard
   ```

   Add user-requested safe options such as `--offline`, `--fail-on`, or
   `--reports-dir`. Do not add remote targets or credentials.
4. Preserve and interpret the exit code:
   - `0`: complete below threshold
   - `1`: complete with findings at/above threshold
   - `2`: incomplete because a required scanner failed
   - `3`: configuration or scope error
   - `4`: orchestrator error
5. Read the generated `scan-manifest.json`, `findings.json`, and `report.md`.
6. Summarize:
   - overall status, execution completeness, and planned coverage separately;
   - supported checks, explicitly out-of-scope checks, and unsupported combinations;
   - findings by severity;
   - highest-priority findings with locations;
   - consolidated duplicate sources and related root-cause groups;
   - dependency presence separately from reachability, which standard mode does not analyze;
   - failed, skipped, and unsupported checks;
   - report path and recommended next steps.

## Safety requirements

- Never interpret failed, skipped, or unsupported checks as passing.
- Never describe completed planned scans as comprehensive security coverage.
- Never claim a vulnerable dependency is reachable unless a separate implemented
  reachability analysis actually established it. Preserve advisory severity.
- Never run project installs, builds, tests, lifecycle scripts, or application
  servers as part of standard mode.
- Never request or pass production credentials.
- Never run ZAP, Strix, active DAST, or any remote-target scan from this skill.
  Those require a separate user-approved deep-testing workflow and explicit
  authorized scope.
- Never modify application code or automatically remediate findings. Offer a
  separate user-approved remediation workflow.
- Do not print raw secret evidence. Use only redacted normalized findings.
- Do not commit reports or raw artifacts unless the user explicitly requests it
  after reviewing their sensitivity.

## Optional source-level audit (separate skill)

The deterministic CLI does **not** run Cloudflare-style multi-agent hunting.
When the user explicitly requests a full source audit, architecture review with
trust boundaries, or coverage-led investigation, switch to the companion skill
`security-scan-source-audit` and the upstream
[Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill).

After an agent produces `findings.json`, validate and attach with:

```bash
security-scan audit validate --repo "<absolute-repository-path>" --findings "<path>"
security-scan audit attach --repo "<absolute-repository-path>" --scan-dir "<report-dir>" --findings "<path>"
```

Never describe the agentic audit as a deterministic CLI scan.

## Final response

Lead with one of: `complete`, `complete with findings`, or `incomplete`.
Include the report path. For findings, use a compact severity/location/title
list. Always state execution completeness, planned coverage, out-of-scope
checks, unsupported combinations, and scanner failures.
