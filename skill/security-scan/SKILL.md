---
name: security-scan
description: Runs a full repository security audit with Trivy, Semgrep CE, applicable Dart checks, and the Cloudflare security-audit skill, then attaches validated source-audit findings. Use when the user asks for a full security scan or security audit. Use deterministic-only mode only when the user explicitly asks for the CLI scanners without the Cloudflare source audit.
disable-model-invocation: true
---

# Security Scan

A normal full security audit has three layers:

1. **Trivy** — dependency vulnerabilities, secrets, and supported misconfigurations.
2. **Semgrep CE** — static source analysis, plus `dart analyze` when a resolved Dart workspace already exists.
3. **Cloudflare source audit** — the upstream `security-audit` skill. This is a multi-phase agent workflow. The CLI does not execute it.

`src/workflow.ts` is the status contract. `planSecurityWorkflow("full")` includes `standard-scan`, `cloudflare-source-audit`, and `validate-and-attach`. `planSecurityWorkflow("deterministic-only")` includes only the standard scan.

## Default workflow (full audit)

1. Resolve the target to an absolute repository path. Never assume the CLI installation directory is the target.
2. Confirm `security-scan` is on `PATH`. If it is missing, stop and report that the local engine is not installed.
3. Run the deterministic scan:

   ```bash
   security-scan scan --repo "<absolute-repository-path>" --mode standard
   ```

   Add only user-requested safe options such as `--offline`, `--fail-on`, or `--reports-dir`. Do not add remote targets or credentials.
4. Preserve the CLI exit code:
   - `0`: deterministic scan complete below threshold
   - `1`: deterministic scan complete with findings at or above threshold
   - `2`: a required scanner failed
   - `3`: configuration or scope error
   - `4`: orchestrator error
   Exit `1` is not a scanner failure. A missing Cloudflare skill is not exit `2`.
5. Read `scan-manifest.json`, `findings.json`, and `report.md`. Record the report directory.
6. Run the Cloudflare source audit. This step is required for a full audit.
   - Look for the upstream skill at `~/.cursor/skills/security-audit/SKILL.md` or `~/.agents/skills/security-audit/SKILL.md`.
   - If that skill is missing, or this session cannot follow its full audit mode, stop the Cloudflare layer. Report the deterministic CLI status as it is. Report the combined audit as **incomplete**. Say the Cloudflare workflow was **not executed** and why. Do not invent `findings.json` and do not attach an empty file.
   - If it is present, read that skill and follow **full audit mode** in order: reconnaissance, coverage-led hunting, candidate validation, structured findings, independent verification, and reporting. Do not invoke the `security-scan` skill again. Do not start a second audit.
   - Write audit artifacts outside the target repository. The upstream default is `~/security-audit-skill/<repo>/run-<N>`.
   - Do not execute target-controlled code unless that skill's OS sandbox is actually enforced: no external network, allowlisted environment, read-only target and toolchain, scratch-only writes, and resource limits. If it is not enforced, do not run that code. Leave those candidates `needs_validation` and record the blocker.
   - Do not modify the target application.
   - After all six phases have actually finished and `findings.json` exists, validate and attach:

     ```bash
     security-scan audit validate --repo "<absolute-repository-path>" --findings "<path>"
     security-scan audit attach --repo "<absolute-repository-path>" --scan-dir "<report-dir>" --findings "<path>"
     ```

   - If validation or attach fails, keep the deterministic scan result and mark the combined audit **incomplete**. A failed Cloudflare audit is not a success.

7. Summarize with `assessSecurityWorkflow` semantics:
   - Cloudflare **executed** only when the upstream workflow was invoked, all six phases finished, validation passed, and attach succeeded.
   - Phase completion may be listed only for phases that finished.
   - If Trivy and Semgrep succeed but Cloudflare was not executed or failed, the deterministic scan is complete (or complete with findings) and the combined audit is **incomplete**.
   - Coverage is never comprehensive.

## Deterministic-only

Use this only when the user explicitly asks for a deterministic-only scan, a standard scan only, or a scan without the Cloudflare source audit.

- Run steps 1–5 only.
- Do not read or invoke `security-audit`.
- Say Cloudflare was **not requested**.
- Report the CLI status and exit code. Do not call that result a full three-layer audit.

## Safety requirements

- Never interpret failed, skipped, or unsupported checks as passing.
- Never describe a finished plan, an empty coverage-gap list, or a finished hunt as comprehensive security coverage.
- A Semgrep process exit of 1 with a valid results document is a completed finding run, not a failed scanner.
- Never claim a vulnerable dependency is reachable unless a separate implemented reachability analysis established it.
- Never run project installs, builds, tests, lifecycle scripts, or application servers as part of the deterministic scan.
- Never request or pass production credentials.
- Never run ZAP, Strix, active DAST, or any remote-target scan from this skill.
- Never modify application code or automatically remediate findings.
- Do not print raw secret evidence. Use redacted normalized findings.
- Do not commit reports or raw artifacts unless the user explicitly asks after reviewing their sensitivity.
- Do not merge a deterministic finding with a source-audit finding because the titles or paths look similar. Attachment keeps both, with their own provenance and verdict.

## Final response

For a full audit, lead with the combined status and state the deterministic CLI status and exit code separately. Include the report path. List Trivy, Semgrep, and Cloudflare execution separately. List confirmed, needs-validation, and rejected audit records when an audit was attached. State which Cloudflare phases finished, using only phases you actually completed. Always state planned coverage, out-of-scope checks, unsupported combinations, and scanner failures.

Never say the Cloudflare workflow ran unless you completed it and attached validated findings.
