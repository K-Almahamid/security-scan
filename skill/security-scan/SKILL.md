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

`src/workflow.ts` is the status contract. `planSecurityWorkflow("full")` includes `standard-scan`, `cloudflare-source-audit`, and `validate-and-attach`. The CLI records execution in `workflow-run.json` and reports combined status through `security-scan workflow assess`.

Cursor does not automatically invoke other Skills or MCP servers. You must read the upstream `security-audit` skill and follow it in this session when a full audit is requested.

## `/security-scan` workflow

1. **Resolve the target repository** from the current Cursor workspace root (absolute path). Never assume the Security Scan installation directory is the target. If the workspace is ambiguous, ask which repository to scan.
2. **Preflight:**

   ```bash
   security-scan doctor --repo "<absolute-repository-path>" --workflow full
   ```

   For deterministic-only requests, use `--workflow deterministic-only`. If doctor exits `2`, stop and report missing required prerequisites. Exit `1` means optional full-audit integrations are missing; continue only when the user still wants a full audit and accepts the gap.
3. **Choose the workflow mode.** Default to **full audit** unless the user explicitly asked for deterministic-only, standard scan only, or no Cloudflare source audit.
4. **Run the deterministic scan:**

   ```bash
   security-scan scan --repo "<absolute-repository-path>" --mode standard --workflow <full|deterministic-only>
   ```

   Add only user-requested safe options (`--offline`, `--fail-on`, `--reports-dir`). Record the `workflowRun` path from the CLI JSON summary.
5. **Read** `scan-manifest.json`, `findings.json`, `workflow-run.json`, and `report.md` from the report directory.
6. **Cloudflare source audit (full audit only).** Required for a full audit; skip for deterministic-only.
   - Confirm the upstream skill exists at `~/.cursor/skills/security-audit/SKILL.md` or `~/.agents/skills/security-audit/SKILL.md`.
   - If it is missing or this session cannot follow full audit mode, do not invent findings. Say the Cloudflare workflow was **not executed** and why. The combined audit is **incomplete**.
   - If present, read that skill and follow **full audit mode** through all six phases. Do not invoke the `security-scan` skill again.
   - Write hunt artifacts outside the target (upstream default: `~/security-audit-skill/<repo>/run-<N>`).
   - Do not execute target-controlled code unless the upstream OS sandbox is actually enforced.
7. **Register what actually happened** (agent-driven; the CLI does not observe phases):

   ```bash
   security-scan workflow register-cloudflare --repo "<absolute-repository-path>" --scan-dir "<report-dir>" \
     --status completed|failed|skipped --invoked true|false \
     --skill-installed true|false --delegation-available true|false --sandbox-available true|false \
     --phases "<comma-separated-phase-ids>" \
     [--findings "<path-to-findings.json>"] [--failure-reason "<text>"]
   ```

   Use only phase ids you actually finished. Do not mark `completed` unless all six phases finished and `findings.json` exists.
8. **Validate and attach** when findings exist:

   ```bash
   security-scan audit validate --repo "<absolute-repository-path>" --findings "<path>"
   security-scan audit attach --repo "<absolute-repository-path>" --scan-dir "<report-dir>" --findings "<path>"
   ```

   Failed validation or attach leaves the combined audit **incomplete** while preserving the deterministic scan.
9. **Assess the combined workflow:**

   ```bash
   security-scan workflow assess --repo "<absolute-repository-path>" --scan-dir "<report-dir>" [--workflow full|deterministic-only] --json
   ```

   Omit `--workflow` to use the request recorded in `workflow-run.json`. Do not pass `--workflow deterministic-only` for reports created with `--workflow full`; the CLI rejects that downgrade.

10. **Respond** using the assess output. Lead with combined status, then deterministic CLI status and exit codes separately. Never claim the Cloudflare workflow ran unless registration, validation, and attach succeeded.

## Exit codes

**Deterministic scan (`scan`):** unchanged — `0` clean below threshold, `1` findings at/above threshold, `2` incomplete, `3` scope/config, `4` internal error.

**Doctor:** `0` ready, `1` full-audit optional gaps, `2` deterministic prerequisites missing.

**Workflow assess:** `0` combined complete (or complete with findings below treating incomplete as 2), `1` deterministic findings at threshold with otherwise complete combined workflow, `2` incomplete combined workflow or deterministic incomplete, `3` scope error.

A successful deterministic scan does **not** mean a full audit succeeded.

## Deterministic-only

When the user explicitly requests deterministic-only:

- Use `doctor --workflow deterministic-only`, `scan --workflow deterministic-only`, and `workflow assess --workflow deterministic-only`.
- Do not read or invoke `security-audit`.
- State Cloudflare was **not requested** for the scan plan.

### Attaching a hunt after a deterministic-only scan

A separate Cloudflare hunt is still allowed when the user wants it: run the upstream `security-audit` skill, then `audit validate` and `audit attach` on the existing report directory. That is **report attachment**, not proof the full workflow ran inside the CLI.

After attach, `workflow-run.json` may show `cloudflare.attached: true` and `cloudflare.validation: passed` while `cloudflare.invoked` remains `false` and `request` stays `deterministic-only` unless the scan used `--workflow full`. Do **not** tell the user the full six-phase workflow completed unless you also ran `workflow register-cloudflare` with accurate phase IDs and `workflow assess` (for a `full` report) shows combined completion.

`workflow assess` uses the `request` recorded at scan time. Assessing a deterministic-only report as a full audit requires a scan that was created with `--workflow full`.

## Workflow metadata (agent reference)

| Signal | Meaning |
|--------|---------|
| `cloudflare.invoked` | You registered that the hunt was started (`workflow register-cloudflare --invoked true`). |
| `cloudflare.attached` | Validated findings were merged into the report (`audit attach`). |
| `cloudflare.validation` | Schema validation outcome for the attached file. |
| Phase list in registration | Only phases you actually finished; never invent phases. |

Attachment ≠ invocation. Attachment ≠ phase completion. Zero normalized findings does not mean a clean scan when a required tool failed or coverage was partial.

## Safety requirements

- Never interpret failed, skipped, or unsupported checks as passing.
- Never describe coverage as comprehensive.
- Semgrep exit `1` with valid JSON is a completed finding run, not a scanner failure.
- Never run installs, builds, or application servers as part of the deterministic scan.
- Never auto-remediate or modify application code.
- Do not print raw secret evidence.

## Final response

Include report paths, per-layer execution, workflow assess JSON summary, failed/skipped tools, unsupported checks, and Cloudflare phase completion only for phases you actually finished.

Never say the Cloudflare workflow ran unless you registered it, validated findings, and attached them successfully.
