---
name: security-scan-source-audit
description: Runs the Cloudflare security-audit skill and attaches its validated findings to a Security Scan report. The default security-scan skill uses this as the Cloudflare layer of a full audit. Also use it when the user asks only for the source audit.
disable-model-invocation: true
---

# Security Scan — Cloudflare source audit

This skill is the Cloudflare layer of a full security audit. It is not a CLI scanner. `security-scan scan` does not launch it. This skill does not reimplement `audit validate`, `audit import`, or `audit attach`.

The three layers are:

1. Trivy and Semgrep (and `dart analyze` when already available) — the deterministic CLI scan.
2. This skill — reconnaissance, coverage-led hunting, candidate validation, structured findings, independent verification, and reporting, by following the upstream `security-audit` skill.
3. The CLI attachment commands — schema validation and idempotent import into the scan report.

## Do not recurse

If the `security-scan` skill dispatched this phase, a report directory already exists.

- Do not invoke the `security-scan` skill again.
- Do not start a second standard scan or a second Cloudflare audit.
- Continue with the upstream full audit, then validate and attach to that report directory.

If no report directory exists, run the CLI directly — not the `security-scan` skill:

```bash
security-scan scan --repo "<absolute-repository-path>" --mode standard
```

## Prerequisites

1. The upstream skill must be installed:

   ```bash
   npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
   ```

   It is expected at `~/.cursor/skills/security-audit/SKILL.md` or `~/.agents/skills/security-audit/SKILL.md`. If neither file exists, or this session cannot follow full audit mode, stop. Report that the Cloudflare workflow was **not executed** and why. Do not invent findings. The deterministic scan, if it already finished, stays complete or complete with findings. The combined audit is **incomplete**.

2. `security-scan` must be on `PATH`.

## Full audit mode

Read the upstream `security-audit` skill and follow all six phases in order:

1. Reconnaissance
2. Coverage-led hunting
3. Candidate validation
4. Structured findings (`findings.json` plus the upstream validators)
5. Independent record verification
6. Reporting (`REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, or an explicit `run_status: "incomplete"`)

Guidance mode is not a full audit. A copied skill file is not an executed audit.

Write artifacts outside the target repository, by default `~/security-audit-skill/<repo>/run-<N>`. Do not put them in the target's Git-tracked source. The scan report under `security-reports/<scan-id>/` is the only target location written, and only by `audit attach`.

Do not execute target-controlled code unless the upstream OS sandbox is enforced: no external network, an allowlisted environment, a read-only target and toolchain, scratch-only writes, and resource limits. If that isolation is unavailable, do not run the target code. Keep the affected candidates `needs_validation` and record the blocker.

Do not modify the target application. Do not scan production or external systems.

## Validate and attach

Only after the six phases finished and `findings.json` exists:

```bash
security-scan audit validate --repo "<absolute-repository-path>" --findings "<path-to-findings.json>"
security-scan audit attach --repo "<absolute-repository-path>" --scan-dir "<report-dir>" --findings "<path-to-findings.json>"
```

`attach` fails closed when validation fails and leaves the previous report in place. Rejected records stay in `source-audit-records.json` and are not promoted to confirmed findings. Confirmed and `needs_validation` records stay importable, with provenance `source-audit`. Repeating attach with the same file is idempotent. Attachment does not execute repository code and is not a sandbox. Paths that escape the repository, including symlink escapes, are rejected.

Same title or path does not merge a deterministic finding with an audit finding.

## Response requirements

- Say whether the Cloudflare workflow executed. Do not say it ran because the skill file exists or because attach commands exist.
- If it did not finish, say the combined audit is incomplete and keep the deterministic result separate.
- Distinguish `confirmed`, `needs_validation`, and `rejected`.
- List only the phases that finished.
- Never claim comprehensive coverage.
- Never auto-remediate the target.

## Attribution

Hunting methodology and validators: [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT).
The vendored validators in this repository check artifacts. They do not perform the hunt.
