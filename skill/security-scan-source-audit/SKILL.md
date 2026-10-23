---
name: security-scan-source-audit
description: Optional agentic source-level security audit using Cloudflare's security-audit methodology, complementary to the deterministic Security Scan CLI. Use only when the user explicitly requests a full source audit, architecture review with trust boundaries, or Cloudflare-style coverage-led hunting after or alongside a standard scan.
disable-model-invocation: true
---

# Security Scan — optional source-level audit

This workflow is **separate** from `security-scan scan --mode standard`. The CLI does not
launch multi-agent hunting. It only validates and imports Cloudflare-format
`findings.json` artifacts produced by an agent run.

## When to use

Use this skill when the user explicitly asks for:

- a full / comprehensive / end-to-end **source** security audit;
- trust-boundary mapping and coverage-led investigation;
- Cloudflare Security Audit Skill methodology; or
- merging agentic audit results into an existing Security Scan report.

Do **not** use this for routine baseline scans — use the `security-scan` skill instead.

## Prerequisites

1. Install the upstream Cloudflare skill (source of truth for hunting prompts and safety rules):

   ```bash
   npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
   ```

2. Install the local Security Scan CLI (`security-scan` on `PATH`).

## Recommended flow

### 1. Deterministic baseline (optional but recommended)

```bash
security-scan scan --repo "<absolute-repository-path>" --mode standard
```

Record the report directory path (`security-reports/<scan-id>/`).

### 2. Agentic source audit (Cursor only)

Follow the upstream `security-audit` skill in **full audit mode**:

- Read-only reconnaissance unless OS-enforced sandbox controls are available.
- Never execute target code without network isolation, allowlisted environment,
  read-only target/toolchain, scratch-only writes, and resource limits.
- If sandbox requirements cannot be met, keep candidates as `needs_validation` —
  never downgrade to confirmed.

Write artifacts to a directory **outside** the target repository unless the user
explicitly chooses an ignored in-repo path.

### 3. Validate and attach (CLI)

```bash
security-scan audit validate --repo "<absolute-repository-path>" --findings "<path-to-findings.json>"
security-scan audit attach --repo "<absolute-repository-path>" --scan-dir "<report-dir>" --findings "<path-to-findings.json>"
```

`attach` fails closed if validation fails. Rejected candidates remain in
`source-audit-records.json` and are not promoted to confirmed findings.

## Response requirements

- State clearly that source audit is **agentic**, not a reproducible CLI scanner.
- Distinguish `confirmed`, `needs_validation`, and `rejected` records.
- Never claim comprehensive coverage because hunting completed.
- Never auto-remediate the target application.
- Never scan production systems or external targets.

## Attribution

Hunting methodology and validators: [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT).
