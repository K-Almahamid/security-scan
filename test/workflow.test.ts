import assert from "node:assert/strict";
import { access, cp, mkdtemp, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { createFinding } from "../src/findings.js";
import { renderMarkdownReport } from "../src/reports.js";
import { attachSourceAuditToReport } from "../src/source-audit/attach.js";
import { importCloudflareFindings, parseCloudflareFindings } from "../src/source-audit/import.js";
import { validateCloudflareFindingsFile } from "../src/source-audit/validate.js";
import type { ScanManifest } from "../src/types.js";
import {
  CLOUDFLARE_AUDIT_PHASES,
  assessSecurityWorkflow,
  cloudflareSkillCandidates,
  planSecurityWorkflow,
  renderWorkflowSummary,
  type CloudflareRunState,
} from "../src/workflow.js";

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(fixtureDir, "..");
const samplePath = path.join(fixtureDir, "fixtures/cloudflare-findings-sample.json");

const passedTools = [
  { adapter: "trivy", status: "passed" as const },
  { adapter: "semgrep", status: "passed" as const },
];

function cloudflare(overrides: Partial<CloudflareRunState> = {}): CloudflareRunState {
  return {
    skillInstalled: true,
    delegationAvailable: true,
    sandboxAvailable: false,
    invoked: true,
    phasesCompleted: [...CLOUDFLARE_AUDIT_PHASES],
    validation: "passed",
    attached: true,
    ...overrides,
  };
}

describe("full security-audit workflow", () => {
  it("mocked: a completed Cloudflare workflow plus a standard scan is one audit", () => {
    const plan = planSecurityWorkflow("full");
    assert.deepEqual(plan.steps.map((step) => step.id), [
      "standard-scan",
      "cloudflare-source-audit",
      "validate-and-attach",
    ]);
    const assessment = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete_with_findings", toolRuns: passedTools },
      cloudflare: cloudflare(),
    });
    assert.equal(assessment.cloudflareExecuted, true);
    assert.equal(assessment.cloudflareStatus, "attached");
    assert.equal(assessment.combinedStatus, "complete_with_findings");
    assert.equal(assessment.comprehensive, false);
    assert.equal(assessment.phasesCompleted.length, CLOUDFLARE_AUDIT_PHASES.length);
    assert.match(renderWorkflowSummary(assessment), /Cloudflare workflow executed: yes/);
    assert.match(renderWorkflowSummary(assessment), /Comprehensive coverage: no/);
    assert.match(renderWorkflowSummary(assessment), /OS sandbox isolation was not available/);
  });

  it("the default full-audit skill invokes the Cloudflare workflow", async () => {
    const skill = await readFile(path.join(projectRoot, "skill/security-scan/SKILL.md"), "utf8");
    const sourceAudit = await readFile(
      path.join(projectRoot, "skill/security-scan-source-audit/SKILL.md"),
      "utf8",
    );
    assert.match(skill, /planSecurityWorkflow\("full"\)/);
    assert.match(skill, /cloudflare-source-audit/);
    assert.match(skill, /~\/\.cursor\/skills\/security-audit\/SKILL\.md/);
    assert.match(skill, /full audit mode/);
    assert.match(skill, /Do not invoke the `security-scan` skill again/);
    assert.match(sourceAudit, /Do not invoke the `security-scan` skill again/);
    assert.equal(planSecurityWorkflow("full").steps.some((step) => step.layer === "cloudflare"), true);
  });

  it("mocked: a missing skill or unavailable agents are not an executed audit", () => {
    const missing = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete", toolRuns: passedTools },
      cloudflare: cloudflare({ skillInstalled: false, invoked: false }),
    });
    assert.equal(missing.deterministicStatus, "complete");
    assert.equal(missing.cloudflareStatus, "not_executed");
    assert.equal(missing.cloudflareExecuted, false);
    assert.equal(missing.combinedStatus, "incomplete");
    assert.match(renderWorkflowSummary(missing), /not installed/);

    const unavailable = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete_with_findings", toolRuns: passedTools },
      cloudflare: cloudflare({ delegationAvailable: false, invoked: false }),
    });
    assert.equal(unavailable.cloudflareExecuted, false);
    assert.equal(unavailable.combinedStatus, "incomplete");
    assert.match(renderWorkflowSummary(unavailable), /delegated agents/);
    assert.equal(unavailable.deterministicStatus, "complete_with_findings");
  });

  it("mocked: Cloudflare validation failure stays incomplete", () => {
    const assessment = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete", toolRuns: passedTools },
      cloudflare: cloudflare({ validation: "failed", attached: false, failureReason: "schema mismatch" }),
    });
    assert.equal(assessment.cloudflareStatus, "validation_failed");
    assert.equal(assessment.cloudflareExecuted, false);
    assert.equal(assessment.combinedStatus, "incomplete");
    assert.match(renderWorkflowSummary(assessment), /Cloudflare workflow executed: no/);
    assert.match(renderWorkflowSummary(assessment), /schema mismatch/);
  });

  it("rejects malformed audit findings and an unfinished phase list", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "security-scan-workflow-bad-"));
    const invalidPath = path.join(dir, "findings.json");
    await writeFile(invalidPath, "{\"verdict\":\"confirmed\"}\n");
    const validation = await validateCloudflareFindingsFile(invalidPath);
    assert.equal(validation.ok, false);
    assert.throws(() => importCloudflareFindings(dir, parseCloudflareFindings({ verdict: "confirmed" })));

    const partial = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete", toolRuns: passedTools },
      cloudflare: cloudflare({ phasesCompleted: ["reconnaissance"], validation: "not_run", attached: false }),
    });
    assert.equal(partial.cloudflareExecuted, false);
    assert.equal(partial.combinedStatus, "incomplete");
    assert.deepEqual(partial.phasesCompleted, ["reconnaissance"]);
  });

  it("keeps confirmed, needs_validation, and rejected verdicts and provenance", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-workflow-verdicts-"));
    const raw = JSON.parse(await readFile(samplePath, "utf8")) as unknown;
    const imported = importCloudflareFindings(repo, parseCloudflareFindings(raw));
    assert.equal(imported.counts.confirmed, 1);
    assert.equal(imported.counts.needs_validation, 1);
    assert.equal(imported.counts.rejected, 1);
    assert.equal(imported.rejected[0]?.verdict, "rejected");
    for (const finding of imported.importable) {
      assert.equal(finding.provenance, "source-audit");
    }
    const confirmed = imported.importable.find((finding) => finding.auditVerdict === "confirmed");
    const pending = imported.importable.find((finding) => finding.auditVerdict === "needs_validation");
    assert.equal(confirmed?.verification, "confirmed");
    assert.equal(pending?.verification, "needs_validation");
    assert.equal(pending?.severity, "unknown");
  });

  it("a standard scan with findings plus a real attachment is unified and idempotent", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-workflow-unified-"));
    const reportDir = await copyMinimalScan(repo);
    const manifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    manifest.toolRuns.push({
      id: "semgrep-app",
      adapter: "semgrep",
      componentId: "app",
      status: "findings",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      exitCode: 1,
      version: "1.143.1",
      reason: null,
      logPath: null,
      findingCount: 1,
    });
    manifest.counts.high = 1;
    manifest.overallStatus = "complete_with_findings";
    const deterministic = createFinding({
      title: "SQL injection",
      severity: "high",
      category: "sast",
      component: "app",
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "static rule hit",
      source: { tool: "semgrep", ruleId: "sql-injection" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    await writeFile(path.join(reportDir, "findings.json"), `${JSON.stringify([deterministic], null, 2)}\n`);
    await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

    const before = renderMarkdownReport(manifest, [deterministic]);
    assert.match(before, /\| Trivy \| passed/);
    assert.match(before, /\| Semgrep CE \| findings/);
    assert.match(before, /\| Cloudflare source audit \| not executed \|/);
    assert.match(before, /Comprehensive security coverage: \*\*No\*\*/);
    assert.match(before, /Dynamic application security testing/);

    const first = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(first.ok, true, first.message);
    const findings = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8")) as Array<{
      provenance: string;
      title: string;
      verification: string;
    }>;
    assert.equal(findings.length, 3);
    assert.equal(findings.filter((finding) => finding.provenance === "deterministic").length, 1);
    assert.equal(findings.filter((finding) => finding.provenance === "source-audit").length, 2);
    assert.equal(
      findings.find((finding) => finding.title === "SQL injection")?.verification,
      "potential",
    );

    const attachedManifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as ScanManifest;
    const report = await readFile(path.join(reportDir, "report.md"), "utf8");
    assert.match(report, /\| Trivy \| passed/);
    assert.match(report, /\| Semgrep CE \| findings/);
    assert.match(report, /\| Cloudflare source audit \| attached/);
    assert.match(report, /Phase completion: not observed by the CLI/);
    assert.match(report, /- Provenance: deterministic/);
    assert.match(report, /- Provenance: source-audit/);
    assert.match(report, /- Source-audit verdict: confirmed/);
    assert.match(report, /- Source-audit verdict: needs_validation/);
    assert.match(report, /Rejected source-audit candidates/);
    assert.equal(attachedManifest.coverage.comprehensive, false);
    assert.equal(attachedManifest.execution.status, "complete");

    const second = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(second.ok, true, second.message);
    const repeated = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8")) as unknown[];
    assert.equal(repeated.length, findings.length);
  });

  it("deterministic-only does not include or claim the Cloudflare audit", async () => {
    const skill = await readFile(path.join(projectRoot, "skill/security-scan/SKILL.md"), "utf8");
    assert.match(skill, /## Deterministic-only/);
    assert.match(skill, /Do not read or invoke `security-audit`/);
    const plan = planSecurityWorkflow("deterministic-only");
    assert.deepEqual(plan.steps.map((step) => step.layer), ["deterministic"]);
    const assessment = assessSecurityWorkflow({
      request: "deterministic-only",
      deterministic: {
        status: "complete_with_findings",
        toolRuns: [
          { adapter: "trivy", status: "findings" },
          { adapter: "semgrep", status: "findings" },
        ],
      },
    });
    assert.equal(assessment.cloudflareStatus, "not_requested");
    assert.equal(assessment.cloudflareExecuted, false);
    assert.equal(assessment.combinedStatus, "complete_with_findings");
    assert.equal(assessment.reasons.some((reason) => reason.includes("scanner failed")), false);
  });

  it("scanner findings are not a scanner execution failure", () => {
    const assessment = assessSecurityWorkflow({
      request: "full",
      deterministic: {
        status: "complete_with_findings",
        toolRuns: [
          { adapter: "trivy", status: "findings" },
          { adapter: "semgrep", status: "findings" },
        ],
      },
      cloudflare: cloudflare({ skillInstalled: false, invoked: false }),
    });
    assert.equal(assessment.deterministicStatus, "complete_with_findings");
    assert.equal(assessment.reasons.some((reason) => reason.includes("scanner failed")), false);
    assert.equal(assessment.combinedStatus, "incomplete");
    assert.equal(assessment.cloudflareExecuted, false);
  });

  it("coverage stays non-comprehensive when checks are out of scope", () => {
    const assessment = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete", toolRuns: passedTools },
      cloudflare: cloudflare(),
    });
    assert.equal(assessment.comprehensive, false);
    assert.match(renderWorkflowSummary(assessment), /Comprehensive coverage: no/);
  });

  it("environment: does not execute the upstream hunt from this test", async () => {
    const installed: string[] = [];
    for (const candidate of cloudflareSkillCandidates()) {
      try {
        await access(candidate);
        installed.push(candidate);
      } catch {
        // The skill file is not present at this candidate.
      }
    }
    const assessment = assessSecurityWorkflow({
      request: "full",
      deterministic: { status: "complete", toolRuns: passedTools },
      cloudflare: cloudflare({
        skillInstalled: installed.length > 0,
        delegationAvailable: false,
        invoked: false,
      }),
    });
    assert.equal(assessment.cloudflareExecuted, false);
    assert.notEqual(assessment.cloudflareStatus, "attached");
  });
});

async function copyMinimalScan(repo: string): Promise<string> {
  const source = path.join(fixtureDir, "fixtures/minimal-scan");
  const reportDir = path.join(repo, "security-reports", "fixture-scan");
  await mkdir(reportDir, { recursive: true });
  for (const name of ["findings.json", "profile.json", "scan-plan.json", "scan-manifest.json", "report.md"]) {
    await cp(path.join(source, name), path.join(reportDir, name));
  }
  const manifest = JSON.parse(await readFile(path.join(reportDir, "scan-manifest.json"), "utf8")) as {
    repositoryPath: string;
    reportDirectory: string;
  };
  manifest.repositoryPath = await realpath(repo);
  manifest.reportDirectory = reportDir;
  await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return reportDir;
}
