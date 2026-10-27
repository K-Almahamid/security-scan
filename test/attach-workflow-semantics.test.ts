import assert from "node:assert/strict";
import { cp, mkdtemp, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { createFinding, deduplicateFindings } from "../src/findings.js";
import { attachSourceAuditToReport } from "../src/source-audit/attach.js";
import { assertRepositoryPath } from "../src/profile.js";
import { assessWorkflowFromReport } from "../src/workflow-assess.js";
import { createInitialWorkflowRun, loadWorkflowRun } from "../src/workflow-run.js";
import type { ScanManifest } from "../src/types.js";
import { WORKFLOW_RUN_FILENAME } from "../src/workflow-run.js";

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const samplePath = path.join(fixtureDir, "fixtures/cloudflare-findings-sample.json");

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

describe("attach and workflow metadata semantics", () => {
  it("records attachment without implying Cloudflare invocation on deterministic-only scans", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-attach-meta-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = await copyMinimalScan(repo);
    const manifestPath = path.join(reportDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    manifest.overallStatus = "incomplete";
    manifest.toolRuns.push({
      id: "semgrep-root",
      adapter: "semgrep",
      componentId: "root",
      status: "failed",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      exitCode: 0,
      version: "1.143.1",
      reason: "Semgrep completed with partial parsing coverage",
      logPath: null,
      findingCount: 100,
    });
    manifest.execution = {
      status: "incomplete",
      planned: 2,
      completed: 1,
      failed: 1,
      skipped: 0,
      unsupported: 0,
    };
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const workflowRun = createInitialWorkflowRun({
      scanId: manifest.scanId,
      repositoryPath: manifest.repositoryPath,
      request: "deterministic-only",
      startedAt: manifest.startedAt,
    });
    await writeFile(
      path.join(reportDir, WORKFLOW_RUN_FILENAME),
      `${JSON.stringify(workflowRun, null, 2)}\n`,
    );

    const attach = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(attach.ok, true, attach.message);

    const loaded = await loadWorkflowRun(reportDir);
    assert.ok(loaded);
    assert.equal(loaded.request, "deterministic-only");
    assert.equal(loaded.cloudflare.invoked, false);
    assert.equal(loaded.cloudflare.attached, true);
    assert.equal(loaded.cloudflare.validation, "passed");
    assert.equal(loaded.steps.some((step) => step.id === "validate-and-attach"), false);

    const afterManifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    assert.equal(afterManifest.overallStatus, "incomplete");
    assert.ok(afterManifest.sourceAudit);

    const assess = await assessWorkflowFromReport({ repo, scanDir: reportDir });
    assert.equal(assess.assessment.request, "deterministic-only");
    assert.equal(assess.assessment.cloudflareStatus, "not_requested");
  });

  it("does not upgrade an incomplete deterministic manifest to complete on attach", async () => {
    const repo = await assertRepositoryPath(
      await mkdtemp(path.join(os.tmpdir(), "security-scan-attach-incomplete-")),
    );
    await writeFile(path.join(repo, "package.json"), JSON.stringify({ name: "fixture" }));
    const reportDir = await copyMinimalScan(repo);
    const manifestPath = path.join(reportDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    manifest.overallStatus = "incomplete";
    manifest.execution.status = "incomplete";
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    const result = await attachSourceAuditToReport({
      repoPath: repo,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: samplePath,
    });
    assert.equal(result.ok, true, result.message);
    const updated = JSON.parse(await readFile(manifestPath, "utf8")) as ScanManifest;
    assert.equal(updated.overallStatus, "incomplete");
  });

  it("documents that normalized findings can be fewer than the sum of tool findingCount", () => {
    const scannedAt = "2026-01-01T00:00:00.000Z";
    const base = createFinding({
      title: "Duplicate rule hit",
      severity: "high",
      category: "sast",
      component: "app",
      location: { path: "src/a.ts", startLine: 10 },
      evidence: "eval(userInput)",
      source: { tool: "semgrep", ruleId: "rule.eval" },
      scannedAt,
    });
    const duplicate = structuredClone(base);
    duplicate.id = "other-id";
    const normalized = deduplicateFindings([base, duplicate]);
    assert.equal(normalized.length, 1);
    const toolFindingSum = 2;
    assert.ok(toolFindingSum > normalized.length);
  });
});
