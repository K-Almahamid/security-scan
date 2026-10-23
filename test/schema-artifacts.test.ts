import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import addFormats from "ajv-formats";
import Ajv2020 from "ajv/dist/2020.js";
import { createFinding } from "../src/findings.js";
import { findingCounts, writeReports } from "../src/reports.js";
import type { ScanManifest, ScanPlan } from "../src/types.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

describe("generated artifacts match the published schemas", () => {
  it("validates a report written by the orchestrator", async () => {
    const finding = createFinding({
      title: "Fixture finding",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: "canary.env", startLine: 1 },
      evidence: "token=super-secret-value",
      source: { tool: "trivy", ruleId: "github-pat" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    const plan: ScanPlan = {
      mode: "standard",
      tools: [{
        id: "trivy-repository",
        adapter: "trivy",
        componentId: null,
        targetPath: ".",
        required: true,
        checks: ["secret"],
        reason: "fixture",
      }],
      supportedChecks: ["Repository secret detection"],
      outOfScope: ["Dynamic application security testing (DAST) and arbitrary remote target scanning"],
      unsupported: [],
      coverageGaps: [],
    };
    const reportDirectory = path.join(await mkdtemp(path.join(os.tmpdir(), "security-scan-schema-")), "scan");
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "schema-scan",
      repositoryPath: projectRoot,
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      overallStatus: "complete_with_findings",
      mode: "standard",
      toolRuns: [{
        id: "trivy-repository",
        adapter: "trivy",
        componentId: null,
        status: "findings",
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:00:01.000Z",
        durationMs: 1000,
        exitCode: 0,
        version: "0.67.2",
        reason: null,
        logPath: null,
        findingCount: 1,
      }],
      execution: { status: "complete", planned: 1, completed: 1, failed: 0, skipped: 0, unsupported: 0 },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: ["trivy:secret"],
        supportedChecks: ["Repository secret detection"],
        outOfScope: ["Dynamic application security testing (DAST) and arbitrary remote target scanning"],
        unsupported: [],
      },
      coverageGaps: [],
      counts: findingCounts([finding]),
      rawArtifactsPath: "/tmp/raw",
      reportDirectory,
    };
    await writeReports({
      reportDirectory,
      profile: {
        repositoryPath: projectRoot,
        generatedAt: "2026-01-01T00:00:00.000Z",
        components: [],
        dockerfiles: [],
        composeFiles: [],
        ciFiles: [],
        previousReports: [],
      },
      plan,
      manifest,
      findings: [finding],
    });
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    addFormats(ajv);
    const manifestSchema = JSON.parse(
      await readFile(path.join(projectRoot, "schemas/manifest.schema.json"), "utf8"),
    ) as object;
    const findingSchema = JSON.parse(
      await readFile(path.join(projectRoot, "schemas/finding.schema.json"), "utf8"),
    ) as object;
    const validateManifest = ajv.compile(manifestSchema);
    const validateFindings = ajv.compile(findingSchema);
    const writtenManifest = JSON.parse(await readFile(path.join(reportDirectory, "scan-manifest.json"), "utf8"));
    const writtenFindings = JSON.parse(await readFile(path.join(reportDirectory, "findings.json"), "utf8"));
    assert.equal(validateManifest(writtenManifest), true, JSON.stringify(validateManifest.errors));
    assert.equal(validateFindings(writtenFindings), true, JSON.stringify(validateFindings.errors));
    assert.equal(writtenManifest.counts.high, 1);
    assert.equal(writtenManifest.coverage.comprehensive, false);
    assert.deepEqual(writtenManifest.coverageGaps, []);
    const markdown = await readFile(path.join(reportDirectory, "report.md"), "utf8");
    assert.match(markdown, /Comprehensive security coverage: \*\*No\*\*/);
    assert.ok(!markdown.includes("super-secret-value"));
    await assert.rejects(() => import("node:fs/promises").then((fs) => fs.access(`${reportDirectory}.partial`)));
  });
});
