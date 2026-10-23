import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { createFinding, validateFindings } from "../src/findings.js";
import { attachSourceAuditToReport } from "../src/source-audit/attach.js";
import {
  importCloudflareFindings,
  parseCloudflareFindings,
} from "../src/source-audit/import.js";
import { mergeDeterministicWithSourceAudit } from "../src/source-audit/merge.js";
import { validateCloudflareFindingsFile } from "../src/source-audit/validate.js";
import type { ScanManifest } from "../src/types.js";

const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
const samplePath = path.join(fixtureDir, "fixtures/cloudflare-findings-sample.json");

describe("Cloudflare source-audit integration", () => {
  it("validates producer-shaped findings with the vendored validator", async () => {
    const result = await validateCloudflareFindingsFile(samplePath);
    assert.equal(result.ok, true);
  });

  it("imports confirmed and needs_validation without promoting rejected records", async () => {
    const repo = await mkdtemp(path.join(os.tmpdir(), "security-scan-repo-"));
    const raw = JSON.parse(await readFile(samplePath, "utf8")) as unknown;
    const imported = importCloudflareFindings(repo, parseCloudflareFindings(raw));
    assert.equal(imported.importable.length, 2);
    assert.equal(imported.rejected.length, 1);
    assert.equal(imported.counts.rejected, 1);
    const confirmed = imported.importable.find((f) => f.auditVerdict === "confirmed");
    const blocked = imported.importable.find((f) => f.auditVerdict === "needs_validation");
    assert.ok(confirmed);
    assert.equal(confirmed.verification, "confirmed");
    assert.equal(confirmed.severity, "medium");
    assert.ok(blocked);
    assert.equal(blocked.verification, "needs_validation");
    assert.equal(blocked.severity, "unknown");
    validateFindings(imported.importable);
  });

  it("merges cross-provenance findings at the same location without inventing evidence", () => {
    const deterministic = createFinding({
      title: "Missing ownership check",
      severity: "high",
      category: "sast",
      component: null,
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "static rule hit",
      source: { tool: "semgrep", ruleId: "semgrep.c.ownership" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    const sourceAudit = createFinding({
      title: "Missing ownership check",
      severity: "medium",
      category: "sast",
      component: null,
      location: { path: "src/handler.c", startLine: 30, endLine: 30 },
      evidence: "reproduced in sandbox",
      source: { tool: "cloudflare-source-audit", ruleId: "source-audit.confirmed" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    sourceAudit.provenance = "source-audit";
    sourceAudit.auditVerdict = "confirmed";
    sourceAudit.verification = "confirmed";

    const merged = mergeDeterministicWithSourceAudit([deterministic], [sourceAudit]);
    assert.equal(merged.length, 1);
    assert.equal(merged[0]?.verification, "confirmed");
    assert.ok(merged[0]?.sources.some((s) => s.tool === "semgrep"));
    assert.ok(merged[0]?.sources.some((s) => s.tool === "cloudflare-source-audit"));
  });

  it("keeps distinct CVEs at the same dependency path separate", () => {
    const first = createFinding({
      title: "CVE-1111",
      severity: "high",
      category: "sca",
      component: null,
      location: { package: "lodash", installedVersion: "4.17.20" },
      evidence: "advisory",
      cve: ["CVE-1111"],
      source: { tool: "trivy", ruleId: "CVE-1111" },
    });
    const second = createFinding({
      title: "CVE-2222",
      severity: "medium",
      category: "sca",
      component: null,
      location: { package: "lodash", installedVersion: "4.17.20" },
      evidence: "advisory",
      cve: ["CVE-2222"],
      source: { tool: "trivy", ruleId: "CVE-2222" },
    });
    assert.equal(mergeDeterministicWithSourceAudit([first], [second]).length, 2);
  });

  it("does not treat invalid source-audit files as attachable", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "security-scan-invalid-"));
    const invalidPath = path.join(dir, "findings.json");
    await writeFile(invalidPath, "[{\"verdict\":\"confirmed\"}]\n");
    const result = await validateCloudflareFindingsFile(invalidPath);
    assert.equal(result.ok, false);
  });

  it("attach fails closed when validation fails and does not mutate reports", async () => {
    const reportDir = await mkdtemp(path.join(os.tmpdir(), "security-scan-report-"));
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "test",
      repositoryPath: "/tmp/repo",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:00.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [],
      execution: {
        status: "complete",
        planned: 0,
        completed: 0,
        failed: 0,
        skipped: 0,
        unsupported: 0,
      },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: [],
        supportedChecks: [],
        outOfScope: [],
        unsupported: [],
      },
      coverageGaps: [],
      counts: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0,
      },
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: reportDir,
    };
    await writeFile(path.join(reportDir, "findings.json"), "[]\n");
    await writeFile(path.join(reportDir, "scan-manifest.json"), `${JSON.stringify(manifest)}\n`);
    const invalidPath = path.join(reportDir, "bad-findings.json");
    await writeFile(invalidPath, "[{\"verdict\":\"confirmed\"}]\n");
    const result = await attachSourceAuditToReport({
      repoPath: reportDir,
      reportDirectory: reportDir,
      sourceAuditFindingsPath: invalidPath,
    });
    assert.equal(result.ok, false);
    assert.equal(result.exitCode, 3);
    const findings = JSON.parse(await readFile(path.join(reportDir, "findings.json"), "utf8"));
    assert.deepEqual(findings, []);
  });
});
