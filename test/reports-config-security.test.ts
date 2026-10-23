import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";
import { loadConfig, resolveReportsDirectory } from "../src/config.js";
import { allowedHostEnvironment, runCommand } from "../src/execution.js";
import { createFinding } from "../src/findings.js";
import {
  coverageSummary,
  determineOverallStatus,
  executionSummary,
  findingCounts,
  renderMarkdownReport,
} from "../src/reports.js";
import type { ScanManifest, ScanPlan, ToolRun } from "../src/types.js";

const roots: string[] = [];
after(async () => {
  await Promise.all(roots.map((root) => rm(root, { recursive: true, force: true })));
});

describe("configuration, reports, and isolation policy", () => {
  it("rejects credential-bearing configuration keys", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-config-"));
    roots.push(root);
    await writeFile(
      path.join(root, ".security-scan.json"),
      JSON.stringify({ version: 1, apiToken: "do-not-store-this" }),
    );
    await assert.rejects(() => loadConfig(root), /Credential-bearing config key/);
  });

  it("confines report paths to the repository", () => {
    assert.equal(resolveReportsDirectory("/repo", "security-reports"), "/repo/security-reports");
    assert.throws(() => resolveReportsDirectory("/repo", "../outside"), /inside/);
  });

  it("rejects component paths outside the repository", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "security-scan-config-"));
    roots.push(root);
    await writeFile(
      path.join(root, ".security-scan.json"),
      JSON.stringify({ version: 1, components: [{ path: "../outside" }] }),
    );
    await assert.rejects(() => loadConfig(root), /Component paths must remain/);
  });

  it("does not inherit credential environment variables", () => {
    const original = process.env.TEST_API_TOKEN;
    process.env.TEST_API_TOKEN = "secret";
    try {
      const clean = allowedHostEnvironment({ SECURITY_SCAN_REPO: "/repo" });
      assert.equal(clean.TEST_API_TOKEN, undefined);
      assert.equal(clean.SECURITY_SCAN_REPO, "/repo");
    } finally {
      if (original === undefined) delete process.env.TEST_API_TOKEN;
      else process.env.TEST_API_TOKEN = original;
    }
  });

  it("terminates a process group when its timeout expires", async () => {
    const result = await runCommand(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)"],
      { cwd: os.tmpdir(), timeoutMs: 50, env: allowedHostEnvironment() },
    );
    assert.equal(result.timedOut, true);
    assert.notEqual(result.exitCode, 0);
  });

  it("renders redacted findings and reports failed tools as incomplete", () => {
    const finding = createFinding({
      title: "Exposed token",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: ".env", startLine: 1 },
      evidence: "token=super-secret-value",
      source: { tool: "trivy", ruleId: "generic-token" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    const run: ToolRun = {
      id: "trivy-repository",
      adapter: "trivy",
      componentId: null,
      status: "failed",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      exitCode: 2,
      version: "0.67.2",
      reason: "scanner failed",
      logPath: null,
      findingCount: 0,
    };
    const plan: ScanPlan = {
      mode: "standard",
      tools: [{
        id: "trivy-repository",
        adapter: "trivy",
        componentId: null,
        targetPath: ".",
        required: true,
        checks: ["vulnerability"],
        reason: "test",
      }],
      supportedChecks: ["Repository dependency vulnerability analysis"],
      outOfScope: ["Dynamic application security testing (DAST)"],
      unsupported: [],
      coverageGaps: [],
    };
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "scan",
      repositoryPath: "/repo",
      startedAt: run.startedAt,
      completedAt: run.completedAt,
      overallStatus: determineOverallStatus([run], [finding]),
      mode: "standard",
      toolRuns: [run],
      execution: executionSummary([run]),
      coverage: coverageSummary(plan, [run]),
      coverageGaps: [],
      counts: findingCounts([finding]),
      rawArtifactsPath: "/cache/raw",
      reportDirectory: "/repo/security-reports/scan",
    };
    const markdown = renderMarkdownReport(manifest, [finding]);
    assert.equal(manifest.overallStatus, "incomplete");
    assert.ok(!markdown.includes("super-secret-value"));
    assert.match(markdown, /Incomplete or skipped scans/);
    assert.match(markdown, /Execution completeness: \*\*incomplete\*\*/);
    assert.match(markdown, /Comprehensive security coverage: \*\*No\*\*/);
    assert.match(markdown, /Dynamic application security testing/);
  });

  it("separates completed execution from partial planned coverage", () => {
    const completed: ToolRun = {
      id: "trivy",
      adapter: "trivy",
      componentId: null,
      status: "passed",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      exitCode: 0,
      version: "1",
      reason: null,
      logPath: null,
      findingCount: 0,
    };
    const skipped: ToolRun = {
      ...completed,
      id: "dart",
      adapter: "dart-analyze",
      status: "skipped",
      exitCode: null,
      reason: "Dart SDK unavailable",
    };
    const plan: ScanPlan = {
      mode: "standard",
      tools: [
        {
          id: "trivy",
          adapter: "trivy",
          componentId: null,
          targetPath: ".",
          required: true,
          checks: ["vulnerability"],
          reason: "test",
        },
        {
          id: "dart",
          adapter: "dart-analyze",
          componentId: "mobile",
          targetPath: "mobile",
          required: false,
          checks: ["dart-static-analysis"],
          reason: "test",
        },
      ],
      supportedChecks: ["Dependency analysis", "Dart analyzer"],
      outOfScope: ["Authenticated runtime testing"],
      unsupported: ["rust: no configured SAST adapter"],
      coverageGaps: ["rust: no configured SAST adapter"],
    };

    const execution = executionSummary([completed, skipped]);
    const coverage = coverageSummary(plan, [completed, skipped]);
    assert.equal(execution.status, "complete");
    assert.equal(execution.completed, 1);
    assert.equal(execution.skipped, 1);
    assert.equal(coverage.plannedStatus, "partial");
    assert.equal(coverage.comprehensive, false);
    assert.deepEqual(coverage.unsupported, ["rust: no configured SAST adapter"]);
  });

  it("pins images and prohibits dangerous Docker options", async () => {
    const compose = await readFile(
      new URL("../compose/security-scan.compose.yml", import.meta.url),
      "utf8",
    );
    assert.match(compose, /@sha256:[a-f0-9]{64}/);
    assert.match(compose, /read_only: true/);
    assert.match(compose, /cap_drop: \[ALL\]/);
    assert.ok(!compose.includes("docker.sock"));
    assert.ok(!compose.includes("privileged: true"));
  });
});
