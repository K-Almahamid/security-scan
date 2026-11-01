import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { createFinding, deduplicateFindings } from "../src/findings.js";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseDartAnalyzeDocument, parseSemgrep, parseSemgrepDocument, parseTrivyDocument } from "../src/adapters.js";
import {
  buildAttachFindingSummary,
  buildScanFindingSummary,
  determineOverallStatus,
  renderMarkdownReport,
} from "../src/reports.js";
import type { FindingSummary, ScanManifest, ToolRun } from "../src/types.js";

function toolRun(partial: Partial<ToolRun> & Pick<ToolRun, "id" | "adapter" | "status">): ToolRun {
  return {
    componentId: null,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    exitCode: 0,
    version: "1.0.0",
    reason: null,
    logPath: null,
    findingCount: 0,
    ...partial,
  };
}

describe("finding summary and partial orchestration", () => {
  it("reports raw tool totals separately from normalized unique findings", () => {
    const base = {
      title: "Issue",
      severity: "high" as const,
      category: "sast" as const,
      component: null,
      location: { path: "app.py", startLine: 1 },
      evidence: "eval(x)",
      scannedAt: "2026-01-01T00:00:00.000Z",
    };
    const a = createFinding({ ...base, source: { tool: "semgrep", ruleId: "rule.a" } });
    const b = createFinding({ ...base, source: { tool: "semgrep", ruleId: "rule.b" } });
    const duplicate = createFinding({ ...base, source: { tool: "trivy", ruleId: "rule.a" } });
    duplicate.fingerprint = a.fingerprint;

    const collected = [a, b, duplicate];
    const normalized = deduplicateFindings(collected);
    const toolRuns = [
      toolRun({ id: "semgrep-root", adapter: "semgrep", status: "findings", findingCount: 2 }),
      toolRun({ id: "trivy-repository", adapter: "trivy", status: "findings", findingCount: 1 }),
    ];
    const summary = buildScanFindingSummary({
      toolRuns,
      collectedFindings: collected,
      normalizedFindings: normalized,
    });
    assert.equal(summary.rawToolFindingsTotal, 3);
    assert.equal(summary.preDedupeCollected, 3);
    assert.equal(summary.normalizedUnique, 2);
    assert.equal(summary.duplicatesRemoved, 1);
    assert.equal(summary.discardedDuringParse, 0);
  });

  it("attributes Brainogram-style duplicate Semgrep rows to deduplication, not parse loss", async () => {
    const fixtureDir = path.dirname(fileURLToPath(import.meta.url));
    const document = JSON.parse(
      await readFile(path.join(fixtureDir, "fixtures/semgrep-duplicate-result-rows.json"), "utf8"),
    );
    const repo = path.join(fixtureDir, "fixtures");
    const parsed = parseSemgrep(document, repo, "root");
    assert.equal(document.results.length, 3);
    assert.equal(parsed.length, 3);
    const normalized = deduplicateFindings(parsed);
    assert.equal(normalized.length, 2);
    const summary = buildScanFindingSummary({
      toolRuns: [
        toolRun({ id: "semgrep-root", adapter: "semgrep", status: "findings", findingCount: 3 }),
      ],
      collectedFindings: parsed,
      normalizedFindings: normalized,
    });
    assert.equal(summary.rawToolFindingsTotal, 3);
    assert.equal(summary.preDedupeCollected, 3);
    assert.equal(summary.duplicatesRemoved, 1);
    assert.equal(summary.discardedDuringParse, 0);
  });

  it("counts malformed individual findings without dropping valid rows", () => {
    const semgrep = parseSemgrepDocument(
      {
        results: [
          {
            check_id: "rule.ok",
            path: "lib/a.dart",
            extra: { message: "eval", severity: "ERROR", lines: "eval(x)" },
          },
          { check_id: "rule.missing-extra" },
          "not-an-object",
        ],
        errors: [
          {
            level: "warn",
            type: ["PartialParsing"],
            message: "Could not parse lib/widget.tsx",
          },
        ],
      },
      "/repo",
      "root",
    );
    assert.equal(semgrep.rawCount, 3);
    assert.equal(semgrep.discarded, 2);
    assert.equal(semgrep.findings.length, 1);
    assert.equal(semgrep.findings[0]?.sources[0]?.ruleId, "rule.ok");

    const trivy = parseTrivyDocument(
      {
        Results: [
          {
            Target: "pubspec.lock",
            Vulnerabilities: [{ VulnerabilityID: "CVE-2026-0001", Severity: "HIGH", PkgName: "pkg", InstalledVersion: "1.0.0" }, "bad-row"],
          },
          "bad-result",
        ],
      },
      "/repo",
      null,
    );
    assert.equal(trivy.discarded, 2);
    assert.equal(trivy.findings.length, 1);

    const dart = parseDartAnalyzeDocument(
      ["ERROR|HINT|undefined_function|lib/a.dart|3|1|8|Undefined name.", "not-machine-output", ""].join("\n"),
      "/repo",
      "app",
    );
    assert.equal(dart.rawCount, 2);
    assert.equal(dart.discarded, 1);
    assert.equal(dart.findings.length, 1);

    const summary = buildScanFindingSummary({
      toolRuns: [
        toolRun({
          id: "semgrep-root",
          adapter: "semgrep",
          status: "failed",
          findingCount: semgrep.findings.length,
          discardedDuringParse: semgrep.discarded,
        }),
      ],
      collectedFindings: semgrep.findings,
      normalizedFindings: semgrep.findings,
    });
    assert.equal(summary.rawToolFindingsTotal, 3);
    assert.equal(summary.preDedupeCollected, 1);
    assert.equal(summary.discardedDuringParse, 2);
    assert.equal(summary.duplicatesRemoved, 0);
  });

  it("preserves a real parse-discard count across attach instead of treating it as dedupe", () => {
    const runs = [
      toolRun({
        id: "semgrep-root",
        adapter: "semgrep",
        status: "failed",
        findingCount: 96,
        discardedDuringParse: 4,
      }),
    ];
    const prior: FindingSummary = {
      perTool: [{ id: "semgrep-root", adapter: "semgrep", findingCount: 96, discardedDuringParse: 4 }],
      rawToolFindingsTotal: 100,
      preDedupeCollected: 96,
      normalizedUnique: 96,
      duplicatesRemoved: 0,
      discardedDuringParse: 4,
    };
    const stub = () =>
      createFinding({
        title: "Fixture",
        severity: "medium",
        category: "sast",
        component: null,
        location: { path: "src/a.ts", startLine: 1 },
        evidence: "eval(x)",
        source: { tool: "semgrep", ruleId: "fixture" },
        scannedAt: "2026-01-01T00:00:00.000Z",
      });
    const deterministic = Array.from({ length: 96 }, stub);
    const afterAttach = buildAttachFindingSummary({
      toolRuns: runs,
      priorSummary: prior,
      deterministicFindings: deterministic,
      importableCount: 0,
      mergedFindings: deterministic,
    });
    assert.equal(afterAttach.discardedDuringParse, 4);
    assert.equal(afterAttach.preDedupeCollected, 96);
    assert.equal(afterAttach.duplicatesRemoved, 0);
    assert.equal(afterAttach.rawToolFindingsTotal, 100);
  });

  it("preserves scan dedupe counts when source audit attach rebuilds findingSummary", () => {
    const runs = [
      toolRun({ id: "semgrep-root", adapter: "semgrep", status: "failed", findingCount: 100 }),
    ];
    const scanSummary: FindingSummary = {
      perTool: [{ id: "semgrep-root", adapter: "semgrep", findingCount: 100 }],
      rawToolFindingsTotal: 100,
      preDedupeCollected: 100,
      normalizedUnique: 96,
      duplicatesRemoved: 4,
      discardedDuringParse: 0,
    };
    const stub = () =>
      createFinding({
        title: "Fixture",
        severity: "medium",
        category: "sast",
        component: null,
        location: { path: "src/a.ts", startLine: 1 },
        evidence: "eval(x)",
        source: { tool: "semgrep", ruleId: "fixture" },
        scannedAt: "2026-01-01T00:00:00.000Z",
      });
    const deterministic = Array.from({ length: 96 }, stub);
    const afterAttach = buildAttachFindingSummary({
      toolRuns: runs,
      priorSummary: scanSummary,
      deterministicFindings: deterministic,
      importableCount: 0,
      mergedFindings: deterministic,
    });
    assert.equal(afterAttach.rawToolFindingsTotal, 100);
    assert.equal(afterAttach.preDedupeCollected, 100);
    assert.equal(afterAttach.duplicatesRemoved, 4);
    assert.equal(afterAttach.normalizedUnique, 96);
    assert.equal(afterAttach.discardedDuringParse, 0);
  });

  it("reconciles a corrupted prior findingSummary on attach", () => {
    const runs = [
      toolRun({ id: "semgrep-root", adapter: "semgrep", status: "failed", findingCount: 100 }),
    ];
    const corruptedPrior: FindingSummary = {
      perTool: [{ id: "semgrep-root", adapter: "semgrep", findingCount: 100 }],
      rawToolFindingsTotal: 100,
      preDedupeCollected: 96,
      normalizedUnique: 96,
      duplicatesRemoved: 0,
      discardedDuringParse: 0,
    };
    const stub = () =>
      createFinding({
        title: "Fixture",
        severity: "medium",
        category: "sast",
        component: null,
        location: { path: "src/a.ts", startLine: 1 },
        evidence: "eval(x)",
        source: { tool: "semgrep", ruleId: "fixture" },
        scannedAt: "2026-01-01T00:00:00.000Z",
      });
    const deterministic = Array.from({ length: 96 }, stub);
    const afterAttach = buildAttachFindingSummary({
      toolRuns: runs,
      priorSummary: corruptedPrior,
      deterministicFindings: deterministic,
      importableCount: 0,
      mergedFindings: deterministic,
    });
    assert.equal(afterAttach.preDedupeCollected, 100);
    assert.equal(afterAttach.duplicatesRemoved, 4);
  });

  it("keeps findings from completed tools when another required tool failed", () => {
    const finding = createFinding({
      title: "Secret",
      severity: "high",
      category: "secret",
      component: null,
      location: { path: "a.env", startLine: 1 },
      evidence: "token=x",
      source: { tool: "trivy", ruleId: "github-pat" },
      scannedAt: "2026-01-01T00:00:00.000Z",
    });
    const passed = toolRun({
      id: "trivy-repository",
      adapter: "trivy",
      status: "findings",
      findingCount: 1,
    });
    const failed = toolRun({
      id: "semgrep-root",
      adapter: "semgrep",
      status: "failed",
      findingCount: 0,
      reason: "Semgrep output invalid",
    });
    const toolRuns = [passed, failed];
    const normalized = deduplicateFindings([finding]);
    assert.equal(normalized.length, 1);
    assert.equal(determineOverallStatus(toolRuns, normalized), "incomplete");
  });

  it("includes finding summary lines in markdown reports", () => {
    const manifest: ScanManifest = {
      schemaVersion: 2,
      scanId: "summary-scan",
      repositoryPath: "/repo",
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      overallStatus: "complete",
      mode: "standard",
      toolRuns: [
        toolRun({ id: "trivy-repository", adapter: "trivy", status: "passed", findingCount: 0 }),
      ],
      execution: { status: "complete", planned: 1, completed: 1, failed: 0, skipped: 0, unsupported: 0 },
      coverage: {
        comprehensive: false,
        plannedStatus: "complete",
        plannedChecks: ["trivy:secret"],
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
      findingSummary: buildScanFindingSummary({
        toolRuns: [
          toolRun({ id: "trivy-repository", adapter: "trivy", status: "passed", findingCount: 0 }),
        ],
        collectedFindings: [],
        normalizedFindings: [],
      }),
      rawArtifactsPath: "/tmp/raw",
      reportDirectory: "/repo/security-reports/summary-scan",
    };
    const markdown = renderMarkdownReport(manifest, []);
    assert.match(markdown, /## Finding counts/);
    assert.match(markdown, /Normalized unique findings:\*\* 0/);
  });
});
