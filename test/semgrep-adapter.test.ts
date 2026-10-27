import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  applySemgrepCompletionPolicy,
  finalizeToolExecution,
  parseSemgrep,
  readSemgrepDocument,
} from "../src/adapters.js";
import { scanExitCode } from "../src/scanner.js";
import type { CanonicalFinding } from "../src/types.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function loadFixture(name: string): Promise<unknown> {
  return JSON.parse(await readFile(path.join(projectRoot, "test/fixtures", name), "utf8")) as unknown;
}

function completeSemgrepFromDocument(
  document: unknown,
  exitCode: number | null,
  repoPath: string,
  componentId: string | null,
): { status: string; findings: CanonicalFinding[]; reason: string | null } {
  const assessment = readSemgrepDocument(document);
  const findings = assessment.valid ? parseSemgrep(document, repoPath, componentId) : [];
  let completion = finalizeToolExecution({
    family: "semgrep",
    exitCode,
    timedOut: false,
    documentValid: assessment.valid,
    ...(assessment.error ? { documentError: assessment.error } : {}),
    findings,
  });
  completion = applySemgrepCompletionPolicy(completion, assessment);
  return {
    status: completion.status,
    findings: completion.findings,
    reason: completion.reason,
  };
}

describe("Semgrep adapter reliability", () => {
  it("accepts valid JSON with zero findings and no errors", async () => {
    const document = await loadFixture("semgrep-clean-empty.json");
    const assessment = readSemgrepDocument(document);
    assert.equal(assessment.valid, true);
    assert.equal(assessment.incompleteScan, undefined);
    const completed = completeSemgrepFromDocument(document, 0, projectRoot, "root");
    assert.equal(completed.status, "passed");
    assert.equal(completed.findings.length, 0);
  });

  it("imports findings from valid JSON without scanner errors", async () => {
    const document = await loadFixture("semgrep-findings-only.json");
    const completed = completeSemgrepFromDocument(document, 1, projectRoot, "app");
    assert.equal(completed.status, "findings");
    assert.equal(completed.findings.length, 1);
    assert.equal(completed.findings[0]?.sources[0]?.tool, "semgrep");
    assert.equal(completed.findings[0]?.component, "app");
  });

  it("rejects blocking rule errors and does not import findings", async () => {
    const document = await loadFixture("semgrep-blocking-rule-error.json");
    const assessment = readSemgrepDocument(document);
    assert.equal(assessment.valid, false);
    assert.match(assessment.error ?? "", /blocking scanner errors/i);
    const completed = completeSemgrepFromDocument(document, 0, projectRoot, "root");
    assert.equal(completed.status, "failed");
    assert.equal(completed.findings.length, 0);
  });

  it("preserves findings for warn-level partial parsing errors (Brainogram regression)", async () => {
    const document = await loadFixture("semgrep-partial-parsing-warnings.json");
    const assessment = readSemgrepDocument(document);
    assert.equal(assessment.valid, true);
    assert.equal(assessment.incompleteScan, true);
    assert.match(assessment.scannerErrorSummary ?? "", /partial parsing coverage/i);
    const completed = completeSemgrepFromDocument(document, 0, projectRoot, "root");
    assert.equal(completed.status, "failed");
    assert.equal(completed.findings.length, 1);
    assert.match(completed.reason ?? "", /partial parsing coverage/i);
  });

  it("marks dashboard partial parsing with zero findings as failed without importing findings", async () => {
    const document = await loadFixture("semgrep-partial-parsing-empty-results.json");
    const completed = completeSemgrepFromDocument(document, 0, projectRoot, "dashboard");
    assert.equal(completed.status, "failed");
    assert.equal(completed.findings.length, 0);
    assert.match(completed.reason ?? "", /OverviewKpiCharts|partial parsing/i);
  });

  it("treats malformed JSON as a failed scanner document", () => {
    const assessment = readSemgrepDocument({ not: "semgrep" });
    assert.equal(assessment.valid, false);
    const completed = completeSemgrepFromDocument({ not: "semgrep" }, 0, projectRoot, "root");
    assert.equal(completed.status, "failed");
    assert.equal(completed.findings.length, 0);
  });

  it("fails on exit code zero with legacy blocking error collections", () => {
    const assessment = readSemgrepDocument({ results: [], errors: [{ message: "bad rule" }] });
    assert.equal(assessment.valid, false);
    assert.match(assessment.error ?? "", /blocking/i);
  });

  it("propagates truncated compose output as failure without findings", () => {
    const completion = finalizeToolExecution({
      family: "semgrep",
      exitCode: 0,
      timedOut: false,
      outputTruncated: true,
      documentValid: false,
      documentError: "Scanner output is missing or is not valid JSON",
      findings: [],
    });
    assert.equal(completion.status, "failed");
    assert.match(completion.reason ?? "", /truncated/i);
  });

  it("keeps the overall scan incomplete when a required Semgrep run fails with imported findings", async () => {
    const document = await loadFixture("semgrep-partial-parsing-warnings.json");
    const completed = completeSemgrepFromDocument(document, 0, projectRoot, "root");
    assert.equal(completed.status, "failed");
    const exit = scanExitCode(
      "incomplete",
      completed.findings,
      "high",
    );
    assert.equal(exit, 2);
  });
});
